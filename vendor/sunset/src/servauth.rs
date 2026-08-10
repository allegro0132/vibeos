#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use crate::sshnames::*;
use crate::*;
use event::ServEventId;
use kex::SessId;
use packets::{AuthMethod, Packet, Userauth60, UserauthPkOk, UserauthRequest};
use traffic::TrafSend;

use heapless::Vec;

/// Server authentication context
///
/// `methods_` can be during runtime, though if they
/// are changed after the auth process starts it's unknown
/// if client implementations will handle varying auth methods correctly.
#[derive(Debug)]
pub(crate) struct ServAuth {
    authed: bool,
    attempts: u8,

    /// Username previously used, as an array of bytes
    pub username: Option<Vec<u8, { config::MAX_USERNAME }>>,

    /// Password authentication is permanently disabled by the VibeOS profile.
    pub method_password: bool,
    /// Whether to advertise pubkey authentication and present it to the application.
    ///
    /// Enabled by default
    pub method_pubkey: bool,
}

impl Default for ServAuth {
    fn default() -> Self {
        Self {
            authed: false,
            attempts: 0,
            username: None,
            method_password: false,
            method_pubkey: true,
        }
    }
}

impl ServAuth {
    /// Configure which authentication methods are allowed
    pub fn set_auth_methods(&mut self, _password: bool, pubkey: bool) {
        // This fork is an exact public-key-only server profile. Applications
        // may disable public-key authentication, but cannot widen it to a
        // password or unauthenticated flow at runtime.
        self.method_password = false;
        self.method_pubkey = pubkey;
    }

    /// Returns `true` if the client has successfully authenticated.
    pub fn is_authed(&self) -> bool {
        self.authed
    }

    /// Returns an event for the app, or `DispatchEvent::None` if auth failure
    /// has been returned immediately.
    pub fn request(
        &mut self,
        sess_id: &SessId,
        s: &mut TrafSend,
        p: packets::UserauthRequest,
    ) -> Result<DispatchEvent> {
        if self.authed {
            trace!("authentication request received after success");
            return error::SSHProto.fail();
        }
        if p.service != SSH_SERVICE_CONNECTION {
            warn!("authentication requested for unexpected service {}", p.service);
            return error::SSHProto.fail();
        }
        if self.attempts >= config::MAX_AUTH_ATTEMPTS {
            warn!("authentication attempt ceiling reached");
            return error::SSHProto.fail();
        }
        self.attempts += 1;

        if let Some(prev) = &self.username {
            // Compare with an existing username
            if prev != p.username.0 {
                warn!("Client tried varying usernames");
                return error::SSHProtoUnsupported.fail();
            }
        } else {
            // Set new username and query app for auth methods
            match Vec::from_slice(p.username.0) {
                Result::Ok(u) => self.username = Some(u),
                Result::Err(_) => {
                    warn!("Client tried too long username, {}", p.username.0.len());
                    return error::SSHProtoUnsupported.fail();
                }
            }
        }
        debug_assert!(self.username.is_some());

        let ev = if self.is_method_enabled(&p.method) {
            self.request_pubkey(p, sess_id)?
        } else {
            DispatchEvent::None
        };

        // Auth method isn't supported, send failure straight away.
        // No concerns about timing leaks since it is independent of the username.
        if ev.is_none() {
            self.send_failure(s)?;
        }

        Ok(ev)
    }

    fn is_method_enabled(&self, method: &AuthMethod<'_>) -> bool {
        self.method_pubkey && matches!(method, AuthMethod::PubKey(_))
    }

    fn send_failure(&self, s: &mut TrafSend) -> Result<()> {
        let methods = self.avail_methods();
        let methods = (&methods).into();
        s.send(packets::UserauthFailure { methods, partial: false })
    }

    fn request_pubkey(
        &mut self,
        mut p: packets::UserauthRequest,
        sess_id: &SessId,
    ) -> Result<DispatchEvent> {
        let strict = match &p.method {
            AuthMethod::PubKey(method) => Self::validate_strict_ed25519(method),
            _ => false,
        };
        if !strict {
            return Ok(DispatchEvent::None);
        }

        // Extract the signature separately. The message for the signature
        // includes the auth packet without the signature part.
        let sig = match &mut p.method {
            AuthMethod::PubKey(m) => {
                let sig = m.sig.take();
                // When we have a signature, we need to set force_sig=true so that the encoded message for verification has the boolean set correctly
                m.force_sig = sig.is_some();
                sig
            }
            _ => return Error::bug(),
        };

        if let Some(ref sig) = sig {
            // Real signature, validate it.
            if !self.verify_sig(&p, &sig.0, sess_id) {
                // Auth failure. OK to return early here since
                // this doesn't rely on any particular username, no concerns
                // about timing leaks.
                return Ok(DispatchEvent::None);
            }
        }

        // Proceed to query the app whether login is allowed
        let real_sig = sig.is_some();
        Ok(DispatchEvent::ServEvent(ServEventId::PubkeyAuth { real_sig }))
    }

    /// Validate the redundant algorithm labels and fixed-size Ed25519 wire
    /// values before a probe reaches policy code or a signature reaches crypto.
    fn validate_strict_ed25519(method: &packets::MethodPubKey<'_>) -> bool {
        if method.sig_algo != SSH_NAME_ED25519
            || !matches!(method.pubkey.0, PubKey::Ed25519(_))
        {
            return false;
        }

        match method.sig.as_ref().map(|signature| &signature.0) {
            None => true,
            Some(Signature::Ed25519(signature)) => signature.sig.0.len() == 64,
            Some(_) => false,
        }
    }

    pub fn resume_request(&mut self, allow: bool, s: &mut TrafSend) -> Result<()> {
        if allow {
            self.authed = true;
            s.send(packets::UserauthSuccess {})
        } else {
            self.send_failure(s)
        }
    }

    pub fn resume_pkok(&self, p: Packet, s: &mut TrafSend) -> Result<()> {
        if let Packet::UserauthRequest(UserauthRequest {
            method: AuthMethod::PubKey(m),
            ..
        }) = p
        {
            if !Self::validate_strict_ed25519(&m) || m.sig.is_some() {
                return error::SSHProto.fail();
            }
            s.send(Userauth60::PkOk(UserauthPkOk {
                algo: SSH_NAME_ED25519,
                key: m.pubkey,
            }))
        } else {
            Error::bug()
        }
    }

    /// Must be passed a MethodPubkey packet with a signature part None
    fn verify_sig(
        &self,
        p: &packets::UserauthRequest,
        sig: &Signature,
        sess_id: &SessId,
    ) -> bool {
        // Remove the signature from the packet - the signature message includes
        // packet without that signature part.

        let key = match &p.method {
            AuthMethod::PubKey(m) if Self::validate_strict_ed25519(m) => &m.pubkey.0,
            _ => {
                return false;
            }
        };

        let msg = auth::AuthSigMsg::new(p.clone(), sess_id);
        match sign::SigType::Ed25519.verify(key, &msg, sig) {
            Ok(()) => true,
            Err(e) => {
                trace!("sig failed  {e}");
                false
            }
        }
    }

    fn avail_methods(&self) -> namelist::LocalNames {
        let mut l = namelist::LocalNames::new();

        // OK unwrap: buf is large enough
        if self.method_password {
            l.0.push(SSH_AUTHMETHOD_PASSWORD).unwrap()
        }
        if self.method_pubkey {
            l.0.push(SSH_AUTHMETHOD_PUBLICKEY).unwrap()
        }
        l
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::KeyState;
    use crate::packets::{Ed25519PubKey, Ed25519Sig, MethodPassword, MethodPubKey};
    use crate::random::tests::TestRandom;
    use crate::sshwire::{BinString, Blob, TextString, Unknown};
    use crate::traffic::TrafOut;

    fn ed25519_method<'a>(
        sig_algo: &'a str,
        signature: Option<&'a [u8]>,
    ) -> MethodPubKey<'a> {
        MethodPubKey {
            sig_algo,
            pubkey: Blob(PubKey::Ed25519(Ed25519PubKey { key: Blob([0x23; 32]) })),
            sig: signature.map(|sig| {
                Blob(Signature::Ed25519(Ed25519Sig { sig: BinString(sig) }))
            }),
            force_sig: false,
        }
    }

    fn request<'a>(
        auth: &mut ServAuth,
        sess_id: &SessId,
        packet: UserauthRequest<'a>,
        output: &mut TrafOut<'_>,
        keys: &mut KeyState,
        random: &mut TestRandom,
    ) -> Result<DispatchEvent> {
        auth.request(sess_id, &mut output.sender(keys, random), packet)
    }

    fn probe_request(username: &[u8]) -> UserauthRequest<'_> {
        UserauthRequest {
            username: TextString(username),
            service: SSH_SERVICE_CONNECTION,
            method: AuthMethod::PubKey(ed25519_method(SSH_NAME_ED25519, None)),
        }
    }

    fn auth_fixture() -> (ServAuth, SessId, KeyState, TestRandom) {
        (
            ServAuth::default(),
            SessId::from_slice(&[0x31; 32]).unwrap(),
            KeyState::new_cleartext(),
            TestRandom::new(0x72),
        )
    }

    #[test]
    fn strict_ed25519_rejects_algorithm_and_signature_length_mismatches() {
        assert!(ServAuth::validate_strict_ed25519(&ed25519_method(
            SSH_NAME_ED25519,
            None,
        )));

        let signature = [0x45; 64];
        assert!(ServAuth::validate_strict_ed25519(&ed25519_method(
            SSH_NAME_ED25519,
            Some(&signature),
        )));

        assert!(!ServAuth::validate_strict_ed25519(&ed25519_method(
            SSH_NAME_RSA_SHA256,
            None,
        )));

        for bad_len in [0, 63, 65] {
            let signature = [0x45; 65];
            assert!(!ServAuth::validate_strict_ed25519(&ed25519_method(
                SSH_NAME_ED25519,
                Some(&signature[..bad_len]),
            )));
        }

        let mut wrong_key = ed25519_method(SSH_NAME_ED25519, None);
        wrong_key.pubkey = Blob(PubKey::Unknown(Unknown::new(b"ssh-rsa")));
        assert!(!ServAuth::validate_strict_ed25519(&wrong_key));

        let mut wrong_signature = ed25519_method(SSH_NAME_ED25519, None);
        wrong_signature.sig =
            Some(Blob(Signature::Unknown(Unknown::new(b"rsa-sha2-256"))));
        assert!(!ServAuth::validate_strict_ed25519(&wrong_signature));
    }

    #[test]
    fn ed25519_public_key_wire_length_is_exact() {
        fn encoded_key(key_len: usize) -> std::vec::Vec<u8> {
            let mut wire = std::vec::Vec::new();
            wire.extend_from_slice(&(SSH_NAME_ED25519.len() as u32).to_be_bytes());
            wire.extend_from_slice(SSH_NAME_ED25519.as_bytes());
            wire.extend_from_slice(&(key_len as u32).to_be_bytes());
            wire.resize(wire.len() + key_len, 0x5a);
            wire
        }

        let valid = encoded_key(32);
        let (_, used): (PubKey<'_>, usize) =
            sshwire::read_ssh(&valid, None).expect("32-byte Ed25519 key");
        assert_eq!(used, valid.len());

        for bad_len in [0, 31, 33] {
            let wire = encoded_key(bad_len);
            let decoded: core::result::Result<(PubKey<'_>, usize), _> =
                sshwire::read_ssh(&wire, None);
            assert!(decoded.is_err(), "accepted {bad_len}-byte Ed25519 key");
        }
    }

    #[test]
    fn username_is_bounded_and_locked_to_first_attempt() {
        let (mut auth, sess_id, mut keys, mut random) = auth_fixture();
        let mut output_buf = [0; 4096];
        let mut output = TrafOut::new(&mut output_buf);

        assert!(
            request(
                &mut auth,
                &sess_id,
                probe_request(b"vibe"),
                &mut output,
                &mut keys,
                &mut random,
            )
            .is_ok()
        );
        assert_eq!(auth.username.as_deref(), Some(b"vibe".as_slice()));

        let changed = request(
            &mut auth,
            &sess_id,
            probe_request(b"other"),
            &mut output,
            &mut keys,
            &mut random,
        );
        assert!(matches!(changed, Err(Error::SSHProtoUnsupported)));
        assert_eq!(auth.username.as_deref(), Some(b"vibe".as_slice()));

        let (mut auth, sess_id, mut keys, mut random) = auth_fixture();
        let maximum = std::vec![b'u'; config::MAX_USERNAME];
        assert!(
            request(
                &mut auth,
                &sess_id,
                probe_request(&maximum),
                &mut output,
                &mut keys,
                &mut random,
            )
            .is_ok()
        );

        let (mut auth, sess_id, mut keys, mut random) = auth_fixture();
        let too_long = std::vec![b'u'; config::MAX_USERNAME + 1];
        let result = request(
            &mut auth,
            &sess_id,
            probe_request(&too_long),
            &mut output,
            &mut keys,
            &mut random,
        );
        assert!(matches!(result, Err(Error::SSHProtoUnsupported)));
        assert!(auth.username.is_none());
    }

    #[test]
    fn authentication_attempts_have_a_hard_ceiling() {
        let (mut auth, sess_id, mut keys, mut random) = auth_fixture();
        let mut output_buf = [0; 8192];
        let mut output = TrafOut::new(&mut output_buf);

        for _ in 0..config::MAX_AUTH_ATTEMPTS {
            assert!(
                request(
                    &mut auth,
                    &sess_id,
                    probe_request(b"vibe"),
                    &mut output,
                    &mut keys,
                    &mut random,
                )
                .is_ok()
            );
        }
        assert_eq!(auth.attempts, config::MAX_AUTH_ATTEMPTS);

        let over_limit = request(
            &mut auth,
            &sess_id,
            probe_request(b"vibe"),
            &mut output,
            &mut keys,
            &mut random,
        );
        assert!(matches!(over_limit, Err(Error::SSHProto { .. })));
        assert_eq!(auth.attempts, config::MAX_AUTH_ATTEMPTS);
    }

    #[test]
    fn password_and_unauthenticated_success_are_never_exposed() {
        let (mut auth, sess_id, mut keys, mut random) = auth_fixture();
        auth.set_auth_methods(true, true);
        assert!(!auth.method_password);
        assert!(auth.method_pubkey);
        assert_eq!(auth.avail_methods().0.as_slice(), [SSH_AUTHMETHOD_PUBLICKEY]);

        let password = AuthMethod::Password(MethodPassword {
            change: false,
            password: "secret".into(),
        });
        assert!(!auth.is_method_enabled(&password));
        assert!(!auth.is_method_enabled(&AuthMethod::None));
        assert!(auth.is_method_enabled(&AuthMethod::PubKey(ed25519_method(
            SSH_NAME_ED25519,
            None,
        ))));

        let mut output_buf = [0; 4096];
        let mut output = TrafOut::new(&mut output_buf);
        let probe = UserauthRequest {
            username: "vibe".into(),
            service: SSH_SERVICE_CONNECTION,
            method: AuthMethod::PubKey(ed25519_method(SSH_NAME_ED25519, None)),
        };
        let event =
            request(&mut auth, &sess_id, probe, &mut output, &mut keys, &mut random)
                .unwrap();
        assert!(matches!(
            event,
            DispatchEvent::ServEvent(ServEventId::PubkeyAuth { real_sig: false })
        ));
        assert!(!auth.is_authed());
    }

    #[test]
    fn authentication_service_name_is_exact() {
        let (mut auth, sess_id, mut keys, mut random) = auth_fixture();
        let mut output_buf = [0; 4096];
        let mut output = TrafOut::new(&mut output_buf);
        let packet = UserauthRequest {
            username: "vibe".into(),
            service: "ssh-userauth",
            method: AuthMethod::None,
        };
        let result = request(
            &mut auth,
            &sess_id,
            packet,
            &mut output,
            &mut keys,
            &mut random,
        );
        assert!(matches!(result, Err(Error::SSHProto { .. })));
        assert_eq!(auth.attempts, 0);
        assert!(auth.username.is_none());
        assert!(!output.is_output_pending());
    }
}
