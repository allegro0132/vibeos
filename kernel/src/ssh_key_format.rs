//! Minimal unencrypted OpenSSH Ed25519 key serialization.

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

fn push_ssh_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn public_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(51);
    push_ssh_string(&mut blob, b"ssh-ed25519");
    push_ssh_string(&mut blob, public);
    blob
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(TABLE[((value >> 18) & 63) as usize] as char);
        out.push(TABLE[((value >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

pub fn openssh_public(public: &[u8; 32]) -> String {
    format!(
        "ssh-ed25519 {} vibeos-device\n",
        base64(&public_blob(public))
    )
}

pub fn openssh_private(seed: &[u8; 32], public: &[u8; 32]) -> String {
    let public_blob = public_blob(public);
    let mut private = Vec::with_capacity(160);
    let check = u32::from_be_bytes(seed[..4].try_into().expect("seed prefix is four bytes"));
    private.extend_from_slice(&check.to_be_bytes());
    private.extend_from_slice(&check.to_be_bytes());
    push_ssh_string(&mut private, b"ssh-ed25519");
    push_ssh_string(&mut private, public);
    let mut expanded = [0u8; 64];
    expanded[..32].copy_from_slice(seed);
    expanded[32..].copy_from_slice(public);
    push_ssh_string(&mut private, &expanded);
    wipe(&mut expanded);
    push_ssh_string(&mut private, b"vibeos-device");
    let padding = 8 - private.len() % 8;
    for value in 1..=padding {
        private.push(value as u8);
    }

    let mut encoded = Vec::with_capacity(256);
    encoded.extend_from_slice(b"openssh-key-v1\0");
    push_ssh_string(&mut encoded, b"none");
    push_ssh_string(&mut encoded, b"none");
    push_ssh_string(&mut encoded, b"");
    encoded.extend_from_slice(&1u32.to_be_bytes());
    push_ssh_string(&mut encoded, &public_blob);
    push_ssh_string(&mut encoded, &private);
    wipe(&mut private);
    let body = base64(&encoded);
    wipe(&mut encoded);
    let mut out = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for line in body.as_bytes().chunks(70) {
        out.push_str(core::str::from_utf8(line).expect("base64 is UTF-8"));
        out.push('\n');
    }
    out.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    const SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const PUBLIC: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    #[test]
    fn openssh_accepts_private_key_and_derives_expected_public_key() {
        let directory =
            std::env::temp_dir().join(format!("vibeos-ssh-key-format-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let private_path = directory.join("id_ed25519");
        fs::write(&private_path, openssh_private(&SEED, &PUBLIC)).unwrap();
        fs::set_permissions(&private_path, fs::Permissions::from_mode(0o600)).unwrap();
        let output = Command::new("ssh-keygen")
            .arg("-y")
            .arg("-f")
            .arg(&private_path)
            .output()
            .unwrap();
        let _ = fs::remove_dir_all(&directory);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            openssh_public(&PUBLIC).trim()
        );
    }
}
