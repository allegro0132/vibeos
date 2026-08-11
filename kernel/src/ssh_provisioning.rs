//! Persistent, fail-closed SSH provisioning for Milk-V Duo.

extern crate alloc;

use alloc::{format, string::String, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use vibeos_core::cap::Rights;
use vibeos_ssh_identity::{
    AuthorizedKeyEntry, AuthorizedKeyPolicyService, CapabilityProfileId, HostSigningService,
    ProvisionedHostSeed, SecurityGeneration, SshEd25519PublicKey,
};
use vibeos_vsh::Status;

const LEGACY_SLOT_A: u64 = 16;
const LEGACY_SLOT_B: u64 = 17;
const CONFIG_OBJECT_KIND: u32 = 0x5353_4801;
const MAGIC: &[u8; 8] = b"VSSHKEY1";
const VERSION: u16 = 1;
const FLAG_HOST: u16 = 1;
const FLAG_CLIENT: u16 = 2;
const FLAG_CLIENT_KEYPAIR: u16 = 4;
const CRC_AT: usize = 508;
const MAX_CLIENT_KEYS: usize = 8;
const KEYS_AT: usize = 56;
pub const PROFILE: u32 = 1;
static UPDATE_BUSY: AtomicBool = AtomicBool::new(false);
static ONBOARDING_ACTIVE: AtomicBool = AtomicBool::new(false);
static POLICY_CHANGED: AtomicBool = AtomicBool::new(false);
static POLICY_GENERATION: AtomicU64 = AtomicU64::new(0);

pub const DEFAULT_USERNAME: &str = "vibe";
pub const DEFAULT_PASSWORD: &str = "vibeos";

fn erase(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

pub struct Config {
    pub generation: u64,
    pub host_seed: [u8; 32],
    client_keys: [[u8; 32]; MAX_CLIENT_KEYS],
    key_count: u8,
    flags: u16,
    client_seed: [u8; 32],
    client_public: [u8; 32],
}
impl Drop for Config {
    fn drop(&mut self) {
        erase(&mut self.host_seed);
        erase(&mut self.client_seed);
    }
}
impl Config {
    fn empty() -> Self {
        Self {
            generation: 0,
            host_seed: [0; 32],
            client_keys: [[0; 32]; MAX_CLIENT_KEYS],
            key_count: 0,
            flags: 0,
            client_seed: [0; 32],
            client_public: [0; 32],
        }
    }
    pub fn complete(&self) -> bool {
        self.flags & (FLAG_HOST | FLAG_CLIENT) == FLAG_HOST | FLAG_CLIENT
    }

    fn has_host(&self) -> bool {
        self.flags & FLAG_HOST != 0
    }
}

fn encode(config: &Config) -> [u8; 512] {
    let mut out = [0u8; 512];
    out[..8].copy_from_slice(MAGIC);
    out[8..10].copy_from_slice(&VERSION.to_le_bytes());
    out[10..12].copy_from_slice(&config.flags.to_le_bytes());
    out[12..20].copy_from_slice(&config.generation.to_le_bytes());
    out[20..52].copy_from_slice(&config.host_seed);
    out[52] = config.key_count;
    for (index, key) in config.client_keys[..config.key_count as usize]
        .iter()
        .enumerate()
    {
        let start = KEYS_AT + index * 32;
        out[start..start + 32].copy_from_slice(key);
    }
    out[320..352].copy_from_slice(&config.client_seed);
    out[352..384].copy_from_slice(&config.client_public);
    let crc = vibeos_durable_format::crc32c(&out[..CRC_AT]);
    out[CRC_AT..].copy_from_slice(&crc.to_le_bytes());
    out
}

fn decode(bytes: &[u8; 512]) -> Option<Config> {
    if &bytes[..8] != MAGIC || u16::from_le_bytes(bytes[8..10].try_into().ok()?) != VERSION {
        return None;
    }
    let expected = u32::from_le_bytes(bytes[CRC_AT..].try_into().ok()?);
    if vibeos_durable_format::crc32c(&bytes[..CRC_AT]) != expected {
        return None;
    }
    let flags = u16::from_le_bytes(bytes[10..12].try_into().ok()?);
    if flags & !(FLAG_HOST | FLAG_CLIENT | FLAG_CLIENT_KEYPAIR) != 0 {
        return None;
    }
    let generation = u64::from_le_bytes(bytes[12..20].try_into().ok()?);
    if generation == 0 {
        return None;
    }
    let mut host_seed = [0; 32];
    host_seed.copy_from_slice(&bytes[20..52]);
    let key_count = bytes[52] as usize;
    if key_count > MAX_CLIENT_KEYS || (flags & FLAG_CLIENT != 0) != (key_count != 0) {
        return None;
    }
    let mut client_keys = [[0; 32]; MAX_CLIENT_KEYS];
    for index in 0..key_count {
        let start = KEYS_AT + index * 32;
        let mut key = [0; 32];
        key.copy_from_slice(&bytes[start..start + 32]);
        if SshEd25519PublicKey::from_bytes(key).is_err() {
            return None;
        }
        if client_keys[..index].contains(&key) {
            return None;
        }
        client_keys[index] = key;
    }
    let mut client_seed = [0u8; 32];
    let mut client_public = [0u8; 32];
    client_seed.copy_from_slice(&bytes[320..352]);
    client_public.copy_from_slice(&bytes[352..384]);
    if flags & FLAG_CLIENT_KEYPAIR != 0 {
        if client_seed == [0; 32]
            || derive_public_key(&client_seed).ok()?.to_bytes() != client_public
        {
            return None;
        }
    } else if client_seed != [0; 32] || client_public != [0; 32] {
        return None;
    }
    Some(Config {
        generation,
        host_seed,
        client_keys,
        key_count: key_count as u8,
        flags,
        client_seed,
        client_public,
    })
}

fn derive_public_key(seed: &[u8; 32]) -> Result<SshEd25519PublicKey, ()> {
    let provisioned = ProvisionedHostSeed::from_trusted_bytes(*seed).map_err(|_| ())?;
    let signer =
        vibeos_ssh_identity::HostSigner::from_provisioned_seed(provisioned).map_err(|_| ())?;
    Ok(signer.public_key())
}

fn block_lease(
    rights: Rights,
) -> Result<
    vibeos_core::cap::InvocationLease<crate::block_device::BlockDevice>,
    crate::block_device::BlockError,
> {
    let world = crate::world::world();
    let cap = world
        .block
        .ok_or(crate::block_device::BlockError::Offline)?;
    let result = world.spaces["init"]
        .0
        .lock()
        .lookup_lease(cap, rights)
        .map_err(|_| crate::block_device::BlockError::PermissionDenied);
    result
}

async fn load_legacy() -> Result<Option<Config>, crate::block_device::BlockError> {
    let a = crate::block_device::read_with(block_lease(Rights::READ)?, LEGACY_SLOT_A).await?;
    let b = crate::block_device::read_with(block_lease(Rights::READ)?, LEGACY_SLOT_B).await?;
    Ok(match (decode(&a), decode(&b)) {
        (Some(a), Some(b)) => Some(if a.generation >= b.generation { a } else { b }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    })
}

fn map_store_error(_error: crate::store::StoreError) -> crate::block_device::BlockError {
    crate::block_device::BlockError::DeviceIo
}

fn config_journal() -> Result<crate::store::SealedConfigJournal, crate::block_device::BlockError> {
    let world = crate::world::world();
    let store = world
        .store
        .ok_or(crate::block_device::BlockError::Offline)?;
    let lease = world.spaces["init"]
        .0
        .lock()
        .lookup_lease::<crate::store::StoreService>(store, Rights::READ)
        .map_err(|_| crate::block_device::BlockError::PermissionDenied)?;
    Ok(lease.with(crate::store::StoreService::sealed_config_journal))
}

async fn latest_object_bytes() -> Result<Option<Vec<u8>>, crate::block_device::BlockError> {
    let kind = crate::store::journal_object_kind(CONFIG_OBJECT_KIND)
        .ok_or(crate::block_device::BlockError::Protocol)?;
    let journal = config_journal()?;
    journal.latest(kind).await.map_err(map_store_error)
}

async fn store_encoded(encoded: &[u8; 512]) -> Result<(), crate::block_device::BlockError> {
    let world = crate::world::world();
    let init = world.spaces["init"].clone();
    let store = world
        .store
        .ok_or(crate::block_device::BlockError::Offline)?;
    let lease = init
        .0
        .lock()
        .lookup_lease::<crate::store::StoreService>(store, Rights::WRITE)
        .map_err(|_| crate::block_device::BlockError::PermissionDenied)?;
    let kind = crate::store::journal_object_kind(CONFIG_OBJECT_KIND)
        .ok_or(crate::block_device::BlockError::Protocol)?;
    let cap = crate::store::put_with(lease, init.clone(), kind, encoded)
        .await
        .map_err(map_store_error)?;
    let _ = init.0.lock().revoke(cap);
    let mut observed = latest_object_bytes().await?;
    let matches = observed.as_deref() == Some(encoded.as_slice());
    if let Some(bytes) = observed.as_mut() {
        erase(bytes);
    }
    if !matches {
        return Err(crate::block_device::BlockError::DeviceIo);
    }
    Ok(())
}

pub async fn load() -> Result<Option<Config>, crate::block_device::BlockError> {
    if let Some(mut bytes) = latest_object_bytes().await? {
        let Ok(mut encoded): Result<[u8; 512], _> = bytes.as_slice().try_into() else {
            erase(&mut bytes);
            return Err(crate::block_device::BlockError::Protocol);
        };
        erase(&mut bytes);
        let decoded = decode(&encoded)
            .map(Some)
            .ok_or(crate::block_device::BlockError::Protocol);
        erase(&mut encoded);
        return decoded;
    }
    let Some(legacy) = load_legacy().await? else {
        return Ok(None);
    };
    let mut encoded = encode(&legacy);
    let stored = store_encoded(&encoded).await;
    erase(&mut encoded);
    stored?;
    Ok(Some(legacy))
}

async fn store(config: Config) -> Result<(), crate::block_device::BlockError> {
    let mut encoded = encode(&config);
    let result = store_encoded(&encoded).await;
    erase(&mut encoded);
    result
}

fn parse_hex_key(text: &str) -> Result<[u8; 32], Status> {
    if text.len() != 64 {
        return Err(Status::Usage);
    }
    let mut out = [0u8; 32];
    let bytes = text.as_bytes();
    for i in 0..32 {
        let nibble = |b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        };
        out[i] = (nibble(bytes[i * 2]).ok_or(Status::Usage)? << 4)
            | nibble(bytes[i * 2 + 1]).ok_or(Status::Usage)?;
    }
    SshEd25519PublicKey::from_bytes(out).map_err(|_| Status::Usage)?;
    Ok(out)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn parse_openssh_key(encoded: &str) -> Result<[u8; 32], Status> {
    let mut decoded = [0u8; 51];
    let mut out = 0usize;
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in encoded.bytes() {
        if byte == b'=' {
            break;
        }
        accumulator = (accumulator << 6) | u32::from(base64_value(byte).ok_or(Status::Usage)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if out == decoded.len() {
                return Err(Status::Usage);
            }
            decoded[out] = (accumulator >> bits) as u8;
            out += 1;
            accumulator &= (1u32 << bits).wrapping_sub(1);
        }
    }
    if out != decoded.len()
        || decoded[..4] != 11u32.to_be_bytes()
        || &decoded[4..15] != b"ssh-ed25519"
        || decoded[15..19] != 32u32.to_be_bytes()
    {
        return Err(Status::Usage);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded[19..]);
    SshEd25519PublicKey::from_bytes(key).map_err(|_| Status::Usage)?;
    Ok(key)
}

fn parse_public_key(args: &[String]) -> Result<[u8; 32], Status> {
    match args {
        [operation, key] if operation == "add" => parse_hex_key(key),
        [operation, algorithm, encoded, ..] if operation == "add" && algorithm == "ssh-ed25519" => {
            parse_openssh_key(encoded)
        }
        _ => Err(Status::Usage),
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (&left, &right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

pub fn onboarding_password_profile(
    username: &str,
    password: &str,
) -> Option<vibeos_sshd::AuthorizedProfile> {
    if !ONBOARDING_ACTIVE.load(Ordering::Acquire)
        || !constant_time_eq(username.as_bytes(), DEFAULT_USERNAME.as_bytes())
        || !constant_time_eq(password.as_bytes(), DEFAULT_PASSWORD.as_bytes())
    {
        return None;
    }
    onboarding_profile()
}

pub fn onboarding_profile() -> Option<vibeos_sshd::AuthorizedProfile> {
    if !ONBOARDING_ACTIVE.load(Ordering::Acquire) {
        return None;
    }
    Some(vibeos_sshd::AuthorizedProfile {
        generation: POLICY_GENERATION.load(Ordering::Acquire),
        profile: CapabilityProfileId::new(PROFILE)?,
    })
}

pub fn policy_changed() -> bool {
    POLICY_CHANGED.load(Ordering::Acquire)
}

pub async fn ensure_host_key() -> Result<Config, crate::block_device::BlockError> {
    if let Some(config) = load().await? {
        if config.has_host() {
            return Ok(config);
        }
    }
    let mut seed = [0u8; 32];
    crate::jitterentropy_random::fill_seed(&mut seed)
        .map_err(|_| crate::block_device::BlockError::DeviceIo)?;
    let mut config = load().await?.unwrap_or_else(Config::empty);
    config.generation = config
        .generation
        .checked_add(1)
        .ok_or(crate::block_device::BlockError::Protocol)?;
    config.host_seed = seed;
    config.flags |= FLAG_HOST;
    let stored = store(config).await;
    erase(&mut seed);
    stored?;
    load()
        .await?
        .ok_or(crate::block_device::BlockError::DeviceIo)
}

pub fn vsh_keygen(_args: &[String]) -> Result<String, Status> {
    if UPDATE_BUSY.swap(true, Ordering::AcqRel) {
        return Ok(String::from("SSH provisioning is busy\n"));
    }
    let mut seed = [0u8; 32];
    if let Err(error) = crate::jitterentropy_random::fill_seed(&mut seed) {
        UPDATE_BUSY.store(false, Ordering::Release);
        return Ok(format!("ssh-keygen failed: entropy {:?}\n", error));
    }
    let public = match derive_public_key(&seed) {
        Ok(public) => public.to_bytes(),
        Err(()) => {
            erase(&mut seed);
            UPDATE_BUSY.store(false, Ordering::Release);
            return Ok(String::from("ssh-keygen failed: invalid generated key\n"));
        }
    };
    crate::exec::spawn("ssh-keygen", async move {
        let result = async {
            let mut config = load().await?.unwrap_or_else(Config::empty);
            if config.flags & FLAG_CLIENT_KEYPAIR != 0 {
                return Err(crate::block_device::BlockError::Protocol);
            }
            config.generation = config
                .generation
                .checked_add(1)
                .ok_or(crate::block_device::BlockError::Protocol)?;
            config.client_seed = seed;
            config.client_public = public;
            config.flags |= FLAG_CLIENT_KEYPAIR;
            store(config).await
        }
        .await;
        match result {
            Ok(()) => {
                let mut seed = seed;
                erase(&mut seed);
                crate::uart::_print(format_args!(
                    "ssh-keygen: client keypair persisted; it was not authorized\n"
                ));
            }
            Err(error) => {
                let mut seed = seed;
                erase(&mut seed);
                crate::uart::_print(format_args!("ssh-keygen failed: {error}\n"));
            }
        }
        UPDATE_BUSY.store(false, Ordering::Release);
    });
    Ok(String::from(
        "ssh-keygen: generating and persisting an unregistered client keypair...\n",
    ))
}

pub fn vsh_keycat(args: Vec<String>) -> vibeos_vsh::AsyncCommandFuture {
    alloc::boxed::Box::pin(async move {
        let config = load().await.map_err(|_| Status::Unavailable)?;
        let config = config.ok_or(Status::Unavailable)?;
        if config.flags & FLAG_CLIENT_KEYPAIR == 0 {
            return Err(Status::Unavailable);
        }
        match args.first().map(String::as_str) {
            Some("ssh-client-key.pub") => {
                Ok(crate::ssh_key_format::openssh_public(&config.client_public))
            }
            Some("ssh-client-key") => Ok(crate::ssh_key_format::openssh_private(
                &config.client_seed,
                &config.client_public,
            )),
            _ => Err(Status::Usage),
        }
    })
}

pub fn vsh_authorize(args: &[String]) -> Result<String, Status> {
    let key = parse_public_key(args)?;
    if UPDATE_BUSY.swap(true, Ordering::AcqRel) {
        return Ok(String::from("SSH provisioning is busy\n"));
    }
    crate::exec::spawn("ssh-authorize", async move {
        let result = async {
            let mut config = load().await?.unwrap_or_else(Config::empty);
            if config.client_keys[..config.key_count as usize]
                .iter()
                .any(|existing| *existing == key)
            {
                return Ok(());
            }
            if config.key_count as usize == MAX_CLIENT_KEYS {
                return Err(crate::block_device::BlockError::OutOfRange);
            }
            config.generation = config
                .generation
                .checked_add(1)
                .ok_or(crate::block_device::BlockError::Protocol)?;
            config.client_keys[config.key_count as usize] = key;
            config.key_count += 1;
            config.flags |= FLAG_CLIENT;
            store(config).await
        }
        .await;
        match result {
            Ok(()) => {
                ONBOARDING_ACTIVE.store(false, Ordering::Release);
                POLICY_CHANGED.store(true, Ordering::Release);
                crate::uart::_print(format_args!(
                    "ssh-authorize: client key persisted; password authentication disabled\n"
                ));
            }
            Err(error) => crate::uart::_print(format_args!("ssh-authorize failed: {error}\n")),
        }
        UPDATE_BUSY.store(false, Ordering::Release);
    });
    Ok(String::from("ssh-authorize: persisting client key...\n"))
}

fn vsh_rm_inner(args: Vec<String>, physical_uart: bool) -> vibeos_vsh::AsyncCommandFuture {
    alloc::boxed::Box::pin(async move {
        let target = args.first().map(String::as_str).ok_or(Status::Usage)?;
        let remove_client_key = target == "ssh-client-key";
        let remove_authorization = target == "ssh-authorized-keys" && physical_uart;
        if !remove_client_key && !remove_authorization {
            return Err(Status::Usage);
        }
        if UPDATE_BUSY.swap(true, Ordering::AcqRel) {
            return Ok(String::from("SSH provisioning is busy\n"));
        }
        let result = async {
            let mut config = load()
                .await?
                .ok_or(crate::block_device::BlockError::DeviceIo)?;
            if !config.has_host() {
                return Err(crate::block_device::BlockError::Protocol);
            }
            config.generation = config
                .generation
                .checked_add(1)
                .ok_or(crate::block_device::BlockError::Protocol)?;
            if remove_client_key {
                erase(&mut config.client_seed);
                config.client_public = [0; 32];
                config.flags &= !FLAG_CLIENT_KEYPAIR;
            } else {
                config.client_keys = [[0; 32]; MAX_CLIENT_KEYS];
                config.key_count = 0;
                config.flags &= !FLAG_CLIENT;
            }
            store(config).await?;
            let verified = load()
                .await?
                .ok_or(crate::block_device::BlockError::DeviceIo)?;
            if (remove_client_key && verified.flags & FLAG_CLIENT_KEYPAIR != 0)
                || (remove_authorization
                    && (verified.flags & FLAG_CLIENT != 0 || verified.key_count != 0))
            {
                return Err(crate::block_device::BlockError::DeviceIo);
            }
            Ok(())
        }
        .await;
        UPDATE_BUSY.store(false, Ordering::Release);
        match result {
            Ok(()) => {
                if remove_authorization {
                    ONBOARDING_ACTIVE.store(true, Ordering::Release);
                    POLICY_CHANGED.store(true, Ordering::Release);
                    Ok(String::from(
                        "removed ssh-authorized-keys; password onboarding enabled\n",
                    ))
                } else {
                    Ok(String::from("removed ssh-client-key and public half\n"))
                }
            }
            Err(_) => Err(Status::Unavailable),
        }
    })
}

/// Remove only objects that cannot reopen password authentication.
pub fn vsh_rm(args: Vec<String>) -> vibeos_vsh::AsyncCommandFuture {
    vsh_rm_inner(args, false)
}

/// The physical UART additionally admits removal of the authorized-key set.
pub fn vsh_rm_uart(args: Vec<String>) -> vibeos_vsh::AsyncCommandFuture {
    vsh_rm_inner(args, true)
}

pub fn install_services(
    space: &crate::world::Space,
    config: Config,
) -> Result<
    (
        vibeos_core::cap::Cap,
        vibeos_core::cap::Cap,
        vibeos_core::cap::Cap,
    ),
    (),
> {
    if !config.has_host() {
        return Err(());
    }
    let generation = SecurityGeneration::new(config.generation).ok_or(())?;
    let seed = ProvisionedHostSeed::from_trusted_bytes(config.host_seed).map_err(|_| ())?;
    let signer = HostSigningService::from_provisioned_seed(seed, generation).map_err(|_| ())?;
    let profile = CapabilityProfileId::new(PROFILE).ok_or(())?;
    let mut entries = Vec::with_capacity(config.key_count as usize);
    for raw in &config.client_keys[..config.key_count as usize] {
        let key = SshEd25519PublicKey::from_bytes(*raw).map_err(|_| ())?;
        entries.push(AuthorizedKeyEntry::new(key, profile));
    }
    let policy =
        AuthorizedKeyPolicyService::new(entries.into_boxed_slice(), generation).map_err(|_| ())?;
    let mut cs = space.0.lock();
    let signer_read = cs.mint(signer.clone(), Rights::READ);
    let signer_invoke = cs.mint(signer, Rights::INVOKE);
    let policy = cs.mint(policy, Rights::READ);
    POLICY_GENERATION.store(config.generation, Ordering::Release);
    ONBOARDING_ACTIVE.store(!config.complete(), Ordering::Release);
    POLICY_CHANGED.store(false, Ordering::Release);
    Ok((signer_read, signer_invoke, policy))
}
