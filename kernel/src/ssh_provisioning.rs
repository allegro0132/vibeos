//! Persistent, fail-closed SSH provisioning for Milk-V Duo.

extern crate alloc;

use alloc::{format, string::String, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use vibeos_core::cap::Rights;
use vibeos_ssh_identity::{
    AuthorizedKeyEntry, AuthorizedKeyPolicyService, CapabilityProfileId, HostSigningService,
    ProvisionedHostSeed, SecurityGeneration, SshEd25519PublicKey,
};
use vibeos_vsh::Status;

const SLOT_A: u64 = 16;
const SLOT_B: u64 = 17;
const MAGIC: &[u8; 8] = b"VSSHKEY1";
const VERSION: u16 = 1;
const FLAG_HOST: u16 = 1;
const FLAG_CLIENT: u16 = 2;
const CRC_AT: usize = 508;
const MAX_CLIENT_KEYS: usize = 8;
const KEYS_AT: usize = 56;
pub const PROFILE: u32 = 1;
static UPDATE_BUSY: AtomicBool = AtomicBool::new(false);

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
}
impl Drop for Config {
    fn drop(&mut self) {
        erase(&mut self.host_seed);
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
        }
    }
    pub fn complete(&self) -> bool {
        self.flags == FLAG_HOST | FLAG_CLIENT
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
    if flags & !(FLAG_HOST | FLAG_CLIENT) != 0 {
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
    Some(Config {
        generation,
        host_seed,
        client_keys,
        key_count: key_count as u8,
        flags,
    })
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

pub async fn load() -> Result<Option<Config>, crate::block_device::BlockError> {
    let a = crate::block_device::read_with(block_lease(Rights::READ)?, SLOT_A).await?;
    let b = crate::block_device::read_with(block_lease(Rights::READ)?, SLOT_B).await?;
    Ok(match (decode(&a), decode(&b)) {
        (Some(a), Some(b)) => Some(if a.generation >= b.generation { a } else { b }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    })
}

async fn store(config: Config) -> Result<(), crate::block_device::BlockError> {
    let sector = if config.generation & 1 == 0 {
        SLOT_A
    } else {
        SLOT_B
    };
    let encoded = encode(&config);
    crate::block_device::write_with(block_lease(Rights::WRITE)?, sector, encoded).await?;
    crate::block_device::flush_with(block_lease(Rights::WRITE)?).await?;
    let observed = crate::block_device::read_with(block_lease(Rights::READ)?, sector).await?;
    if observed != encoded {
        return Err(crate::block_device::BlockError::DeviceIo);
    }
    Ok(())
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

pub fn vsh_keygen(_args: &[String]) -> Result<String, Status> {
    if UPDATE_BUSY.swap(true, Ordering::AcqRel) {
        return Ok(String::from("SSH provisioning is busy\n"));
    }
    let mut seed = [0u8; 32];
    if let Err(error) = crate::jitterentropy_random::fill_seed(&mut seed) {
        UPDATE_BUSY.store(false, Ordering::Release);
        return Ok(format!("ssh-keygen failed: entropy {:?}\n", error));
    }
    crate::exec::spawn("ssh-keygen", async move {
        let result = async {
            let mut config = load().await?.unwrap_or_else(Config::empty);
            config.generation = config
                .generation
                .checked_add(1)
                .ok_or(crate::block_device::BlockError::Protocol)?;
            config.host_seed = seed;
            config.flags |= FLAG_HOST;
            store(config).await
        }
        .await;
        let mut erased = seed;
        erase(&mut erased);
        match result {
            Ok(()) => crate::uart::_print(format_args!(
                "ssh-keygen: host key persisted and verified\n"
            )),
            Err(error) => crate::uart::_print(format_args!("ssh-keygen failed: {error}\n")),
        }
        UPDATE_BUSY.store(false, Ordering::Release);
    });
    Ok(String::from(
        "ssh-keygen: generating and persisting host key...\n",
    ))
}

pub fn vsh_authorize(args: &[String]) -> Result<String, Status> {
    if args.first().map(String::as_str) != Some("add") {
        return Err(Status::Usage);
    }
    let key = parse_hex_key(&args[1])?;
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
            Ok(()) => crate::uart::_print(format_args!(
                "ssh-authorize: client key persisted; SSH will start when configuration is complete\n"
            )),
            Err(error) => crate::uart::_print(format_args!("ssh-authorize failed: {error}\n")),
        }
        UPDATE_BUSY.store(false, Ordering::Release);
    });
    Ok(String::from("ssh-authorize: persisting client key...\n"))
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
    if !config.complete() {
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
    Ok((signer_read, signer_invoke, policy))
}
