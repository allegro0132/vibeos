#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]

//! # Usage
//!
//! Simple usage (allocating, no associated data):
//!
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! // NOTE: requires the `getrandom` feature is enabled
//!
//! use aes_gcm::{
//!     aead::{Aead, AeadCore, Generate, Key, KeyInit},
//!     Aes256Gcm, Nonce, // Or `Aes128Gcm`
//! };
//!
//! let key = Key::<Aes256Gcm>::generate();
//! let cipher = Aes256Gcm::new(&key);
//!
//! let nonce = Nonce::generate(); // MUST be unique per message
//! let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())?;
//!
//! let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;
//! assert_eq!(&plaintext, b"plaintext message");
//! # Ok(())
//! # }
//! ```
//!
//! ## In-place Usage (eliminates `alloc` requirement)
//!
//! This crate has an optional `alloc` feature which can be disabled in e.g.
//! microcontroller environments that don't have a heap.
//!
//! The [`AeadInOut::encrypt_in_place`] and [`AeadInOut::decrypt_in_place`]
//! methods accept any type that impls the [`aead::Buffer`] trait which
//! contains the plaintext for encryption or ciphertext for decryption.
//!
//! Enabling the `arrayvec` feature of this crate will provide an impl of
//! [`aead::Buffer`] for `arrayvec::ArrayVec` (re-exported from the [`aead`] crate as
//! [`aead::arrayvec::ArrayVec`]), and enabling the `bytes` feature of this crate will
//! provide an impl of [`aead::Buffer`] for `bytes::BytesMut` (re-exported from the
//! [`aead`] crate as [`aead::bytes::BytesMut`]).
//!
//! It can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
#![cfg_attr(all(feature = "getrandom", feature = "arrayvec"), doc = "```")]
#![cfg_attr(
    not(all(feature = "getrandom", feature = "arrayvec")),
    doc = "```ignore"
)]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! // NOTE: requires the `arrayvec` and `getrandom` features are enabled
//!
//! use aes_gcm::{
//!     aead::{AeadCore, AeadInOut, Generate, Key, KeyInit, arrayvec::ArrayVec},
//!     Aes256Gcm, Nonce, // Or `Aes128Gcm`
//! };
//!
//! let key = Key::<Aes256Gcm>::generate();
//! let cipher = Aes256Gcm::new(&key);
//!
//! let nonce = Nonce::generate(); // MUST be unique per message
//! let mut buffer: ArrayVec<u8, 128> = ArrayVec::new(); // Note: buffer needs 16-bytes overhead for auth tag
//! buffer.try_extend_from_slice(b"plaintext message").unwrap();
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(&nonce, b"", &mut buffer)?;
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(buffer.as_ref(), b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(&nonce, b"", &mut buffer)?;
//! assert_eq!(buffer.as_ref(), b"plaintext message");
//! # Ok(())
//! # }

/// Optional process-wide hardware dispatch used by VibeWRT.
#[cfg(feature = "eip197-backend")]
pub mod backend;
#[cfg(feature="eip197-backend")]
extern crate alloc;

pub use aead::{self, AeadCore, AeadInOut, Error, Key, KeyInit, KeySizeUser};

#[cfg(feature = "aes")]
pub use aes;

use aead::{TagPosition, inout::InOutBuf};

use cipher::{
    BlockCipherEncrypt, BlockSizeUser, InnerIvInit, StreamCipherCore,
    array::{Array, ArraySize},
    consts::U16,
};
use core::{fmt, marker::PhantomData};
use ghash::{GHash, universal_hash::UniversalHash};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[cfg(feature = "aes")]
use aes::{Aes128, Aes256, cipher::consts::U12};

/// Maximum length of associated data in bytes.
pub const A_MAX: u64 = (1 << 61) - 1;

/// Maximum length of plaintext in bytes.
pub const P_MAX: u64 = (1 << 36) - 32;

/// AES-GCM nonces.
pub type Nonce<NonceSize> = Array<u8, NonceSize>;

/// AES-GCM tags.
pub type Tag<TagSize = U16> = Array<u8, TagSize>;

/// Trait implemented for valid tag sizes, i.e.
/// [`U12`][consts::U12], [`U13`][consts::U13], [`U14`][consts::U14],
/// [`U15`][consts::U15] and [`U16`][consts::U16].
/// When the crate feature `hazmat` is enabled, [`U4`][consts::U4] and
/// [`U8`][consts::U8] are also supported.
pub trait TagSize: private::SealedTagSize {}

impl<T: private::SealedTagSize> TagSize for T {}

mod private {
    use cipher::{array::ArraySize, consts, typenum::Unsigned};

    // Sealed traits stop other crates from implementing any traits that use it.
    pub trait SealedTagSize: ArraySize + Unsigned {}

    #[cfg(feature = "hazmat")]
    impl SealedTagSize for consts::U4 {}
    #[cfg(feature = "hazmat")]
    impl SealedTagSize for consts::U8 {}

    impl SealedTagSize for consts::U12 {}
    impl SealedTagSize for consts::U13 {}
    impl SealedTagSize for consts::U14 {}
    impl SealedTagSize for consts::U15 {}
    impl SealedTagSize for consts::U16 {}
}

/// AES-GCM with a 128-bit key and 96-bit nonce.
#[cfg(feature = "aes")]
#[cfg_attr(docsrs, doc(cfg(feature = "aes")))]
pub type Aes128Gcm = AesGcm<Aes128, U12>;

/// AES-GCM with a 256-bit key and 96-bit nonce.
#[cfg(feature = "aes")]
#[cfg_attr(docsrs, doc(cfg(feature = "aes")))]
pub type Aes256Gcm = AesGcm<Aes256, U12>;

/// AES block.
type Block = Array<u8, U16>;

/// Counter mode with a 32-bit big endian counter.
type Ctr32BE<Aes> = ctr::CtrCore<Aes, ctr::flavors::Ctr32BE>;

/// AES-GCM: generic over an underlying AES implementation and nonce size.
///
/// This type is generic to support substituting alternative AES implementations
/// (e.g. embedded hardware implementations)
///
/// It is NOT intended to be instantiated with any block cipher besides AES!
/// Doing so runs the risk of unintended cryptographic properties!
///
/// The `NonceSize` generic parameter can be used to instantiate AES-GCM with other
/// nonce sizes, however it's recommended to use it with `typenum::U12`,
/// the default of 96-bits.
///
/// The `TagSize` generic parameter can be used to instantiate AES-GCM with other
/// authorization tag sizes, however it's recommended to use it with `typenum::U16`,
/// the default of 128-bits.
///
/// If in doubt, use the built-in [`Aes128Gcm`] and [`Aes256Gcm`] type aliases.
///
/// # ⚠️ WARNING: Hazmat!
///
/// When using short authentication tags, namely 32-bit tags with `typenum::U4` or
/// 64-bit tags with `typenum::U8` (which require the crate feature `hazmat`), it is
/// **RECOMMENDED** that a key not be used for more than the maximum invocations of
/// authenticated decryption specified in Table 1 or Table 2 of NIST SP 800-38D,
/// respectively.
#[derive(Clone)]
pub struct AesGcm<Aes, NonceSize, TagSize = U16>
where
    TagSize: crate::TagSize,
{
    /// Encryption cipher.
    cipher: Aes,
    #[cfg(feature = "eip197-backend")]
    raw_key: Option<backend::RawKey>,

    /// GHASH authenticator.
    ghash: GHash,

    /// Length of the nonce.
    nonce_size: PhantomData<NonceSize>,

    /// Length of the tag.
    tag_size: PhantomData<TagSize>,
}

impl<Aes, NonceSize, TagSize> KeySizeUser for AesGcm<Aes, NonceSize, TagSize>
where
    Aes: KeySizeUser,
    TagSize: crate::TagSize,
{
    type KeySize = Aes::KeySize;
}

impl<Aes, NonceSize, TagSize> KeyInit for AesGcm<Aes, NonceSize, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit,
    TagSize: crate::TagSize,
{
    fn new(key: &Key<Self>) -> Self {
        let cipher = Aes::new(key);
        let mut h = ghash::Key::default();
        cipher.encrypt_block(&mut h);
        let ghash = GHash::new(&h);
        #[cfg(feature = "eip197-backend")]
        let raw_key = backend::RawKey::new(key, h.as_ref());
        #[cfg(feature = "zeroize")]
        h.zeroize();
        Self {
            cipher,
            #[cfg(feature = "eip197-backend")]
            raw_key,
            ghash,
            nonce_size: PhantomData,
            tag_size: PhantomData,
        }
    }
}

impl<Aes, NonceSize, TagSize> From<Aes> for AesGcm<Aes, NonceSize, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    TagSize: crate::TagSize,
{
    fn from(cipher: Aes) -> Self {
        let mut ghash_key = ghash::Key::default();
        cipher.encrypt_block(&mut ghash_key);

        let ghash = GHash::new(&ghash_key);

        #[cfg(feature = "zeroize")]
        ghash_key.zeroize();

        Self {
            cipher,
            #[cfg(feature = "eip197-backend")]
            raw_key: None,
            ghash,
            nonce_size: PhantomData,
            tag_size: PhantomData,
        }
    }
}

impl<Aes, NonceSize, TagSize> AeadCore for AesGcm<Aes, NonceSize, TagSize>
where
    NonceSize: ArraySize,
    TagSize: crate::TagSize,
{
    type NonceSize = NonceSize;
    type TagSize = TagSize;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl<Aes, NonceSize, TagSize> AeadInOut for AesGcm<Aes, NonceSize, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    NonceSize: ArraySize,
    TagSize: crate::TagSize,
{
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<NonceSize>,
        associated_data: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<TagSize>, Error> {
        if buffer.len() as u64 > P_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        #[cfg(feature = "eip197-backend")]
        if let Some(result) = backend::dispatch(self.raw_key.as_ref(), nonce, associated_data, buffer.reborrow(), None, TagSize::to_usize()) {
            return result.and_then(|tag| Tag::<TagSize>::try_from(&tag[..]).map_err(|_| Error));
        }

        self.encrypt_cpu(nonce, associated_data, buffer)
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<NonceSize>,
        associated_data: &[u8],
        #[allow(unused_mut)]
        mut buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<TagSize>,
    ) -> Result<(), Error> {
        if buffer.len() as u64 > P_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        #[cfg(feature = "eip197-backend")]
        if let Some(result) = backend::dispatch(self.raw_key.as_ref(), nonce, associated_data, buffer.reborrow(), Some(tag), TagSize::to_usize()) {
            return result.map(|_| ());
        }

        self.decrypt_cpu(nonce, associated_data, buffer, tag)
    }
}

impl<Aes, NonceSize, TagSize> AesGcm<Aes, NonceSize, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    NonceSize: ArraySize,
    TagSize: crate::TagSize,
{
    fn encrypt_cpu(&self, nonce: &Nonce<NonceSize>, associated_data: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>) -> Result<Tag<TagSize>, Error> {
        let (ctr, mask) = self.init_ctr(nonce);

        // TODO(tarcieri): interleave encryption with GHASH
        // See: <https://github.com/RustCrypto/AEADs/issues/74>
        ctr.apply_keystream_partial(buffer.reborrow());

        let full_tag = self.compute_tag(mask, associated_data, buffer.get_out());
        full_tag[..TagSize::to_usize()]
            .try_into()
            .map_err(|_| Error)
    }
    fn decrypt_cpu(&self, nonce: &Nonce<NonceSize>, associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>, tag: &Tag<TagSize>) -> Result<(), Error> {
        let (ctr, mask) = self.init_ctr(nonce);

        // TODO(tarcieri): interleave encryption with GHASH
        // See: <https://github.com/RustCrypto/AEADs/issues/74>
        let expected_tag = self.compute_tag(mask, associated_data, buffer.get_in());

        use subtle::ConstantTimeEq;
        if expected_tag[..TagSize::to_usize()].ct_eq(tag).into() {
            ctr.apply_keystream_partial(buffer);
            Ok(())
        } else {
            Err(Error)
        }
    }

    /// Initialize counter mode.
    ///
    /// See algorithm described in Section 7.2 of NIST SP800-38D:
    /// <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf>
    ///
    /// > Define a block, J0, as follows:
    /// > If len(IV)=96, then J0 = IV || 0{31} || 1.
    /// > If len(IV) ≠ 96, then let s = 128 ⎡len(IV)/128⎤-len(IV), and
    /// >     J0=GHASH(IV||0s+64||[len(IV)]64).
    fn init_ctr(&self, nonce: &Nonce<NonceSize>) -> (Ctr32BE<&Aes>, Block) {
        let j0 = if NonceSize::to_usize() == 12 {
            let mut block = ghash::Block::default();
            block[..12].copy_from_slice(nonce);
            block[15] = 1;
            block
        } else {
            let mut ghash = self.ghash.clone();
            ghash.update_padded(nonce);

            let mut block = ghash::Block::default();
            let nonce_bits = (NonceSize::to_usize() as u64) * 8;
            block[8..].copy_from_slice(&nonce_bits.to_be_bytes());
            ghash.update(&[block]);
            ghash.finalize()
        };

        let mut ctr = Ctr32BE::inner_iv_init(&self.cipher, &j0);
        let mut tag_mask = Block::default();
        ctr.write_keystream_block(&mut tag_mask);
        (ctr, tag_mask)
    }

    /// Authenticate the given plaintext and associated data using GHASH.
    fn compute_tag(&self, mask: Block, associated_data: &[u8], buffer: &[u8]) -> Tag {
        let mut ghash = self.ghash.clone();
        ghash.update_padded(associated_data);
        ghash.update_padded(buffer);

        let associated_data_bits = (associated_data.len() as u64) * 8;
        let buffer_bits = (buffer.len() as u64) * 8;

        let mut block = ghash::Block::default();
        block[..8].copy_from_slice(&associated_data_bits.to_be_bytes());
        block[8..].copy_from_slice(&buffer_bits.to_be_bytes());
        ghash.update(&[block]);

        let mut tag = ghash.finalize();
        for (a, b) in tag.as_mut_slice().iter_mut().zip(mask.as_slice()) {
            *a ^= *b;
        }

        tag
    }
}

impl<Aes, NonceSize, TagSize> fmt::Debug for AesGcm<Aes, NonceSize, TagSize>
where
    TagSize: crate::TagSize,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AesGcm").finish_non_exhaustive()
    }
}

#[cfg(all(feature = "eip197-backend",feature="aes"))]
impl<Aes> AesGcm<Aes,U12,U16>
where Aes:BlockSizeUser<BlockSize=U16>+BlockCipherEncrypt {
    /// Try a synchronous hardware open that returns only authenticated storage.
    pub fn try_open_owned(&self, nonce: &[u8; 12], aad: &[u8], input: &[u8], tag: &[u8; 16])
        -> Option<Result<alloc::vec::Vec<u8>, Error>> {
        backend::open_owned(self.raw_key.as_ref(), nonce, aad, input, tag)
    }

    /// Submit borrowed ciphertext while the record is still in the TLS buffer.
    /// The returned operation owns everything needed for completion.
    pub fn start_decrypt_slice(&self, nonce: [u8; 12], aad: &[u8], input: &[u8], tag: [u8; 16])
        -> alloc::boxed::Box<dyn backend::Operation> {
        backend::submit_decrypt(self.raw_key.as_ref(), &nonce, aad, input, &tag)
            .unwrap_or_else(|| self.start_decrypt_owned(nonce, aad.to_vec(), input.to_vec(), tag))
    }

    /// Authenticate and decrypt owned ciphertext. Pending and error results
    /// carry no plaintext; only a successful completion transfers the buffer.
    pub fn start_decrypt_owned(&self, nonce: [u8; 12], aad: alloc::vec::Vec<u8>,
        mut input: alloc::vec::Vec<u8>, tag: [u8; 16]) -> alloc::boxed::Box<dyn backend::Operation> {
        let result = if let Some((backend, key)) = backend::async_target(self.raw_key.as_ref()) {
            // Preserve the hardware API's size checks even when admission is busy.
            if !backend::record_fits(input.len(), aad.len(), true) {
                Err(Error)
            } else {
                match backend.admit_owned(&key, input.len()) {
                    Err(e) => Err(e),
                    Ok(true) => return alloc::boxed::Box::new(backend::HardwareOperation::new(key, backend, nonce, aad, input, Some(tag))),
                    Ok(false) => self.decrypt_cpu((&nonce).into(), &aad, input.as_mut_slice().into(), (&tag).into()),
                }
            }
        } else {
            self.decrypt_inout_detached((&nonce).into(), &aad, input.as_mut_slice().into(), (&tag).into())
        }.map(|()| (core::mem::take(&mut input), [0; 16]));
        input.as_mut_slice().zeroize();
        alloc::boxed::Box::new(backend::ReadyOperation(Some(result)))
    }
    /// Try to submit plaintext and its trailer without building a temporary Vec.
    /// None leaves the caller responsible for the ordinary owned/CPU path.
    pub fn try_encrypt_slices(&self, nonce: &[u8; 12], aad: &[u8], input: &[u8], suffix: &[u8])
        -> Option<alloc::boxed::Box<dyn backend::Operation>> {
        backend::submit_encrypt(self.raw_key.as_ref(), nonce, aad, input, suffix)
    }

    /// Transfer an owned record to the selected backend. Selection is captured
    /// now; disabling hardware does not change an already admitted operation.
    pub fn start_encrypt_owned(&self,nonce:[u8;12],aad:alloc::vec::Vec<u8>,mut input:alloc::vec::Vec<u8>)->alloc::boxed::Box<dyn backend::Operation>{
        let result = if let Some((backend, key)) = backend::async_target(self.raw_key.as_ref()) {
            // Preserve the hardware API's size checks even when admission is busy.
            if !backend::record_fits(input.len(), aad.len(), false) {
                Err(Error)
            } else {
                match backend.admit_owned(&key, input.len()) {
                    Err(e) => Err(e),
                    Ok(true) => return alloc::boxed::Box::new(backend::HardwareOperation::new(key, backend, nonce, aad, input, None)),
                    Ok(false) => self.encrypt_cpu((&nonce).into(), &aad, input.as_mut_slice().into()),
                }
            }
        } else {
            self.encrypt_inout_detached((&nonce).into(), &aad, input.as_mut_slice().into())
        }.map(|tag| (core::mem::take(&mut input), tag.into()));
        input.as_mut_slice().zeroize();
        alloc::boxed::Box::new(backend::ReadyOperation(Some(result)))
    }
}
