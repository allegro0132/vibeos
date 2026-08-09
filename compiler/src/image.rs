//! Canonical, address-independent executable images.
//!
//! Generated code ultimately runs in the kernel's shared S-mode address space,
//! so loading a persisted binary is a security boundary rather than a
//! convenience parser. The decoder accepts one exact little-endian
//! representation, and the linker revalidates every address placeholder before
//! writing an absolute address into caller-owned storage. The kernel separately
//! enforces the writable-to-execute-only page transition.
//!
//! Structural validation is not proof that arbitrary machine code came from
//! this compiler.  A loader must receive the image through a trusted compiled-
//! program capability or recompile its bound source and compare the canonical
//! bytes before execution.  Neither CRC32C field is an authenticity mechanism.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::{Image, Runtime};

pub const IMAGE_MAGIC: [u8; 8] = *b"VIBEEXE\0";
pub const IMAGE_FORMAT_VERSION: u16 = 1;
pub const IMAGE_HEADER_LEN: u16 = 64;
pub const TARGET_ABI_RV64IM_LP64_V1: u32 = 1;
pub const COMPILER_ABI_VERSION: u32 = 1;
pub const RUNTIME_ABI_VERSION: u32 = 1;

/// M4's object store admits at most 1024 360-byte chunks.  Keeping the bound in
/// the executable ABI lets a loader reject an object before allocating from
/// untrusted length fields.
pub const MAX_ENCODED_IMAGE_BYTES: usize = 360 * 1024;

const FLAGS_V1: u32 = 0;
const RELOCATION_RECORD_LEN: usize = 16;
const LI64_WORDS: usize = 11;
const T0: u32 = 5;
const A0: u32 = 10;
const OP_IMM: u32 = 0x13;
const JALR_RA_T0: u32 = 0x0002_80e7;
const RET: u32 = 0x0000_8067;

/// Stable runtime-import numbers carried by persisted relocation records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RuntimeImport {
    PrintStr = 1,
    PrintInt = 2,
    PrintBool = 3,
    Abort = 4,
}

impl RuntimeImport {
    pub const ALL: [Self; 4] = [Self::PrintStr, Self::PrintInt, Self::PrintBool, Self::Abort];

    pub const fn id(self) -> u32 {
        self as u32
    }

    pub const fn mask(self) -> u32 {
        1 << (self.id() - 1)
    }

    fn from_id(id: u32) -> Option<Self> {
        match id {
            1 => Some(Self::PrintStr),
            2 => Some(Self::PrintInt),
            3 => Some(Self::PrintBool),
            4 => Some(Self::Abort),
            _ => None,
        }
    }
}

/// One runtime symbol supplied by the loader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeBinding {
    pub import: RuntimeImport,
    pub address: u64,
}

/// Stable relocation kinds in the on-media ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum RelocationKind {
    DataAddress = 1,
    CodeCall = 2,
    RuntimeCall = 3,
}

/// The meaning of a relocation's `target` field is explicit in memory rather
/// than being left as an untyped integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocationTarget {
    /// Byte offset from the linked data base.
    DataOffset(u32),
    /// Instruction-word offset from the linked code base.
    CodeWord(u32),
    /// Stable runtime import supplied by the loader.
    Runtime(RuntimeImport),
}

impl RelocationTarget {
    pub const fn kind(self) -> RelocationKind {
        match self {
            Self::DataOffset(_) => RelocationKind::DataAddress,
            Self::CodeWord(_) => RelocationKind::CodeCall,
            Self::Runtime(_) => RelocationKind::RuntimeCall,
        }
    }

    const fn encoded_target(self) -> u32 {
        match self {
            Self::DataOffset(offset) | Self::CodeWord(offset) => offset,
            Self::Runtime(import) => import.id(),
        }
    }
}

/// One fixed-width, fixed-`li64` relocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Relocation {
    /// First instruction word of the eleven-word address placeholder.
    pub site_word: u32,
    pub target: RelocationTarget,
}

impl Relocation {
    pub const fn data_address(site_word: u32, byte_offset: u32) -> Self {
        Self {
            site_word,
            target: RelocationTarget::DataOffset(byte_offset),
        }
    }

    pub const fn code_call(site_word: u32, target_word: u32) -> Self {
        Self {
            site_word,
            target: RelocationTarget::CodeWord(target_word),
        }
    }

    pub const fn runtime_call(site_word: u32, import: RuntimeImport) -> Self {
        Self {
            site_word,
            target: RelocationTarget::Runtime(import),
        }
    }

    pub const fn kind(self) -> RelocationKind {
        self.target.kind()
    }
}

/// Header fields a kernel loader may inspect before linking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageMetadata {
    pub format_version: u16,
    pub target_abi: u32,
    pub compiler_abi: u32,
    pub runtime_abi: u32,
    pub funcs: u32,
    pub data_len: u32,
    pub code_words: u32,
    pub relocation_count: u32,
    pub required_runtime_imports: u32,
    /// These two fields identify the source used to compile the image. CRC32C
    /// is only an accidental-corruption check; it is not authentication or a
    /// rollback proof.
    pub source_len: u32,
    pub source_crc32c: u32,
    pub body_crc32c: u32,
}

/// A validated executable template containing no absolute addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelocatableImage {
    metadata: ImageMetadata,
    data: Vec<u8>,
    code_template: Vec<u32>,
    relocations: Vec<Relocation>,
}

impl RelocatableImage {
    /// Construct from compiler output or another trusted producer.  The same
    /// canonical and bounds checks used by `decode` apply here as well.
    pub fn from_parts(
        funcs: u32,
        source_len: u32,
        source_crc32c: u32,
        data: Vec<u8>,
        code_template: Vec<u32>,
        relocations: Vec<Relocation>,
    ) -> Result<Self, String> {
        let data_len = u32::try_from(data.len())
            .map_err(|_| "executable data length exceeds the v1 ABI".to_string())?;
        let code_words = u32::try_from(code_template.len())
            .map_err(|_| "executable code length exceeds the v1 ABI".to_string())?;
        let relocation_count = u32::try_from(relocations.len())
            .map_err(|_| "executable relocation count exceeds the v1 ABI".to_string())?;
        let required_runtime_imports = required_import_mask(&relocations);

        let mut image = Self {
            metadata: ImageMetadata {
                format_version: IMAGE_FORMAT_VERSION,
                target_abi: TARGET_ABI_RV64IM_LP64_V1,
                compiler_abi: COMPILER_ABI_VERSION,
                runtime_abi: RUNTIME_ABI_VERSION,
                funcs,
                data_len,
                code_words,
                relocation_count,
                required_runtime_imports,
                source_len,
                source_crc32c,
                body_crc32c: 0,
            },
            data,
            code_template,
            relocations,
        };
        image.validate()?;
        let body = image.encode_body();
        image.metadata.body_crc32c = crc32c(&body);
        Ok(image)
    }

    pub const fn metadata(&self) -> &ImageMetadata {
        &self.metadata
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn code_template(&self) -> &[u32] {
        &self.code_template
    }

    pub fn relocations(&self) -> &[Relocation] {
        &self.relocations
    }

    /// Encode the one canonical v1 little-endian representation.
    pub fn encode(&self) -> Vec<u8> {
        // Objects can only be constructed by checked paths, so these sizes are
        // known to fit both the ABI fields and MAX_ENCODED_IMAGE_BYTES.
        let body = self.encode_body();
        let mut out = alloc::vec![0u8; usize::from(IMAGE_HEADER_LEN)];
        out.extend_from_slice(&body);

        out[0..8].copy_from_slice(&IMAGE_MAGIC);
        put_u16(&mut out, 8, IMAGE_FORMAT_VERSION);
        put_u16(&mut out, 10, IMAGE_HEADER_LEN);
        put_u32(&mut out, 12, TARGET_ABI_RV64IM_LP64_V1);
        put_u32(&mut out, 16, COMPILER_ABI_VERSION);
        put_u32(&mut out, 20, RUNTIME_ABI_VERSION);
        put_u32(&mut out, 24, FLAGS_V1);
        put_u32(&mut out, 28, self.metadata.funcs);
        put_u32(&mut out, 32, self.metadata.data_len);
        put_u32(&mut out, 36, self.metadata.code_words);
        put_u32(&mut out, 40, self.metadata.relocation_count);
        put_u32(&mut out, 44, self.metadata.required_runtime_imports);
        put_u32(&mut out, 48, self.metadata.source_len);
        put_u32(&mut out, 52, self.metadata.source_crc32c);
        put_u32(&mut out, 56, crc32c(&body));
        // 60..64 is reserved and remains zero.
        out
    }

    /// Decode and validate a canonical v1 image without trusting any length,
    /// import, relocation, reserved field, or trailing byte from the object.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_ENCODED_IMAGE_BYTES {
            return Err("executable image exceeds the v1 size limit".to_string());
        }
        if bytes.len() < usize::from(IMAGE_HEADER_LEN) {
            return Err("truncated executable header".to_string());
        }
        if bytes[0..8] != IMAGE_MAGIC {
            return Err("bad executable magic".to_string());
        }
        if get_u16(bytes, 8)? != IMAGE_FORMAT_VERSION {
            return Err("unsupported executable format version".to_string());
        }
        if get_u16(bytes, 10)? != IMAGE_HEADER_LEN {
            return Err("non-canonical executable header length".to_string());
        }
        if get_u32(bytes, 12)? != TARGET_ABI_RV64IM_LP64_V1 {
            return Err("unsupported executable target ABI".to_string());
        }
        if get_u32(bytes, 16)? != COMPILER_ABI_VERSION {
            return Err("unsupported executable compiler ABI".to_string());
        }
        if get_u32(bytes, 20)? != RUNTIME_ABI_VERSION {
            return Err("unsupported executable runtime ABI".to_string());
        }
        if get_u32(bytes, 24)? != FLAGS_V1 {
            return Err("unknown executable flags".to_string());
        }
        if get_u32(bytes, 60)? != 0 {
            return Err("non-zero executable reserved header field".to_string());
        }

        let funcs = get_u32(bytes, 28)?;
        let data_len_u32 = get_u32(bytes, 32)?;
        let code_words_u32 = get_u32(bytes, 36)?;
        let relocation_count_u32 = get_u32(bytes, 40)?;
        let declared_imports = get_u32(bytes, 44)?;
        let source_len = get_u32(bytes, 48)?;
        let source_crc32c = get_u32(bytes, 52)?;
        let declared_body_crc = get_u32(bytes, 56)?;

        let data_len = usize::try_from(data_len_u32)
            .map_err(|_| "executable data length does not fit this target".to_string())?;
        let code_words = usize::try_from(code_words_u32)
            .map_err(|_| "executable code length does not fit this target".to_string())?;
        let relocation_count = usize::try_from(relocation_count_u32)
            .map_err(|_| "executable relocation count does not fit this target".to_string())?;
        let padding = padding_after(data_len);
        let code_bytes = code_words
            .checked_mul(4)
            .ok_or_else(|| "executable code byte length overflow".to_string())?;
        let relocation_bytes = relocation_count
            .checked_mul(RELOCATION_RECORD_LEN)
            .ok_or_else(|| "executable relocation byte length overflow".to_string())?;
        let body_len = data_len
            .checked_add(padding)
            .and_then(|n| n.checked_add(code_bytes))
            .and_then(|n| n.checked_add(relocation_bytes))
            .ok_or_else(|| "executable body length overflow".to_string())?;
        let expected_len = usize::from(IMAGE_HEADER_LEN)
            .checked_add(body_len)
            .ok_or_else(|| "executable total length overflow".to_string())?;
        if expected_len != bytes.len() {
            return Err(format!(
                "executable length mismatch: header describes {expected_len} bytes, object has {}",
                bytes.len()
            ));
        }

        let body = &bytes[usize::from(IMAGE_HEADER_LEN)..];
        if crc32c(body) != declared_body_crc {
            return Err("executable body CRC32C mismatch".to_string());
        }
        if bytes[usize::from(IMAGE_HEADER_LEN) + data_len
            ..usize::from(IMAGE_HEADER_LEN) + data_len + padding]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err("non-zero executable data padding".to_string());
        }

        let data_start = usize::from(IMAGE_HEADER_LEN);
        let code_start = data_start + data_len + padding;
        let relocation_start = code_start + code_bytes;
        let data = bytes[data_start..data_start + data_len].to_vec();
        let mut code_template = Vec::with_capacity(code_words);
        for chunk in bytes[code_start..relocation_start].chunks_exact(4) {
            code_template.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }

        let mut relocations = Vec::with_capacity(relocation_count);
        for record in bytes[relocation_start..].chunks_exact(RELOCATION_RECORD_LEN) {
            let site_word = u32::from_le_bytes([record[0], record[1], record[2], record[3]]);
            let kind = u16::from_le_bytes([record[4], record[5]]);
            let reserved0 = u16::from_le_bytes([record[6], record[7]]);
            let target = u32::from_le_bytes([record[8], record[9], record[10], record[11]]);
            let reserved1 = u32::from_le_bytes([record[12], record[13], record[14], record[15]]);
            if reserved0 != 0 || reserved1 != 0 {
                return Err("non-zero executable relocation reserved field".to_string());
            }
            let target = match kind {
                1 => RelocationTarget::DataOffset(target),
                2 => RelocationTarget::CodeWord(target),
                3 => RelocationTarget::Runtime(
                    RuntimeImport::from_id(target)
                        .ok_or_else(|| "unknown executable runtime import".to_string())?,
                ),
                _ => return Err("unknown executable relocation kind".to_string()),
            };
            relocations.push(Relocation { site_word, target });
        }

        let image = Self {
            metadata: ImageMetadata {
                format_version: IMAGE_FORMAT_VERSION,
                target_abi: TARGET_ABI_RV64IM_LP64_V1,
                compiler_abi: COMPILER_ABI_VERSION,
                runtime_abi: RUNTIME_ABI_VERSION,
                funcs,
                data_len: data_len_u32,
                code_words: code_words_u32,
                relocation_count: relocation_count_u32,
                required_runtime_imports: declared_imports,
                source_len,
                source_crc32c,
                body_crc32c: declared_body_crc,
            },
            data,
            code_template,
            relocations,
        };
        image.validate()?;
        Ok(image)
    }

    /// Link into caller-owned code storage with an explicit import table.
    ///
    /// `code` must have exactly the same number of words as the validated
    /// template. Every image, address, import, and output-length check runs
    /// before the first write, so an error always leaves `code` unchanged.
    pub fn link_into(
        &self,
        data_base: u64,
        code_base: u64,
        bindings: &[RuntimeBinding],
        code: &mut [u32],
    ) -> Result<(), String> {
        let import_addresses = self.preflight_link(data_base, code_base, bindings, code.len())?;
        self.link_into_prevalidated(data_base, code_base, &import_addresses, code);
        Ok(())
    }

    /// Link with an explicit import table. Duplicate bindings are rejected;
    /// all imports named by the image must be present.
    pub fn link(
        &self,
        data_base: u64,
        code_base: u64,
        bindings: &[RuntimeBinding],
    ) -> Result<Image, String> {
        // Preflight before allocating preserves the owned linker's hostile-
        // input bound while sharing the exact write path with `link_into`.
        let import_addresses =
            self.preflight_link(data_base, code_base, bindings, self.code_template.len())?;
        let mut code = alloc::vec![0; self.code_template.len()];
        self.link_into_prevalidated(data_base, code_base, &import_addresses, &mut code);

        Ok(Image {
            data: self.data.clone(),
            code,
            funcs: self.metadata.funcs as usize,
        })
    }

    fn preflight_link(
        &self,
        data_base: u64,
        code_base: u64,
        bindings: &[RuntimeBinding],
        output_words: usize,
    ) -> Result<[u64; 4], String> {
        self.validate()?;
        if output_words != self.code_template.len() {
            return Err(format!(
                "linked code buffer length mismatch: image requires {} words, caller supplied {}",
                self.code_template.len(),
                output_words
            ));
        }
        if code_base & 3 != 0 {
            return Err("linked code base is not four-byte aligned".to_string());
        }
        data_base
            .checked_add(self.data.len() as u64)
            .ok_or_else(|| "linked data address range overflows u64".to_string())?;
        let code_bytes = (self.code_template.len() as u64)
            .checked_mul(4)
            .ok_or_else(|| "linked code byte length overflows u64".to_string())?;
        code_base
            .checked_add(code_bytes)
            .ok_or_else(|| "linked code address range overflows u64".to_string())?;

        let mut import_addresses = [0; 4];
        let mut import_present = [false; 4];
        for binding in bindings {
            let slot = (binding.import.id() - 1) as usize;
            if import_present[slot] {
                return Err(format!("duplicate runtime import {:?}", binding.import));
            }
            import_addresses[slot] = binding.address;
            import_present[slot] = true;
        }

        // Resolve every relocation before touching caller storage. `validate`
        // already proved each target is within its corresponding image range;
        // these checked additions prove the chosen bases keep those concrete
        // addresses representable as well.
        for relocation in &self.relocations {
            match relocation.target {
                RelocationTarget::DataOffset(offset) => data_base
                    .checked_add(u64::from(offset))
                    .ok_or_else(|| "linked data relocation overflows u64".to_string())?,
                RelocationTarget::CodeWord(word) => {
                    let offset = u64::from(word)
                        .checked_mul(4)
                        .ok_or_else(|| "linked code relocation offset overflows u64".to_string())?;
                    code_base
                        .checked_add(offset)
                        .ok_or_else(|| "linked code relocation overflows u64".to_string())?
                }
                RelocationTarget::Runtime(import) => {
                    if !import_present[(import.id() - 1) as usize] {
                        return Err(format!("missing runtime import {:?}", import));
                    }
                    import_addresses[(import.id() - 1) as usize]
                }
            };
        }
        Ok(import_addresses)
    }

    fn link_into_prevalidated(
        &self,
        data_base: u64,
        code_base: u64,
        import_addresses: &[u64; 4],
        code: &mut [u32],
    ) {
        code.copy_from_slice(&self.code_template);
        for relocation in &self.relocations {
            // `preflight_link` proved these additions and import lookups. The
            // inputs are all immutably borrowed across both phases, so none of
            // those facts can change after the output copy begins.
            let address = match relocation.target {
                RelocationTarget::DataOffset(offset) => data_base + u64::from(offset),
                RelocationTarget::CodeWord(word) => code_base + u64::from(word) * 4,
                RelocationTarget::Runtime(import) => import_addresses[(import.id() - 1) as usize],
            };
            let rd = match relocation.target {
                RelocationTarget::DataOffset(_) => A0,
                RelocationTarget::CodeWord(_) | RelocationTarget::Runtime(_) => T0,
            };
            write_li64(code, relocation.site_word as usize, rd, address);
        }
    }

    /// Link into caller-owned code storage using the compatibility runtime
    /// table. The exact-length and no-write-on-error guarantees are identical
    /// to [`Self::link_into`].
    pub fn link_into_with_runtime(
        &self,
        data_base: u64,
        code_base: u64,
        runtime: &Runtime,
        code: &mut [u32],
    ) -> Result<(), String> {
        self.link_into(
            data_base,
            code_base,
            &[
                RuntimeBinding {
                    import: RuntimeImport::PrintStr,
                    address: runtime.print_str,
                },
                RuntimeBinding {
                    import: RuntimeImport::PrintInt,
                    address: runtime.print_int,
                },
                RuntimeBinding {
                    import: RuntimeImport::PrintBool,
                    address: runtime.print_bool,
                },
                RuntimeBinding {
                    import: RuntimeImport::Abort,
                    address: runtime.abort,
                },
            ],
            code,
        )
    }

    /// Compatibility convenience for the compiler's existing runtime struct.
    pub fn link_with_runtime(
        &self,
        data_base: u64,
        code_base: u64,
        runtime: &Runtime,
    ) -> Result<Image, String> {
        self.link(
            data_base,
            code_base,
            &[
                RuntimeBinding {
                    import: RuntimeImport::PrintStr,
                    address: runtime.print_str,
                },
                RuntimeBinding {
                    import: RuntimeImport::PrintInt,
                    address: runtime.print_int,
                },
                RuntimeBinding {
                    import: RuntimeImport::PrintBool,
                    address: runtime.print_bool,
                },
                RuntimeBinding {
                    import: RuntimeImport::Abort,
                    address: runtime.abort,
                },
            ],
        )
    }

    fn encode_body(&self) -> Vec<u8> {
        let padding = padding_after(self.data.len());
        let capacity = self.data.len()
            + padding
            + self.code_template.len() * 4
            + self.relocations.len() * RELOCATION_RECORD_LEN;
        let mut body = Vec::with_capacity(capacity);
        body.extend_from_slice(&self.data);
        body.resize(body.len() + padding, 0);
        for word in &self.code_template {
            body.extend_from_slice(&word.to_le_bytes());
        }
        for relocation in &self.relocations {
            body.extend_from_slice(&relocation.site_word.to_le_bytes());
            body.extend_from_slice(&(relocation.kind() as u16).to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&relocation.target.encoded_target().to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
        }
        body
    }

    fn validate(&self) -> Result<(), String> {
        if self.metadata.format_version != IMAGE_FORMAT_VERSION
            || self.metadata.target_abi != TARGET_ABI_RV64IM_LP64_V1
            || self.metadata.compiler_abi != COMPILER_ABI_VERSION
            || self.metadata.runtime_abi != RUNTIME_ABI_VERSION
        {
            return Err("executable metadata ABI mismatch".to_string());
        }
        if self.metadata.funcs == 0 || self.code_template.is_empty() {
            return Err("executable image has no entry function".to_string());
        }
        if self
            .code_template
            .iter()
            .filter(|word| **word == RET)
            .count()
            != self.metadata.funcs as usize
        {
            return Err("executable function-count metadata does not match its code".to_string());
        }
        if self.metadata.data_len as usize != self.data.len()
            || self.metadata.code_words as usize != self.code_template.len()
            || self.metadata.relocation_count as usize != self.relocations.len()
        {
            return Err("executable metadata length mismatch".to_string());
        }
        if self.metadata.required_runtime_imports != required_import_mask(&self.relocations) {
            return Err("executable runtime import mask mismatch".to_string());
        }
        if self.encoded_len()? > MAX_ENCODED_IMAGE_BYTES {
            return Err("executable image exceeds the v1 size limit".to_string());
        }

        let mut previous_site = None;
        let mut previous_end = 0usize;
        for relocation in &self.relocations {
            let site = usize::try_from(relocation.site_word)
                .map_err(|_| "executable relocation site does not fit this target".to_string())?;
            let end = site
                .checked_add(LI64_WORDS)
                .ok_or_else(|| "executable relocation site overflows".to_string())?;
            if end > self.code_template.len() {
                return Err("executable relocation placeholder is out of bounds".to_string());
            }
            if let Some(previous) = previous_site {
                if site <= previous {
                    return Err("executable relocations are not strictly ordered".to_string());
                }
                if site < previous_end {
                    return Err("executable relocation placeholders overlap".to_string());
                }
            }
            previous_site = Some(site);
            previous_end = end;

            let rd = match relocation.target {
                RelocationTarget::DataOffset(offset) => {
                    if offset as usize > self.data.len() {
                        return Err(
                            "executable data relocation target is out of bounds".to_string()
                        );
                    }
                    A0
                }
                RelocationTarget::CodeWord(word) => {
                    if word as usize >= self.code_template.len() {
                        return Err(
                            "executable code relocation target is out of bounds".to_string()
                        );
                    }
                    require_call_after(&self.code_template, end)?;
                    T0
                }
                RelocationTarget::Runtime(_) => {
                    require_call_after(&self.code_template, end)?;
                    T0
                }
            };
            if self.code_template[site..end] != li64_words(rd, 0) {
                return Err(
                    "executable relocation does not name a canonical zero placeholder".to_string(),
                );
            }
        }

        // No compiler-generated address placeholder may be omitted from the
        // relocation table.  A missing T0 call relocation would otherwise turn
        // into a call to address zero; a missing A0 relocation would silently
        // give a runtime hook an ungranted pointer.
        let a0_placeholder = li64_words(A0, 0);
        let t0_placeholder = li64_words(T0, 0);
        let mut relocation_cursor = 0usize;
        for site in 0..self.code_template.len().saturating_sub(LI64_WORDS - 1) {
            while self
                .relocations
                .get(relocation_cursor)
                .is_some_and(|relocation| (relocation.site_word as usize) < site)
            {
                relocation_cursor += 1;
            }
            let target = if self.code_template[site..site + LI64_WORDS] == a0_placeholder {
                Some(RelocationKind::DataAddress)
            } else if self.code_template[site..site + LI64_WORDS] == t0_placeholder {
                Some(
                    if self.code_template.get(site + LI64_WORDS) == Some(&JALR_RA_T0) {
                        RelocationKind::RuntimeCall // either call kind is accepted below
                    } else {
                        return Err("executable contains an unrecognized T0 address placeholder"
                            .to_string());
                    },
                )
            } else {
                None
            };
            let Some(kind) = target else { continue };
            let relocation = self
                .relocations
                .get(relocation_cursor)
                .filter(|relocation| relocation.site_word as usize == site);
            match (kind, relocation.map(|rel| rel.kind())) {
                (RelocationKind::DataAddress, Some(RelocationKind::DataAddress)) => {}
                (
                    RelocationKind::RuntimeCall,
                    Some(RelocationKind::RuntimeCall | RelocationKind::CodeCall),
                ) => {}
                _ => {
                    return Err(
                        "executable address placeholder is missing its relocation".to_string()
                    )
                }
            }
        }
        Ok(())
    }

    fn encoded_len(&self) -> Result<usize, String> {
        let code_bytes = self
            .code_template
            .len()
            .checked_mul(4)
            .ok_or_else(|| "executable code byte length overflow".to_string())?;
        let relocation_bytes = self
            .relocations
            .len()
            .checked_mul(RELOCATION_RECORD_LEN)
            .ok_or_else(|| "executable relocation byte length overflow".to_string())?;
        usize::from(IMAGE_HEADER_LEN)
            .checked_add(self.data.len())
            .and_then(|n| n.checked_add(padding_after(self.data.len())))
            .and_then(|n| n.checked_add(code_bytes))
            .and_then(|n| n.checked_add(relocation_bytes))
            .ok_or_else(|| "executable total length overflow".to_string())
    }
}

fn required_import_mask(relocations: &[Relocation]) -> u32 {
    relocations
        .iter()
        .fold(0, |mask, relocation| match relocation.target {
            RelocationTarget::Runtime(import) => mask | import.mask(),
            _ => mask,
        })
}

fn require_call_after(code: &[u32], after_placeholder: usize) -> Result<(), String> {
    if code.get(after_placeholder) != Some(&JALR_RA_T0) {
        return Err(
            "executable call relocation is not followed by canonical jalr ra,t0,0".to_string(),
        );
    }
    Ok(())
}

fn padding_after(len: usize) -> usize {
    (4 - (len & 3)) & 3
}

fn li64_words(rd: u32, value: u64) -> [u32; LI64_WORDS] {
    let mut words = [0u32; LI64_WORDS];
    words[0] = encode_addi(rd, 0, ((value >> 55) & 0x1ff) as i32);
    let mut at = 1;
    for k in (0..5).rev() {
        words[at] = encode_slli(rd, rd, 11);
        words[at + 1] = encode_addi(rd, rd, ((value >> (11 * k)) & 0x7ff) as i32);
        at += 2;
    }
    words
}

fn write_li64(code: &mut [u32], site: usize, rd: u32, value: u64) {
    code[site..site + LI64_WORDS].copy_from_slice(&li64_words(rd, value));
}

fn encode_addi(rd: u32, rs1: u32, immediate: i32) -> u32 {
    ((immediate as u32 & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | OP_IMM
}

fn encode_slli(rd: u32, rs1: u32, shift: u32) -> u32 {
    ((shift & 0xfff) << 20) | (rs1 << 15) | (1 << 12) | (rd << 7) | OP_IMM
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| "truncated executable integer".to_string())?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn get_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| "truncated executable integer".to_string())?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// Castagnoli CRC, matching the durable store.  It detects torn/corrupt bytes
/// but deliberately provides no authenticity or rollback guarantee.
pub(crate) fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
        }
    }
    !crc
}
