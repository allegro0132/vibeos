//! M4.5 persisted executable ABI, relocation, and hostile-input tests.

use std::collections::BTreeMap;

use vibeos_rustc::image::{
    RelocatableImage, Relocation, RelocationKind, RelocationTarget, RuntimeBinding, RuntimeImport,
    COMPILER_ABI_VERSION, IMAGE_FORMAT_VERSION, IMAGE_HEADER_LEN, IMAGE_MAGIC,
    MAX_ENCODED_IMAGE_BYTES, RUNTIME_ABI_VERSION, TARGET_ABI_RV64IM_LP64_V1,
};
use vibeos_rustc::{codegen, compile_at, compile_relocatable, samples, Image, Runtime};

const HEADER_LEN: usize = IMAGE_HEADER_LEN as usize;
const RELOCATION_LEN: usize = 16;

const RICH: &str = r#"
fn twice(n: i64) -> i64 { n + n }
fn main() {
    print!("value={} flag={}", twice(21), true);
    println!("");
}
"#;

fn runtime() -> Runtime {
    Runtime {
        print_str: 0x1111_2222_3333_4444,
        print_int: 0x5555_6666_7777_8888,
        print_bool: 0x1357_9bdf_0246_8ace,
        abort: 0x9999_aaaa_bbbb_cccc,
    }
}

fn legacy_compile_at(src: &str, data_base: u64, code_base: u64, rt: &Runtime) -> Image {
    let toks = vibeos_rustc::lex::lex(src).unwrap();
    let parsed = vibeos_rustc::parse::Parser::new(toks).program().unwrap();
    let checked = vibeos_rustc::types::check(&parsed).unwrap();
    let literals = codegen::collect_strings(&checked, "\n");
    let mut data = Vec::new();
    let mut addresses = BTreeMap::new();
    for literal in literals {
        addresses.insert(literal.clone(), data_base + data.len() as u64);
        data.extend_from_slice(literal.as_bytes());
    }
    let legacy_runtime = codegen::Runtime {
        print_str: rt.print_str,
        print_int: rt.print_int,
        print_bool: rt.print_bool,
        abort: rt.abort,
    };
    let code = codegen::compile(&checked, code_base, addresses, &legacy_runtime).unwrap();
    Image {
        data,
        code,
        funcs: checked.funcs.len(),
    }
}

fn simulate_li64(words: &[u32]) -> u64 {
    assert_eq!(words.len(), 11);
    let mut value = 0u64;
    for word in words {
        let funct3 = (word >> 12) & 7;
        let rs1 = (word >> 15) & 0x1f;
        let immediate = (word >> 20) & 0xfff;
        match funct3 {
            0 => {
                let base = if rs1 == 0 { 0 } else { value };
                value = base.wrapping_add(u64::from(immediate));
            }
            1 => value <<= immediate & 0x3f,
            _ => panic!("not a canonical li64 instruction: {word:08x}"),
        }
    }
    value
}

fn runtime_address(import: RuntimeImport, rt: &Runtime) -> u64 {
    match import {
        RuntimeImport::PrintStr => rt.print_str,
        RuntimeImport::PrintInt => rt.print_int,
        RuntimeImport::PrintBool => rt.print_bool,
        RuntimeImport::Abort => rt.abort,
    }
}

fn relocation_start(image: &RelocatableImage) -> usize {
    let padding = (4 - (image.data().len() & 3)) & 3;
    HEADER_LEN + image.data().len() + padding + image.code_template().len() * 4
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn crc32c(bytes: &[u8]) -> u32 {
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

fn refresh_body_crc(bytes: &mut [u8]) {
    let crc = crc32c(&bytes[HEADER_LEN..]);
    put_u32(bytes, 56, crc);
}

fn rebuild(
    image: &RelocatableImage,
    code: Vec<u32>,
    relocations: Vec<Relocation>,
) -> Result<RelocatableImage, String> {
    let metadata = image.metadata();
    RelocatableImage::from_parts(
        metadata.funcs,
        metadata.source_len,
        metadata.source_crc32c,
        image.data().to_vec(),
        code,
        relocations,
    )
}

#[test]
fn persisted_encoding_is_deterministic_canonical_and_round_trips() {
    for source in [samples::HELLO, samples::DEMO, samples::CONFORMANCE, RICH] {
        let first = compile_relocatable(source).unwrap();
        let second = compile_relocatable(source).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.encode(), second.encode());

        let bytes = first.encode();
        assert_eq!(&bytes[..8], &IMAGE_MAGIC);
        assert_eq!(
            u16::from_le_bytes([bytes[8], bytes[9]]),
            IMAGE_FORMAT_VERSION
        );
        assert_eq!(u16::from_le_bytes([bytes[10], bytes[11]]), IMAGE_HEADER_LEN);
        assert_eq!(
            u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            TARGET_ABI_RV64IM_LP64_V1
        );
        assert_eq!(
            u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            COMPILER_ABI_VERSION
        );
        assert_eq!(
            u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
            RUNTIME_ABI_VERSION
        );
        assert_eq!(&bytes[60..64], &[0; 4]);
        assert_eq!(RelocatableImage::decode(&bytes).unwrap(), first);
        assert_eq!(RelocatableImage::decode(&bytes).unwrap().encode(), bytes);
        assert_eq!(first.metadata().source_len as usize, source.len());
        assert_eq!(first.metadata().source_crc32c, crc32c(source.as_bytes()));
        assert_eq!(first.metadata().body_crc32c, crc32c(&bytes[HEADER_LEN..]));
    }
}

#[test]
fn relocation_metadata_is_explicit_complete_and_strictly_ordered() {
    let image = compile_relocatable(RICH).unwrap();
    assert!(image
        .relocations()
        .iter()
        .any(|r| r.kind() == RelocationKind::DataAddress));
    assert!(image
        .relocations()
        .iter()
        .any(|r| r.kind() == RelocationKind::CodeCall));
    for import in RuntimeImport::ALL {
        assert!(image
            .relocations()
            .iter()
            .any(|r| r.target == RelocationTarget::Runtime(import)));
    }
    assert_eq!(image.metadata().required_runtime_imports, 0x0f);

    let leaf = compile_relocatable("fn main() {}").unwrap();
    assert_eq!(
        leaf.metadata().required_runtime_imports,
        RuntimeImport::Abort.mask(),
        "unused print hooks must not become ambient imports"
    );
    assert!(leaf.relocations().iter().all(|relocation| !matches!(
        relocation.target,
        RelocationTarget::Runtime(import) if import != RuntimeImport::Abort
    )));

    let mut previous_end = 0usize;
    for (index, relocation) in image.relocations().iter().enumerate() {
        let site = relocation.site_word as usize;
        if index != 0 {
            assert!(site >= previous_end, "relocations overlap at word {site}");
        }
        previous_end = site + 11;
    }
}

#[test]
fn linking_rewrites_only_declared_placeholders_to_checked_targets() {
    let image = compile_relocatable(RICH).unwrap();
    let rt = runtime();
    let data_base = 0x8000_1234_0000u64;
    let code_base = 0x9000_5678_0000u64;
    let linked = image.link_with_runtime(data_base, code_base, &rt).unwrap();
    let mut relocated = vec![false; linked.code.len()];

    for relocation in image.relocations() {
        let site = relocation.site_word as usize;
        let actual = simulate_li64(&linked.code[site..site + 11]);
        let expected = match relocation.target {
            RelocationTarget::DataOffset(offset) => data_base + u64::from(offset),
            RelocationTarget::CodeWord(word) => code_base + u64::from(word) * 4,
            RelocationTarget::Runtime(import) => runtime_address(import, &rt),
        };
        assert_eq!(actual, expected, "wrong target for {relocation:?}");
        relocated[site..site + 11].fill(true);
    }

    for (word, was_relocated) in relocated.iter().enumerate() {
        if !was_relocated {
            assert_eq!(linked.code[word], image.code_template()[word]);
        }
    }
    assert_eq!(linked.data, image.data());
    assert_eq!(linked.funcs, image.metadata().funcs as usize);
    assert_eq!(
        image.link_with_runtime(data_base, code_base, &rt).unwrap(),
        linked
    );
}

#[test]
fn compile_at_is_byte_for_byte_compatible_with_the_previous_codegen_path() {
    let rt = runtime();
    for (data_base, code_base) in [
        (0, 0),
        (0x8000_0000, 0x8010_0000),
        (0x1234_5678_9abc_0000, 0x2345_6789_abcd_0000),
    ] {
        for source in [samples::HELLO, samples::DEMO, samples::CONFORMANCE, RICH] {
            let linked = compile_at(source, data_base, code_base, &rt).unwrap();
            let legacy = legacy_compile_at(source, data_base, code_base, &rt);
            assert_eq!(
                linked, legacy,
                "changed output at bases {data_base:#x}/{code_base:#x}"
            );
        }
    }
}

#[test]
fn every_truncation_and_trailing_suffix_is_rejected() {
    let bytes = compile_relocatable(RICH).unwrap().encode();
    for end in 0..bytes.len() {
        assert!(
            RelocatableImage::decode(&bytes[..end]).is_err(),
            "accepted prefix {end}"
        );
    }
    for extra in 1..=32 {
        let mut extended = bytes.clone();
        extended.resize(extended.len() + extra, 0);
        assert!(
            RelocatableImage::decode(&extended).is_err(),
            "accepted {extra} trailing bytes"
        );
    }
}

#[test]
fn every_single_body_bit_corruption_is_rejected_by_crc32c() {
    let original = compile_relocatable(RICH).unwrap().encode();
    for offset in HEADER_LEN..original.len() {
        for bit in 0..8 {
            let mut corrupted = original.clone();
            corrupted[offset] ^= 1 << bit;
            assert!(
                RelocatableImage::decode(&corrupted).is_err(),
                "accepted body corruption at byte {offset} bit {bit}"
            );
        }
    }
}

#[test]
fn header_versions_flags_reserved_lengths_and_function_count_are_strict() {
    let original = compile_relocatable(RICH).unwrap().encode();
    let mutations: &[(usize, u32)] = &[
        (12, 2), // target ABI
        (16, 2), // compiler ABI
        (20, 2), // runtime ABI
        (24, 1), // flags
        (28, 0), // no entry function
        (32, u32::MAX),
        (36, u32::MAX),
        (40, u32::MAX),
        (44, u32::MAX),
        (60, 1), // reserved
    ];
    for &(offset, value) in mutations {
        let mut bytes = original.clone();
        put_u32(&mut bytes, offset, value);
        assert!(
            RelocatableImage::decode(&bytes).is_err(),
            "accepted header field at {offset}"
        );
    }

    for &(offset, value) in &[(8usize, 2u16), (10, 60)] {
        let mut bytes = original.clone();
        put_u16(&mut bytes, offset, value);
        assert!(RelocatableImage::decode(&bytes).is_err());
    }
    let mut bad_magic = original;
    bad_magic[0] ^= 1;
    assert!(RelocatableImage::decode(&bad_magic).is_err());
}

#[test]
fn noncanonical_padding_and_relocation_records_are_rejected() {
    let padded = compile_relocatable(r#"fn main() { print!("xx"); }"#).unwrap();
    assert_ne!(padded.data().len() & 3, 0);
    let mut bytes = padded.encode();
    bytes[HEADER_LEN + padded.data().len()] = 1;
    refresh_body_crc(&mut bytes);
    assert!(RelocatableImage::decode(&bytes).is_err());

    let image = compile_relocatable(RICH).unwrap();
    let start = relocation_start(&image);

    let mut unknown_kind = image.encode();
    put_u16(&mut unknown_kind, start + 4, 99);
    refresh_body_crc(&mut unknown_kind);
    assert!(RelocatableImage::decode(&unknown_kind).is_err());

    let runtime_record = image
        .relocations()
        .iter()
        .position(|rel| matches!(rel.target, RelocationTarget::Runtime(_)))
        .unwrap();
    let runtime_offset = start + runtime_record * RELOCATION_LEN;
    let mut unknown_import = image.encode();
    put_u32(&mut unknown_import, runtime_offset + 8, 99);
    refresh_body_crc(&mut unknown_import);
    assert!(RelocatableImage::decode(&unknown_import).is_err());

    for reserved in [runtime_offset + 6, runtime_offset + 12] {
        let mut nonzero = image.encode();
        nonzero[reserved] = 1;
        refresh_body_crc(&mut nonzero);
        assert!(RelocatableImage::decode(&nonzero).is_err());
    }
}

#[test]
fn malformed_relocation_sites_targets_and_templates_are_rejected() {
    let image = compile_relocatable(RICH).unwrap();
    let original = image.relocations().to_vec();
    assert!(original.len() >= 3);

    let mut duplicate = original.clone();
    duplicate[1].site_word = duplicate[0].site_word;
    assert!(rebuild(&image, image.code_template().to_vec(), duplicate).is_err());

    let mut overlap = original.clone();
    overlap[1].site_word = overlap[0].site_word + 1;
    assert!(rebuild(&image, image.code_template().to_vec(), overlap).is_err());

    let mut reversed = original.clone();
    reversed.swap(0, 1);
    assert!(rebuild(&image, image.code_template().to_vec(), reversed).is_err());

    let mut out_of_bounds = original.clone();
    out_of_bounds[0].site_word = u32::MAX;
    assert!(rebuild(&image, image.code_template().to_vec(), out_of_bounds).is_err());

    let mut bad_data_target = original.clone();
    let data = bad_data_target
        .iter_mut()
        .find(|rel| matches!(rel.target, RelocationTarget::DataOffset(_)))
        .unwrap();
    data.target = RelocationTarget::DataOffset(u32::MAX);
    assert!(rebuild(&image, image.code_template().to_vec(), bad_data_target).is_err());

    let mut bad_code_target = original.clone();
    let call = bad_code_target
        .iter_mut()
        .find(|rel| matches!(rel.target, RelocationTarget::CodeWord(_)))
        .unwrap();
    call.target = RelocationTarget::CodeWord(u32::MAX);
    assert!(rebuild(&image, image.code_template().to_vec(), bad_code_target).is_err());

    let mut bad_template = image.code_template().to_vec();
    bad_template[original[0].site_word as usize] ^= 1;
    assert!(rebuild(&image, bad_template, original.clone()).is_err());

    let mut missing = original;
    missing.remove(0);
    assert!(rebuild(&image, image.code_template().to_vec(), missing).is_err());
}

#[test]
fn linker_rejects_missing_duplicate_imports_and_address_overflow() {
    let image = compile_relocatable(RICH).unwrap();
    let rt = runtime();
    let complete = [
        RuntimeBinding {
            import: RuntimeImport::PrintStr,
            address: rt.print_str,
        },
        RuntimeBinding {
            import: RuntimeImport::PrintInt,
            address: rt.print_int,
        },
        RuntimeBinding {
            import: RuntimeImport::PrintBool,
            address: rt.print_bool,
        },
        RuntimeBinding {
            import: RuntimeImport::Abort,
            address: rt.abort,
        },
    ];
    assert!(image.link(0x1000, 0x2000, &complete[..3]).is_err());

    let mut duplicate = complete.to_vec();
    duplicate.push(complete[0]);
    assert!(image.link(0x1000, 0x2000, &duplicate).is_err());

    assert!(image.link(0x1000, 0x2002, &complete).is_err());
    assert!(image.link(u64::MAX, 0x2000, &complete).is_err());
    assert!(image.link(0x1000, u64::MAX, &complete).is_err());
}

#[test]
fn executable_size_limit_is_checked_before_decode_or_link_allocation() {
    let oversized = vec![0u8; MAX_ENCODED_IMAGE_BYTES + 1];
    assert!(RelocatableImage::decode(&oversized).is_err());

    let image = compile_relocatable("fn main() {}").unwrap();
    let too_much_data = vec![0u8; MAX_ENCODED_IMAGE_BYTES];
    assert!(RelocatableImage::from_parts(
        image.metadata().funcs,
        image.metadata().source_len,
        image.metadata().source_crc32c,
        too_much_data,
        image.code_template().to_vec(),
        image.relocations().to_vec(),
    )
    .is_err());
}
