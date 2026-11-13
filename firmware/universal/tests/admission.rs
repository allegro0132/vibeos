use vibeos_firmware_universal::{identify, supports_isa, Error};
use vibeos_hal::runtime_platform::BoardId;

fn dtb(properties: &[(&str, &[u8])]) -> Vec<u8> {
    let mut structure = vec![];
    let mut strings = vec![];
    structure.extend(1u32.to_be_bytes());
    structure.extend([0; 4]);
    for (name, value) in properties {
        let offset = strings.len() as u32;
        strings.extend(name.bytes());
        strings.push(0);
        structure.extend(3u32.to_be_bytes());
        structure.extend((value.len() as u32).to_be_bytes());
        structure.extend(offset.to_be_bytes());
        structure.extend(*value);
        while structure.len() % 4 != 0 {
            structure.push(0);
        }
    }
    structure.extend(2u32.to_be_bytes());
    structure.extend(9u32.to_be_bytes());
    let total = 56 + structure.len() + strings.len();
    let mut blob = vec![];
    for value in [
        0xd00dfeed,
        total as u32,
        56,
        (56 + structure.len()) as u32,
        40,
        17,
        16,
        0,
        strings.len() as u32,
        structure.len() as u32,
    ] {
        blob.extend(value.to_be_bytes());
    }
    blob.extend([0; 16]);
    blob.extend(structure);
    blob.extend(strings);
    blob
}
#[test]
fn identities_are_explicit_and_unambiguous() {
    for (compatible, marker, board) in [
        (
            b"riscv-virtio\0".as_slice(),
            b"qemu-virt\0".as_slice(),
            BoardId::QemuVirt,
        ),
        (
            b"milk-v,duo\0cvitek,cv1800b\0",
            b"milkv-duo\0",
            BoardId::MilkvDuo,
        ),
        (
            b"milk-v,mars\0starfive,jh7110\0",
            b"milkv-mars\0",
            BoardId::MilkvMars,
        ),
    ] {
        let bytes = dtb(&[("compatible", compatible), ("vibeos,board-id", marker)]);
        assert_eq!(identify(&bytes), Ok(board));
        for size in 0..bytes.len() {
            assert!(identify(&bytes[..size]).is_err());
        }
        assert_eq!(
            identify(&dtb(&[
                ("compatible", compatible),
                ("vibeos,board-id", b"wrong\0")
            ])),
            Err(Error::ConflictingIdentity)
        );
    }
    assert!(identify(&dtb(&[("compatible", b"cvitek,cv180x\0")])).is_err());
    assert_eq!(
        identify(&dtb(&[
            ("compatible", b"cvitek,cv180x\0"),
            ("vibeos,board-id", b"milkv-duo\0")
        ])),
        Ok(BoardId::MilkvDuo)
    );
    assert!(identify(&dtb(&[("compatible", b"starfive,jh7110\0")])).is_err());
    assert!(identify(&dtb(&[("compatible", b"riscv-virtio\0milk-v,duo\0")])).is_err());
    assert!(identify(&dtb(&[
        ("compatible", b"riscv-virtio\0"),
        ("compatible", b"riscv-virtio\0")
    ]))
    .is_err());
}
#[test]
fn isa_contract_rejects_missing_extensions() {
    assert!(supports_isa("rv64imac", false));
    assert!(!supports_isa("rv64imac", true));
    for isa in ["rv64gc", "rv64imafdc_zba_zbb"] {
        assert!(supports_isa(isa, true));
    }
    for isa in ["rv32imafdc", "rv64imaf", "rv64imc", "rv64"] {
        assert!(!supports_isa(isa, false));
    }
}
