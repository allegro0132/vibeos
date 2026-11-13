//! Packed 193-byte VLAN rule encoding for qualified MxL firmware 1.0.70.70.
//! Offsets independently checked with sizeof/offsetof of the pinned vendor
//! mxl862xx-api.h. Never transmute Rust/C enums or bools onto the wire.
use crate::{mxl862xx::VlanRule, mxl_tag::Port};

#[derive(Clone, Copy, Debug)]
pub(crate) enum Rule {
    PushUntagged(Port),
    PushSingleTagged(Port),
    PushDoubleTagged(Port),
    PopOuter(Port),
    PopOuterTagged(Port),
    ClassifyCpu(Port),
    DropAnySingleTagged,
    DropAnyDoubleTagged,
    DropSingleTagged,
    DropDoubleTagged,
}
impl Rule {
    pub(crate) fn encode(self, block: u16, index: u16) -> [u8; 193] {
        let mut b = [0; 193];
        b[..2].copy_from_slice(&block.to_le_bytes());
        b[2..4].copy_from_slice(&index.to_le_bytes());
        let mut word = |off, value: u32| b[off..off + 4].copy_from_slice(&value.to_le_bytes());
        word(31, 3); // inner NO_TAG
        match self {
            Self::PushUntagged(port)
            | Self::PushSingleTagged(port)
            | Self::PushDoubleTagged(port) => {
                word(
                    9,
                    if matches!(self, Self::PushUntagged(_)) {
                        3
                    } else {
                        1
                    },
                );
                if matches!(self, Self::PushDoubleTagged(_)) {
                    word(31, 1);
                }
                word(78, port.vid() as u32);
                word(82, 3); // treatment TPID 802.1Q
                word(86, 2); // treatment DEI zero
                b[65] = 1; // add outer VLAN
            }
            Self::PopOuter(port) | Self::PopOuterTagged(port) | Self::ClassifyCpu(port) => {
                word(19, port.vid() as u32);
                word(23, 1); // filter TPID 802.1Q
                if matches!(self, Self::PopOuter(_) | Self::PopOuterTagged(_)) {
                    word(57, 1);
                }
                if matches!(self, Self::PopOuterTagged(_)) {
                    word(31, 1);
                }
                b[18] = 1; // match outer VID
                if matches!(self, Self::ClassifyCpu(_)) {
                    b[115] = 1;
                    b[116..118].copy_from_slice(&(port.dt_index() as u16 + 17).to_le_bytes());
                }
            }
            Self::DropAnySingleTagged | Self::DropAnyDoubleTagged => {
                word(9, 1); // Any outer tag; this does not match an absent tag.
                if matches!(self, Self::DropAnyDoubleTagged) { word(31, 1); }
                word(57, 3);
            }
            Self::DropSingleTagged | Self::DropDoubleTagged => {
                if matches!(self, Self::DropDoubleTagged) {
                    word(31, 1);
                }
                word(9, 2); // outer DEFAULT, inner NO_TAG
                word(57, 3); // DISCARD_UPSTREAM
            }
        }
        b
    }
    pub(crate) fn matches(self, got: &VlanRule) -> bool {
        let (
            outer,
            vid_enabled,
            match_vid,
            filter_tpid,
            remove,
            add,
            vid,
            tpid,
            dei,
            reassign,
            bridge,
        ) = match self {
            Self::PushUntagged(p) => (3, false, 0, 0, 0, true, p.vid() as u32, 3, 2, false, 0),
            Self::PushSingleTagged(p) | Self::PushDoubleTagged(p) => {
                (1, false, 0, 0, 0, true, p.vid() as u32, 3, 2, false, 0)
            }
            Self::PopOuter(p) | Self::PopOuterTagged(p) => {
                (0, true, p.vid() as u32, 1, 1, false, 0, 0, 0, false, 0)
            }
            Self::ClassifyCpu(p) => (
                0,
                true,
                p.vid() as u32,
                1,
                0,
                false,
                0,
                0,
                0,
                true,
                p.dt_index() as u16 + 17,
            ),
            Self::DropAnySingleTagged | Self::DropAnyDoubleTagged =>
                (1, false, 0, 0, 3, false, 0, 0, 0, false, 0),
            Self::DropSingleTagged | Self::DropDoubleTagged => {
                (2, false, 0, 0, 3, false, 0, 0, 0, false, 0)
            }
        };
        !got.original_packet
            && !got.extra_actions
            && got.outer_filter == outer
            && got.inner_filter
                == if matches!(
                    self,
                    Self::PushDoubleTagged(_) | Self::PopOuterTagged(_) | Self::DropDoubleTagged | Self::DropAnyDoubleTagged
                ) {
                    1
                } else {
                    3
                }
            && got.match_vid_enabled == vid_enabled
            && (!vid_enabled || (got.match_vid == match_vid && got.filter_tpid == filter_tpid))
            && got.remove == remove
            && got.add_outer == add
            && (!add
                || (got.outer_vid_mode == 0
                    && got.outer_vid == vid
                    && got.outer_tpid == tpid
                    && got.outer_dei == dei))
            && got.reassign_bridge == reassign
            && (!reassign || got.bridge_port == bridge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independently_checked_packed_fields_and_zero_tail() {
        let b = Rule::PushUntagged(Port::Sfp).encode(0x1234, 2);
        assert_eq!(&b[..4], &[0x34, 0x12, 2, 0]);
        assert_eq!(&b[9..13], &[3, 0, 0, 0]);
        assert_eq!(&b[31..35], &[3, 0, 0, 0]);
        assert_eq!(b[65], 1);
        assert_eq!(&b[78..90], &[12, 12, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0]);
        assert!(b[90..].iter().all(|v| *v == 0));
        let b = Rule::ClassifyCpu(Port::Copper3).encode(4, 1);
        assert_eq!(b[18], 1);
        assert_eq!(&b[19..27], &[3, 12, 0, 0, 1, 0, 0, 0]);
        assert_eq!(&b[115..118], &[1, 20, 0]);
        let b = Rule::PopOuter(Port::Copper0).encode(4, 0);
        assert_eq!(&b[57..61], &[1, 0, 0, 0]);
        assert_eq!(b[65], 0);
        let b = Rule::DropSingleTagged.encode(4, 3);
        assert_eq!(b[9], 2);
        assert_eq!(b[57], 3);
    }
}
