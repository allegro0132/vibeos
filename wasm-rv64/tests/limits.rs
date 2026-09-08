use vibeos_wasm_rv64::{compile, CompileError, Op, Slot};

#[test]
fn invalid_frame_references_are_rejected() {
    for (destination, source) in [(-1, 0), (2, 0), (0, -2), (0, 2)] {
        let ops = [Op::copy(Slot::from(destination), Slot::from(source))];
        assert!(matches!(compile(&ops, 2, 1, 100), Err(CompileError::Slot)));
    }
    assert!(compile(&[Op::copy(Slot::from(1i16), Slot::from(-1i16))], 2, 1, 100).is_ok());
}

#[test]
fn branch_cannot_escape_original_function() {
    for offset in [-1, 1, i32::MIN, i32::MAX] {
        assert!(matches!(
            compile(&[Op::branch(offset)], 1, 0, 100),
            Err(CompileError::Branch)
        ));
    }
}

#[test]
fn unmetered_backedge_falls_back_without_a_native_cycle() {
    let code = compile(&[Op::branch(0)], 1, 0, 100).unwrap();
    assert_eq!(code.lowered, 0);
    let ops = [Op::consume_fuel(1u32), Op::branch(-1i32)];
    assert_eq!(compile(&ops, 1, 0, 100).unwrap().lowered, 2);
    let ops = [Op::consume_fuel(0u32), Op::branch(-1i32)];
    assert_eq!(compile(&ops, 1, 0, 100).unwrap().lowered, 1);
}

#[test]
fn emission_budget_includes_exit_paths() {
    let ops = [Op::consume_fuel(u32::MAX), Op::Return];
    let words = compile(&ops, 0, 0, 100).unwrap().words.len();
    assert!(compile(&ops, 0, 0, words).is_ok());
    assert!(matches!(
        compile(&ops, 0, 0, words - 1),
        Err(CompileError::Limit)
    ));
    assert!(matches!(compile(&[], 0, 0, 100), Err(CompileError::Empty)));
}

#[test]
fn unsupported_instructions_remain_original_entry_points() {
    // Software floating-point operations still return to the interpreter.
    let ops = [
        Op::f32_add(Slot::from(0i16), Slot::from(1i16), Slot::from(1i16)),
        Op::Return,
    ];
    let code = compile(&ops, 2, 0, 100).unwrap();
    assert_eq!(code.lowered, 0);
    assert_eq!(code.entries.len(), 2);
    assert!(code.entries[0] < code.entries[1]);
    assert!(code.entries.iter().all(|offset| *offset < code.words.len()));
}

#[test]
fn malformed_table_and_select_parameters_are_rejected() {
    for count in [0u32, 1, u32::MAX] {
        assert!(matches!(
            compile(&[Op::branch_table_0(Slot::from(0i16), count)], 1, 0, 100),
            Err(CompileError::Branch)
        ));
    }
    let select = || Op::select_i32_eq_imm16(Slot::from(0i16), Slot::from(1i16), 0i16);
    assert!(matches!(
        compile(&[select(), Op::Return], 2, 0, 100),
        Err(CompileError::Branch)
    ));
    assert!(matches!(
        compile(
            &[
                select(),
                Op::Slot2 {
                    slots: [Slot::from(0i16), Slot::from(1i16)]
                }
            ],
            2,
            0,
            100
        ),
        Err(CompileError::Branch)
    ));
    let code = compile(
        &[
            select(),
            Op::Slot2 {
                slots: [Slot::from(0i16), Slot::from(1i16)],
            },
            Op::Return,
        ],
        2,
        0,
        100,
    )
    .unwrap();
    assert_eq!(code.supported, [true, false, false]);
}

#[test]
fn parallel_copy_checks_both_sources_and_destinations() {
    use wasmi_ir::{FixedSlotSpan, SlotSpan};
    for (destination, a, b) in [(-1i16, 0, 1), (1, 0, 1), (0, 0, 2), (0, -2, 0)] {
        let op = Op::Copy2 {
            results: FixedSlotSpan::new(SlotSpan::new(Slot::from(destination))).unwrap(),
            values: [Slot::from(a), Slot::from(b)],
        };
        assert!(matches!(compile(&[op], 2, 1, 200), Err(CompileError::Slot)));
    }
}
