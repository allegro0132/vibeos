use std::task::{Context, Poll, Waker};
use vibeos_wasi_runtime::*;
#[derive(Default)]
struct Io {
    input: Vec<u8>,
    position: usize,
    out: Vec<u8>,
    err: Vec<u8>,
    writes: usize,
}
impl WasiIo for Io {
    fn read(&mut self, _: &mut Context<'_>, output: &mut [u8]) -> Poll<Result<usize, WasiIoError>> {
        let n = output.len().min(self.input.len() - self.position).min(13);
        output[..n].copy_from_slice(&self.input[self.position..self.position + n]);
        self.position += n;
        Poll::Ready(Ok(n))
    }
    fn write(
        &mut self,
        _: &mut Context<'_>,
        fd: u32,
        input: &[u8],
    ) -> Poll<Result<usize, WasiIoError>> {
        self.writes += 1;
        let n = input.len().min(7);
        if fd == 1 {
            self.out.extend_from_slice(&input[..n]);
        } else {
            self.err.extend_from_slice(&input[..n]);
        }
        Poll::Ready(Ok(n))
    }
}
fn run(wat: &str, io: &mut Io, limits: WasiLimits) -> WasiTerminal {
    let wasm = wat::parse_str(wat).unwrap();
    let mut instance = WasiInvocation::new(&wasm, &["test.wasm".into()], limits).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..100_000 {
        if let Poll::Ready(terminal) = instance.poll(&mut cx, io) {
            assert_eq!(instance.poll(&mut cx, io), Poll::Ready(terminal));
            return terminal;
        }
    }
    panic!("invocation never completed")
}
#[test]
fn exit_is_non_returning_and_preserves_u32() {
    let terminal = run(
        r#"(module (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32))) (memory (export "memory") 1) (func (export "_start") i32.const -1 call $exit unreachable))"#,
        &mut Io::default(),
        WasiLimits::default(),
    );
    assert_eq!(terminal, WasiTerminal::Exited(u32::MAX));
}
#[test]
fn malicious_later_iovec_has_no_output() {
    let mut io = Io::default();
    let terminal = run(
        r#"(module (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32))) (memory (export "memory") 1)
    (data (i32.const 0) "\20\00\00\00\01\00\00\00\ff\ff\ff\ff\01\00\00\00")
    (func (export "_start") i32.const 1 i32.const 0 i32.const 2 i32.const 24 call $write i32.const 21 i32.ne if unreachable end))"#,
        &mut io,
        WasiLimits::default(),
    );
    assert_eq!(terminal, WasiTerminal::Exited(0));
    assert_eq!(io.writes, 0);
}
#[test]
fn bad_result_pointer_has_no_output() {
    let mut io = Io::default();
    run(
        r#"(module (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32))) (memory (export "memory") 1)
    (data (i32.const 0) "\20\00\00\00\01\00\00\00")
    (func (export "_start") i32.const 1 i32.const 0 i32.const 1 i32.const -1 call $write drop))"#,
        &mut io,
        WasiLimits::default(),
    );
    assert_eq!(io.writes, 0);
}
#[test]
fn loop_and_growth_are_contained() {
    for body in ["(loop $l br $l)", "i32.const 100 memory.grow drop"] {
        let wat =
            format!("(module (memory (export \"memory\") 1) (func (export \"_start\") {body}))");
        let limits = WasiLimits {
            total_fuel: 1000,
            poll_quantum: 100,
            memory_bytes: 65536,
            ..Default::default()
        };
        assert_eq!(
            run(&wat, &mut Io::default(), limits),
            WasiTerminal::LimitExceeded
        );
    }
}
#[test]
fn closed_import_and_start_contract() {
    for wat in [
        r#"(module (import "env" "x" (func)) (memory (export "memory") 1) (func (export "_start")))"#,
        r#"(module (import "wasi_snapshot_preview1" "fd_write" (func)) (memory (export "memory") 1) (func (export "_start")))"#,
        r#"(module (memory (export "memory") 1) (func $f (export "_start")) (start $f))"#,
        r#"(module (memory (export "memory") 1) (func (export "_start") (result i32) i32.const 0))"#,
    ] {
        assert!(WasiInvocation::new(
            &wat::parse_str(wat).unwrap(),
            &["test".into()],
            Default::default()
        )
        .is_err());
    }
}
#[test]
fn cancellation_is_stable() {
    let bytes = wat::parse_str(
        "(module (memory (export \"memory\") 1) (func (export \"_start\") unreachable))",
    )
    .unwrap();
    let mut invocation = WasiInvocation::new(&bytes, &["test".into()], Default::default()).unwrap();
    invocation.cancel();
    let mut io = Io::default();
    assert_eq!(
        invocation.poll(&mut Context::from_waker(Waker::noop()), &mut io),
        Poll::Ready(WasiTerminal::Cancelled)
    );
}
#[test]
#[ignore = "run with WASI_EXAMPLE after building standard-library examples"]
fn genuine_standard_library() {
    let bytes = std::fs::read(std::env::var("WASI_EXAMPLE").unwrap()).unwrap();
    for (args, input, out, err, status) in [
        (
            vec!["args", "a b", "中文"],
            &b""[..],
            &b"a b\n\xe4\xb8\xad\xe6\x96\x87\n"[..],
            &b""[..],
            0,
        ),
        (
            vec!["filter"],
            &b"hello\0world\n"[..],
            &b"HELLO\0WORLD\n"[..],
            &b""[..],
            0,
        ),
        (vec!["stderr"], &b""[..], &b"out\n"[..], &b"err\n"[..], 0),
        (vec!["exit"], &b""[..], &b""[..], &b""[..], 7),
    ] {
        let argv: Vec<_> = std::iter::once("test.wasm")
            .chain(args)
            .map(String::from)
            .collect();
        let mut instance = WasiInvocation::new(&bytes, &argv, Default::default()).unwrap();
        let mut io = Io {
            input: input.into(),
            ..Default::default()
        };
        let mut result = None;
        for _ in 0..100_000 {
            if let Poll::Ready(terminal) =
                instance.poll(&mut Context::from_waker(Waker::noop()), &mut io)
            {
                result = Some(terminal);
                break;
            }
        }
        assert_eq!(
            result,
            Some(WasiTerminal::Exited(status)),
            "stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&io.out),
            String::from_utf8_lossy(&io.err)
        );
        assert_eq!(io.out, out);
        assert_eq!(io.err, err);
    }
}

#[test]
fn standard_descriptors_and_known_stubs() {
    let t = run(
        r#"(module
      (import "wasi_snapshot_preview1" "fd_fdstat_get" (func $stat (param i32 i32)(result i32)))
      (import "wasi_snapshot_preview1" "fd_filestat_get" (func $file (param i32 i32)(result i32)))
      (import "wasi_snapshot_preview1" "fd_close" (func $close (param i32)(result i32)))
      (import "wasi_snapshot_preview1" "fd_tell" (func $tell (param i32 i32)(result i32)))
      (import "wasi_snapshot_preview1" "fd_prestat_get" (func $pre (param i32 i32)(result i32)))
      (import "wasi_snapshot_preview1" "random_get" (func $random (param i32 i32)(result i32)))
      (memory (export "memory") 1)
      (func (export "_start")
        i32.const 1 i32.const 0 call $stat if unreachable end
        i32.const 0 i32.load8_u i32.const 2 i32.ne if unreachable end
        i32.const 8 i64.load i64.const 2097216 i64.ne if unreachable end
        i32.const 1 i32.const 32 call $file if unreachable end
        i32.const 48 i32.load8_u i32.const 2 i32.ne if unreachable end
        i32.const 1 i32.const 0 call $tell i32.const 70 i32.ne if unreachable end
        i32.const 3 i32.const 0 call $pre i32.const 8 i32.ne if unreachable end
        i32.const -1 i32.const -1 call $random i32.const 52 i32.ne if unreachable end
        i32.const 1 call $close if unreachable end
        i32.const 1 call $close i32.const 8 i32.ne if unreachable end
        i32.const 1 i32.const 0 call $stat i32.const 8 i32.ne if unreachable end))"#,
        &mut Io::default(),
        Default::default(),
    );
    assert_eq!(t, WasiTerminal::Exited(0));
}

#[test]
fn invalid_read_result_does_not_consume_input() {
    let mut io = Io {
        input: b"secret".to_vec(),
        ..Default::default()
    };
    let t = run(
        r#"(module
      (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32)(result i32)))
      (memory (export "memory") 1) (data(i32.const 0) "\20\00\00\00\01\00\00\00")
      (func (export "_start") i32.const 0 i32.const 0 i32.const 1 i32.const -1 call $read
        i32.const 21 i32.ne if unreachable end))"#,
        &mut io,
        Default::default(),
    );
    assert_eq!(t, WasiTerminal::Exited(0));
    assert_eq!(io.position, 0);
}

#[test]
fn pending_input_does_not_burn_fuel_and_can_be_denied() {
    struct Pending;
    impl WasiIo for Pending {
        fn read(&mut self, _: &mut Context<'_>, _: &mut [u8]) -> Poll<Result<usize, WasiIoError>> {
            Poll::Pending
        }
        fn write(
            &mut self,
            _: &mut Context<'_>,
            _: u32,
            _: &[u8],
        ) -> Poll<Result<usize, WasiIoError>> {
            panic!("unexpected write")
        }
    }
    let bytes = wat::parse_str(
        r#"(module
      (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32)(result i32)))
      (memory (export "memory") 1) (data(i32.const 0) "\20\00\00\00\01\00\00\00")
      (func (export "_start") i32.const 0 i32.const 0 i32.const 1 i32.const 16 call $read drop))"#,
    )
    .unwrap();
    let mut invocation = WasiInvocation::new(&bytes, &["test".into()], Default::default()).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(invocation.poll(&mut cx, &mut Pending), Poll::Pending);
    assert_eq!(invocation.poll(&mut cx, &mut Pending), Poll::Pending);
    let consumed = invocation.consumed_fuel();
    for _ in 0..100 {
        assert_eq!(invocation.poll(&mut cx, &mut Pending), Poll::Pending);
    }
    assert_eq!(invocation.consumed_fuel(), consumed);
    invocation.deny();
    assert_eq!(
        invocation.poll(&mut cx, &mut Pending),
        Poll::Ready(WasiTerminal::Denied)
    );
}

#[test]
fn clocks_validate_pointers_and_preserve_full_nanoseconds() {
    struct Clock {
        calls: usize,
        error: Option<WasiClockError>,
    }
    impl WasiIo for Clock {
        fn read(&mut self, _: &mut Context<'_>, _: &mut [u8]) -> Poll<Result<usize, WasiIoError>> {
            unreachable!()
        }
        fn write(
            &mut self,
            _: &mut Context<'_>,
            _: u32,
            _: &[u8],
        ) -> Poll<Result<usize, WasiIoError>> {
            unreachable!()
        }
        fn clock_time(&mut self, id: u32, precision: u64) -> Result<u64, WasiClockError> {
            self.calls += 1;
            assert_eq!(id, 1);
            assert_eq!(precision, u64::MAX);
            self.error.map_or(Ok(0x123456789abcdef0), Err)
        }
        fn clock_resolution(&mut self, id: u32) -> Result<u64, WasiClockError> {
            self.calls += 1;
            assert_eq!(id, 0);
            Ok(100)
        }
    }
    let prefix = r#"(module
        (import "wasi_snapshot_preview1" "clock_time_get" (func $t (param i32 i64 i32) (result i32)))
        (import "wasi_snapshot_preview1" "clock_res_get" (func $r (param i32 i32) (result i32)))
        (memory (export "memory") 1) (func (export "_start") "#;
    for (body, calls, error, expected) in [
        ("i32.const 1 i64.const -1 i32.const 65529 call $t i32.const 21 i32.ne if unreachable end", 0, None, WasiTerminal::Exited(0)),
        ("i32.const 0 i32.const -1 call $r i32.const 21 i32.ne if unreachable end", 0, None, WasiTerminal::Exited(0)),
        ("i32.const 4 i64.const 0 i32.const 0 call $t i32.const 28 i32.ne if unreachable end", 0, None, WasiTerminal::Exited(0)),
        ("i32.const 1 i64.const -1 i32.const 3 call $t if unreachable end i32.const 3 i64.load i64.const 0x123456789abcdef0 i64.ne if unreachable end i32.const 0 i32.const 17 call $r if unreachable end i32.const 17 i64.load i64.const 100 i64.ne if unreachable end", 2, None, WasiTerminal::Exited(0)),
        ("i32.const 1 i64.const -1 i32.const 0 call $t i32.const 52 i32.ne if unreachable end", 1, Some(WasiClockError::Unsupported), WasiTerminal::Exited(0)),
        ("i32.const 1 i64.const -1 i32.const 0 call $t i32.const 29 i32.ne if unreachable end", 1, Some(WasiClockError::Failed), WasiTerminal::Exited(0)),
        ("i32.const 1 i64.const -1 i32.const 0 call $t unreachable", 1, Some(WasiClockError::Denied), WasiTerminal::Denied),
    ] {
        let bytes = wat::parse_str(format!("{prefix}{body}))")).unwrap();
        let mut instance = WasiInvocation::new(&bytes, &["clock.wasm".into()], WasiLimits::default()).unwrap();
        let mut io = Clock { calls: 0, error };
        let mut cx = Context::from_waker(Waker::noop());
        let terminal = loop { if let Poll::Ready(t) = instance.poll(&mut cx, &mut io) { break t; } };
        assert_eq!(terminal, expected);
        assert_eq!(io.calls, calls);
    }
}

#[test]
fn embedding_fuel_budget_has_a_hard_ceiling_and_bounded_quanta() {
    let bytes = wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "_start")))"#)
        .unwrap();
    assert_eq!(WasiLimits::default().total_fuel, 10_000_000);
    for (fuel, quantum, valid) in [
        (100_000_000_000, 10_000, true),
        (100_000_000_001, 10_000, false),
        (100_000_000_000, 10_001, false),
    ] {
        let result = WasiInvocation::new(
            &bytes,
            &["test.wasm".into()],
            WasiLimits {
                total_fuel: fuel,
                poll_quantum: quantum,
                ..Default::default()
            },
        );
        assert_eq!(result.is_ok(), valid);
    }
}

#[test]
fn clocks_are_not_ambient_in_standalone_embeddings() {
    let terminal = run(
        r#"(module
      (import "wasi_snapshot_preview1" "clock_time_get" (func $time (param i32 i64 i32) (result i32)))
      (import "wasi_snapshot_preview1" "clock_res_get" (func $res (param i32 i32) (result i32)))
      (memory (export "memory") 1)
      (func (export "_start")
        i32.const 0 i32.const 0 call $res i32.const 52 i32.ne if unreachable end
        i32.const 1 i64.const 0 i32.const 0 call $time i32.const 52 i32.ne if unreachable end
        i32.const 2 i64.const 0 i32.const 0 call $time i32.const 52 i32.ne if unreachable end
        i32.const 3 i32.const 0 call $res i32.const 52 i32.ne if unreachable end))"#,
        &mut Io::default(),
        WasiLimits::default(),
    );
    assert_eq!(terminal, WasiTerminal::Exited(0));
}

#[test]
fn scalar_memory_helpers_preserve_unaligned_access_and_traps() {
    let value = 0xfedc_ba98_f654_b2f1u64;
    for (width, suffix) in [(1, "8"), (2, "16"), (4, "32"), (8, "")] {
        for signed in [false, true] {
            let extension = if width == 8 {
                ""
            } else if signed {
                "_s"
            } else {
                "_u"
            };
            let shift = 64 - width * 8;
            let expected = if signed {
                (((value << shift) as i64) >> shift) as u64
            } else {
                (value << shift) >> shift
            };
            let function = format!(
                r#"(func $rw (param $p i32) (result i64)
                local.get $p i64.const 0x{value:x} i64.store{suffix} offset=1 align=1
                local.get $p i64.load{suffix}{extension} offset=1 align=1)"#
            );
            for pointer in (0..16).chain([65535 - width, 65536 - width, u32::MAX]) {
                let module = format!(
                    r#"(module (memory (export "memory") 1) {function}
                    (func (export "_start") i32.const {pointer} call $rw
                    i64.const 0x{expected:x} i64.ne if unreachable end))"#
                );
                let expected_terminal = if pointer <= 65535 - width {
                    WasiTerminal::Exited(0)
                } else {
                    WasiTerminal::Trapped
                };
                assert_eq!(
                    run(&module, &mut Io::default(), WasiLimits::default()),
                    expected_terminal,
                    "width={width} signed={signed} pointer={pointer}"
                );
            }
            // Exercise a trapping load independently of the trapping store above.
            let module = format!(
                r#"(module (memory (export "memory") 1)
                (func $read (param i32) (result i64) local.get 0 i64.load{suffix}{extension} offset=1 align=1)
                (func (export "_start") i32.const -1 call $read drop))"#
            );
            assert_eq!(
                run(&module, &mut Io::default(), WasiLimits::default()),
                WasiTerminal::Trapped
            );
        }
    }
}

#[test]
fn fuel_continuation_hint_excludes_host_calls_and_terminal_states() {
    let make = |source: &str| {
        WasiInvocation::new(
            &wat::parse_str(source).unwrap(),
            &["test".into()],
            WasiLimits {
                total_fuel: 1000,
                poll_quantum: 100,
                ..Default::default()
            },
        )
        .unwrap()
    };
    let mut io = Io::default();
    let mut cx = Context::from_waker(Waker::noop());
    let mut looping =
        make(r#"(module (memory (export "memory") 1) (func (export "_start") (loop $l br $l)))"#);
    assert!(!looping.yielded_for_fuel());
    assert!(looping.poll(&mut cx, &mut io).is_pending());
    assert!(looping.yielded_for_fuel());
    looping.cancel();
    assert!(!looping.yielded_for_fuel());
    let mut host = make(
        r#"(module
        (import "wasi_snapshot_preview1" "environ_sizes_get" (func $env (param i32 i32) (result i32)))
        (memory (export "memory") 1)
        (func (export "_start") i32.const 0 i32.const 4 call $env drop))"#,
    );
    assert!(host.poll(&mut cx, &mut io).is_pending());
    assert!(!host.yielded_for_fuel());
    assert_eq!(
        host.poll(&mut cx, &mut io),
        Poll::Ready(WasiTerminal::Exited(0))
    );
    assert!(!host.yielded_for_fuel());
}
