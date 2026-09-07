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
