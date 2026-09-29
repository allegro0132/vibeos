//! Target-only qualification of the production Node supervisor's revocation.
use alloc::{sync::Arc, string::String, vec::Vec};
use core::{future::poll_fn, task::Poll};
use crate::{cap::Rights, native_files::FileGrant};
use vibeos_file_store::{FileTreeRoot, FileError, RelPath};
use vibeos_wasi_command::CommandIo;
use vibeos_wasi_runtime::WasiTerminal;

const SCRIPT: &str = r#"
const fs = require('fs');
const p = fs.openSync('data', 'r');
const t = fs.openSync('/.vibeos-tools/data', 'r');
if (fs.readFileSync(p, 'utf8') !== 'project' || fs.readFileSync(t, 'utf8') !== 'tools') throw Error('initial authority');
let denied = false;
try { fs.writeFileSync('/.vibeos-tools/data', 'bad'); } catch(e) { denied = e.code === 'EACCES'; }
if (!denied || fs.readFileSync('/.vibeos-tools/data', 'utf8') !== 'tools') throw Error('readonly authority');
console.log('AUTH_READY');
setTimeout(() => {
  fs.readSync(p, Buffer.alloc(1), 0, 1, 0);
  fs.readSync(t, Buffer.alloc(1), 0, 1, 0);
  fs.writeFileSync('after', 'unauthorized');
  console.log('AUTH_BAD');
}, 60000);
"#;

async fn collect(io: &CommandIo, output: &mut Vec<u8>, ready: bool) -> Option<WasiTerminal> {
    poll_fn(|cx| {
        for pipe in [&io.stdout, &io.stderr] {
            let mut bytes = [0u8; 1024];
            if let Poll::Ready(Ok(n)) = pipe.read(cx, &mut bytes) {
                assert!(output.len() + n <= 8192, "authority probe output overflow");
                output.extend_from_slice(&bytes[..n]);
            }
        }
        if ready && output.windows(10).any(|w| w == b"AUTH_READY") { return Poll::Ready(None); }
        if let Poll::Ready(terminal) = io.poll_terminal(cx) {
            if io.stdout.drained() && io.stderr.drained() { return Poll::Ready(Some(terminal)); }
        }
        Poll::Pending
    }).await
}

pub(super) async fn run() {
    for revoke_project in [true, false] {
        let project = Arc::new(FileTreeRoot::new_empty(0x6175746870726f6a).unwrap());
        let tools = Arc::new(FileTreeRoot::new_empty(0x61757468746f6f6c).unwrap());
        for (root, bytes) in [(&project, b"project".as_slice()), (&tools, b"tools".as_slice())] {
            let mut tx = root.begin().unwrap();
            tx.write_chunks(&RelPath::parse("data").unwrap(), [bytes], false).unwrap();
            tx.commit_authoritative().await.unwrap();
        }
        let space = crate::world::Space::new("node-live-authority");
        let (project_parent, tool_parent, project_cap, tool_cap) = {
            let mut table = space.0.lock();
            let p = table.mint(project.clone(), Rights::ALL);
            let t = table.mint(tools, Rights::ALL);
            let pc = table.derive(p, Rights::READ.union(Rights::WRITE)).unwrap();
            let tc = table.derive(t, Rights::READ).unwrap();
            assert_eq!(table.live_count(), 4);
            (p, t, pc, tc)
        };
        let io = Arc::new(CommandIo::new());
        io.stdin.close();
        crate::native_node::launch(&[String::from("node")], Some(SCRIPT),
            FileGrant::new(space.clone(), project_cap).unwrap(),
            Some(FileGrant::new(space.clone(), tool_cap).unwrap()), io.clone()).unwrap();
        let mut output = Vec::new();
        assert_eq!(collect(&io, &mut output, true).await, None,
                   "Node did not open its files: {}", String::from_utf8_lossy(&output));
        let kind = if revoke_project { "project" } else { "tools" };
        crate::println!("NODE AUTHORITY READY kind={} opened_fds=2 readonly=denied", kind);
        space.0.lock().revoke(if revoke_project { project_parent } else { tool_parent }).unwrap();
        assert_eq!(space.0.lock().live_count(), 2);
        assert_eq!(collect(&io, &mut output, false).await, Some(WasiTerminal::Denied));
        assert!(!output.windows(8).any(|w| w == b"AUTH_BAD"));
        assert_eq!(io.pending_waiters(), 0);
        assert!(matches!(project.snapshot().stat(&RelPath::parse("after").unwrap(), true), Err(FileError::NotFound)));
        space.0.lock().revoke(if revoke_project { tool_parent } else { project_parent }).unwrap();
        assert_eq!(space.0.lock().live_count(), 0);

        // Successful readmission uses a fresh capability, never a revoked one.
        let retry_cap = space.0.lock().mint(project, Rights::ALL);
        let retry = Arc::new(CommandIo::new());
        retry.stdin.close();
        crate::native_node::launch(&[String::from("node")],
            Some("if(require('fs').readFileSync('data','utf8')!=='project')throw Error('restart');console.log('AUTH_RESTART')"),
            FileGrant::new(space.clone(), retry_cap).unwrap(), None, retry.clone()).unwrap();
        let mut restarted = Vec::new();
        assert_eq!(collect(&retry, &mut restarted, false).await, Some(WasiTerminal::Exited(0)));
        assert!(restarted.windows(12).any(|w| w == b"AUTH_RESTART"));
        assert_eq!(retry.pending_waiters(), 0);
        space.0.lock().revoke(retry_cap).unwrap();
        assert_eq!(space.0.lock().live_count(), 0);
        let released = Arc::downgrade(&space);
        drop(space);
        assert_eq!(released.strong_count(), 0, "native supervisor retained fixture CSpace");
        crate::println!("NODE AUTHORITY REVOKE kind={} terminal=Denied caps=0 waiters=0 space_refs=0 restart=1 PASS", kind);
    }
    crate::sbi::shutdown(false);
}
