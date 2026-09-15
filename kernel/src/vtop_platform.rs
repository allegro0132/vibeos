//! Real resource snapshots and transport-scoped service control for vtop.
use alloc::{string::String, vec::Vec};
use vibeos_core::{
    arch, exec, ipi,
    runqueue::{HartId, MAX_HARTS},
};
use vibeos_vsh::vtop::{Backend, Control, Cpu, Request, Service, Snapshot};

pub struct Monitor {
    remote: bool,
}
impl Monitor {
    pub fn local() -> Self {
        Self { remote: false }
    }
    pub fn remote() -> Self {
        Self { remote: true }
    }

    fn protection(&self, name: &str, restartable: bool) -> Option<&'static str> {
        if matches!(name, "shell" | "vsh") {
            return Some("protected: active system console");
        }
        // Remote operators retain their control path. Dependency shutdown is
        // available through the physical console when explicitly intended.
        if self.remote && (name.contains("ssh") || name.contains("net") || name.contains("rng")) {
            return Some("protected: SSH transport dependency; use the local console");
        }
        if !restartable {
            return Some("read-only: no audited restart template");
        }
        None
    }
}

impl Backend for Monitor {
    fn snapshot(&self) -> Snapshot {
        let heap = crate::HEAP.snapshot();
        let cpus: Vec<_> = exec::idle_profile()
            .into_iter()
            .enumerate()
            .filter_map(|(index, sample)| {
                let sample = sample.filter(|s| s.active)?;
                Some(Cpu {
                    index,
                    since: sample.since,
                    now: sample.now,
                    idle: sample.idle,
                })
            })
            .collect();
        let online_cpus = (0..MAX_HARTS)
            .filter(|index| ipi::is_online(HartId::new(*index).unwrap()))
            .count();
        let services = crate::world::world()
            .components()
            .into_iter()
            .filter_map(|component| {
                let s = component.try_snapshot()?;
                let protected = self.protection(&s.name, component.is_restartable());
                Some(Service {
                    name: s.name,
                    generation: s.generation,
                    task: s.task_id,
                    state: s.state,
                    polls: s.polls,
                    poll_ticks: s.poll_ticks,
                    live: s.memory.live_bytes,
                    peak: s.memory.peak_bytes,
                    budget: s.memory.budget_bytes,
                    denials: s.memory.denials,
                    protected,
                })
            })
            .collect();
        Snapshot {
            board: String::from(crate::platform::name()),
            now: arch::time(),
            timebase_hz: exec::timebase_hz(),
            cpus,
            online_cpus,
            heap_live: heap.live_bytes,
            heap_peak: heap.peak_live_bytes,
            heap_total: heap
                .bump_used_bytes
                .saturating_add(heap.bump_remaining_bytes),
            heap_untouched: heap.bump_remaining_bytes,
            tasks: exec::task_report().len(),
            services,
        }
    }

    fn control(&self, request: &Request) -> Result<Control, &'static str> {
        let world = crate::world::world();
        let component = world
            .component_named(&request.name)
            .ok_or("service no longer exists")?;
        if let Some(reason) = self.protection(&request.name, component.is_restartable()) {
            return Err(reason);
        }
        world.control_component(request)
    }
}
