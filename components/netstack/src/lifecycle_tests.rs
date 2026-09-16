use super::*;
use alloc::vec;
use vibeos_core::{
    cap::{CSpace, Rights},
    chan::Endpoint,
    heap::{AllocationDomain, ArenaId, OwnerId},
    net::StampedPacket,
    sync::TaskRecoveryKey,
};
use vibeos_net_api::{receive_ownership::Owner, receive_storage::Storage, TcpListenerId};

struct TestPlatform {
    info: NetworkInfo,
    busy: bool,
}
impl Platform for TestPlatform {
    fn packet_endpoints(&self, _: Cap, _: Cap) -> Option<PacketEndpoints> {
        None
    }
    fn bind_stack(&self, _: Cap) -> Result<PacketStamp, NetworkBindError> {
        if self.busy {
            Err(NetworkBindError::SessionBusy)
        } else {
            Ok(PacketStamp::new(self.info.session_epoch, 1).unwrap())
        }
    }
    fn network_info(&self, _: Cap) -> Option<NetworkInfo> {
        Some(self.info)
    }
    fn tcp_listener(&self, _: Cap) -> Option<Revocable<TcpListener>> {
        None
    }
}

#[test]
fn epoch_rebuild_releases_old_writers_even_when_replacement_fails() {
    let owner = Owner {
        domain: AllocationDomain::new(OwnerId::new(111), ArenaId::new(111)),
        task: TaskRecoveryKey::new(111).unwrap(),
    };
    // Independent interfaces avoid sharing configuration with other fixtures.
    for (case, busy, invalid) in [(0, true, false), (1, false, true), (2, false, false)] {
        let interface = NetworkInterfaceId::new(40 + case);
        assert!(config::register_interface(interface, true));
        let pool = Storage::<3>::new_static(4096, 8192).unwrap();
        let frontend = TcpListener::new_with_receive_storage(
            "epoch",
            TcpListenerId::new(111 + u64::from(case)).unwrap(),
            9000,
            8192,
            4096,
            pool,
        )
        .unwrap();
        let mut caps = CSpace::new("epoch-fixture");
        let inbound = Endpoint::<StampedPacket>::new("epoch-in", 8);
        let outbound = Endpoint::<StampedPacket>::new("epoch-out", 8);
        let in_cap = caps.mint(inbound, Rights::ALL_VOLATILE);
        let out_cap = caps.mint(outbound, Rights::ALL_VOLATILE);
        let listener_cap = caps.mint(frontend.clone(), Rights::ALL_VOLATILE);
        // Replacement remains copied in this non-executor fixture. Producer
        // identity setup is exercised in the real task/image path separately.
        let replacement = TcpListener::new("replacement", TcpListenerId::new(211 + u64::from(case)).unwrap(), 9000, 8192, 4096).unwrap();
        let replacement_cap = caps.mint(replacement, Rights::ALL_VOLATILE);
        let replacement = caps.lookup_revocable::<TcpListener>(replacement_cap, Rights::RECV).unwrap();
        let input = caps
            .lookup_revocable::<Endpoint<StampedPacket>>(in_cap, Rights::RECV)
            .unwrap();
        let output = caps
            .lookup_revocable::<Endpoint<StampedPacket>>(out_cap, Rights::SEND)
            .unwrap();
        let listener = caps
            .lookup_revocable::<TcpListener>(listener_cap, Rights::RECV)
            .unwrap();
        let mac = [2, 0, 0, 0, 0, 1];
        let mut core = SharedIpv4TcpStack::new(
            Ipv4StackConfig::new(mac, [192, 0, 2, 1], 24, 111),
            PacketStamp::new(1, 1).unwrap(),
            input.clone(),
            output.clone(),
        )
        .unwrap();
        let socket = core.add_tcp_listener(9000).unwrap();
        unsafe {
            core.enable_receive_exchange(socket, frontend, owner)
                .unwrap();
        }
        let mut task = InterfaceTask {
            interface,
            outbound: output.into(),
            inbound: input.into(),
            control: in_cap,
            listeners: vec![replacement],
            observed_epoch: Some(1),
            observed_ethernet_address: Some(mac),
            observed_config_revision: 123,
            stack: Some(BoundStack {
                core,
                listeners: vec![BoundListener {
                    frontend: listener,
                    socket,
                }],
            }),
            retired: false,
        };
        let platform = TestPlatform {
            busy,
            info: NetworkInfo {
                online: true,
                quarantined: false,
                session_epoch: 2,
                phy_link_up: true,
                ethernet_address: if invalid { [0xff; 6] } else { mac },
                tx_checksum_offload: false,
                rx_checksum_offload: false,
            },
        };
        let result = task.poll(&platform, 1);
        if busy {
            assert!(result.is_ok());
            assert!(task.stack.is_some());
            assert_eq!(task.observed_epoch, Some(1));
            let spare = pool.reserve(owner).unwrap();
            assert!(
                pool.reserve(owner).is_err(),
                "old stack still holds two writers during bind retry"
            );
            unsafe {
                pool.release_writer(spare, owner).unwrap();
            }
        } else {
            assert_eq!(result.is_err(), invalid);
            assert_eq!(task.stack.is_none(), invalid);
            assert_eq!(task.observed_epoch, if invalid { None } else { Some(2) });
            if invalid {
                assert_eq!(task.observed_ethernet_address, None);
                assert_eq!(task.observed_config_revision, 0);
            }
            // The actual poll path ended every old socket reference before
            // replacement success/failure. All three old pool slots are free.
            let tickets = [
                pool.reserve(owner).unwrap(),
                pool.reserve(owner).unwrap(),
                pool.reserve(owner).unwrap(),
            ];
            for ticket in tickets {
                unsafe {
                    pool.release_writer(ticket, owner).unwrap();
                }
            }
        }
        drop(task);
        assert_eq!(unsafe { pool.retire_stopped_owner(owner) }, 0);
    }
}
