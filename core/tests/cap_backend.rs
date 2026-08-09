use std::alloc::{alloc_zeroed, dealloc, handle_alloc_error, Layout};
use std::any::Any;
use std::sync::{Arc, Mutex};

use vibeos_core::cap::{
    CSpace, CapabilityTableBackend, Resource, Rights, CAPABILITY_TABLE_PAGE_SIZE,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BackendEvent {
    Allocate {
        start: usize,
        pages: usize,
    },
    Protect {
        start: usize,
        pages: usize,
        read_only: bool,
    },
    Release {
        start: usize,
        pages: usize,
    },
}

static EVENTS: Mutex<Vec<BackendEvent>> = Mutex::new(Vec::new());

fn page_layout(pages: usize) -> Layout {
    Layout::from_size_align(
        pages.checked_mul(CAPABILITY_TABLE_PAGE_SIZE).unwrap(),
        CAPABILITY_TABLE_PAGE_SIZE,
    )
    .unwrap()
}

fn allocate_pages(pages: usize) -> *mut u8 {
    let layout = page_layout(pages);
    // Safety: the layout is non-zero and valid, and release reconstructs it.
    let allocation = unsafe { alloc_zeroed(layout) };
    if allocation.is_null() {
        handle_alloc_error(layout);
    }
    EVENTS.lock().unwrap().push(BackendEvent::Allocate {
        start: allocation as usize,
        pages,
    });
    allocation
}

fn protect_pages(start: usize, pages: usize, read_only: bool) {
    EVENTS.lock().unwrap().push(BackendEvent::Protect {
        start,
        pages,
        read_only,
    });
}

unsafe fn release_pages(start: usize, pages: usize) {
    EVENTS
        .lock()
        .unwrap()
        .push(BackendEvent::Release { start, pages });
    // Safety: CapTable has already dropped every resident slot, and this exact
    // pointer/layout pair came from allocate_pages.
    unsafe { dealloc(start as *mut u8, page_layout(pages)) };
}

struct Probe;

impl Resource for Probe {
    fn kind(&self) -> &'static str {
        "cap-backend-probe"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[test]
fn cow_backend_seals_before_publish_and_retires_only_after_replacement() {
    // This integration-test binary contains one test, so the process-global
    // backend is installed exactly once before any CSpace mutation.
    vibeos_core::cap::set_capability_table_backend(unsafe {
        CapabilityTableBackend::new(allocate_pages, protect_pages, release_pages)
    });

    let mut cspace = CSpace::new("backend-order");
    let root = cspace.mint(Arc::new(Probe), Rights::ALL);
    let child = cspace
        .derive(root, Rights::READ.union(Rights::REVOKE))
        .unwrap();
    assert_eq!(cspace.revoke(child), Ok(1));
    drop(cspace);

    let events = EVENTS.lock().unwrap().clone();
    assert_eq!(events.len(), 12);

    let BackendEvent::Allocate {
        start: first,
        pages: first_pages,
    } = events[0]
    else {
        panic!("mint did not allocate first")
    };
    let BackendEvent::Allocate {
        start: second,
        pages: second_pages,
    } = events[2]
    else {
        panic!("derive did not allocate its candidate first")
    };
    let BackendEvent::Allocate {
        start: third,
        pages: third_pages,
    } = events[6]
    else {
        panic!("revoke did not allocate its candidate first")
    };
    assert_eq!((first_pages, second_pages, third_pages), (1, 1, 1));
    assert_ne!(first, second, "derive must not overwrite the live table");
    assert_ne!(second, third, "revoke must not overwrite the live table");
    for start in [first, second, third] {
        assert_eq!(start % CAPABILITY_TABLE_PAGE_SIZE, 0);
    }

    assert_eq!(
        events,
        vec![
            BackendEvent::Allocate {
                start: first,
                pages: 1,
            },
            BackendEvent::Protect {
                start: first,
                pages: 1,
                read_only: true,
            },
            BackendEvent::Allocate {
                start: second,
                pages: 1,
            },
            BackendEvent::Protect {
                start: second,
                pages: 1,
                read_only: true,
            },
            BackendEvent::Protect {
                start: first,
                pages: 1,
                read_only: false,
            },
            BackendEvent::Release {
                start: first,
                pages: 1,
            },
            BackendEvent::Allocate {
                start: third,
                pages: 1,
            },
            BackendEvent::Protect {
                start: third,
                pages: 1,
                read_only: true,
            },
            BackendEvent::Protect {
                start: second,
                pages: 1,
                read_only: false,
            },
            BackendEvent::Release {
                start: second,
                pages: 1,
            },
            BackendEvent::Protect {
                start: third,
                pages: 1,
                read_only: false,
            },
            BackendEvent::Release {
                start: third,
                pages: 1,
            },
        ]
    );
}
