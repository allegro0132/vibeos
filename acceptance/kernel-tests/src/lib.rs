//! Guest-kernel acceptance harness and machine-readable benchmark suite.

#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub mod bench;
#[cfg(feature = "milkv-ssh-acceptance")]
pub mod ssh_acceptance_rng;
#[cfg(feature = "ssh-security-test")]
pub mod ssh_security_test;
#[cfg(feature = "ssh-test-fixture")]
pub mod ssh_test_fixture;

pub struct Report {
    pub passed: usize,
    pub failed: usize,
}

#[derive(Default)]
pub struct Harness {
    passed: usize,
    failures: Vec<String>,
}

impl Harness {
    pub fn check(&mut self, name: &str, ok: bool) {
        if ok {
            self.passed += 1
        } else {
            self.failures.push(String::from(name))
        }
    }

    pub fn eq<T: PartialEq + core::fmt::Debug>(&mut self, name: &str, got: T, want: T) {
        if got == want {
            self.passed += 1;
        } else {
            self.failures
                .push(format!("{} (got {:?}, want {:?})", name, got, want));
        }
    }

    pub fn failures(&self) -> &[String] {
        &self.failures
    }

    pub fn report(&self) -> Report {
        Report {
            passed: self.passed,
            failed: self.failures.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Harness;

    #[test]
    fn report_counts_passes_and_preserves_failure_diagnostics() {
        let mut harness = Harness::default();
        harness.check("passes", true);
        harness.check("fails", false);
        harness.eq("mismatch", 1, 2);

        let report = harness.report();
        assert_eq!(report.passed, 1);
        assert_eq!(report.failed, 2);
        assert_eq!(harness.failures()[0], "fails");
        assert_eq!(harness.failures()[1], "mismatch (got 1, want 2)");
    }
}
