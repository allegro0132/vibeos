//! SDHCI-specific CMD18/CMD25 fallback and verified blind-PIO probing.
//! Capability admission and partition translation remain in the caller.
extern crate alloc;
use crate::{
    Card as HardwareCard, Error as HardwareError, MultiBlockWriteMode, MAX_TRANSFER_BLOCKS,
    SAFE_BLIND_WRITE_BLOCKS,
};
use alloc::vec;
/// Issue one logical batched write as one or more hardware transfers: the
/// blind PIO mode is split into [`SAFE_BLIND_WRITE_BLOCKS`]-sized CMD25
/// bursts (the always-safe, FIFO-verified size used while probing). The
/// publication hook still fires exactly once, before the first published
/// transfer.
fn write_batch_in_mode<H: FnOnce()>(
    hardware: &mut HardwareCard,
    physical_first: u64,
    data: &[u8],
    mode: MultiBlockWriteMode,
    hook: &mut Option<H>,
) -> Result<(), HardwareError> {
    let chunk_bytes = if mode == MultiBlockWriteMode::BlindPio {
        SAFE_BLIND_WRITE_BLOCKS as usize * 512
    } else {
        data.len()
    };
    let mut sector = physical_first;
    for chunk in data.chunks(chunk_bytes) {
        hardware.write_blocks_tracked_with_mode(sector, chunk, mode, || {
            if let Some(hook) = hook.take() {
                hook();
            }
        })?;
        sector += (chunk.len() / 512) as u64;
    }
    Ok(())
}

pub struct AdaptiveCard {
    hardware: HardwareCard,
    capacity_sectors: u64,
    log: fn(core::fmt::Arguments<'_>),
    verify_writes: bool,
    /// Set after the first CMD18 failure of this incarnation: the rest of the
    /// session decomposes batched reads into the single-sector command this
    /// exact board has already proven, instead of paying a full poll-budget
    /// timeout on every subsequent batch.
    multiblock_reads_disabled: bool,
    write_batching: WriteBatching,
    /// Consecutive locked-mode batched-write failures; the lock survives
    /// transient card stalls and is only abandoned after several in a row.
    locked_write_failures: u8,
    /// Blind CMD25 burst size currently attempted. SD cards handle one long
    /// sequential burst far better than the same bytes as 4 KiB commands, so
    /// this starts at the full transfer bound and shrinks on evidence.
    blind_chunk_blocks: u32,
    /// Largest blind burst size proven by read-back this session. A burst
    /// larger than this is verified after it completes before the size is
    /// trusted, because a FIFO overflow would corrupt data silently.
    qualified_blind_blocks: u32,
}

/// Session-sticky CMD25 protocol probe state. The CV1800B integration has
/// rejected the standard Auto CMD12 shape on real hardware, so the first
/// batched write walks a ladder of protocol variants, locks onto the first
/// one the controller completes, and otherwise decomposes every later batch
/// into proven single-sector CMD24 writes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WriteBatching {
    Unprobed,
    Locked(MultiBlockWriteMode),
    Disabled,
}

/// (apply write-stall workarounds first, protocol shape) probe ladder.
///
/// `BlindPio` under the host write-stall workarounds is the only shape the
/// CV1800B has ever completed on real hardware, so it leads the ladder: the
/// workarounds are applied up front and the proven mode is tried first, which
/// keeps a healthy session from spending four full data-transfer timeouts
/// rediscovering it on every first batched write. The remaining standard
/// shapes stay as ordered fallbacks in case a different card or a firmware
/// revision ever accepts one of them.
const WRITE_MODE_LADDER: [(bool, MultiBlockWriteMode); 5] = [
    (true, MultiBlockWriteMode::BlindPio),
    (true, MultiBlockWriteMode::AutoCmd12),
    (true, MultiBlockWriteMode::ManualCmd12),
    (true, MultiBlockWriteMode::OpenEnded),
    (true, MultiBlockWriteMode::SetBlockCount),
];

impl AdaptiveCard {
    pub fn new(hardware: HardwareCard, log: fn(core::fmt::Arguments<'_>)) -> Self {
        Self {
            capacity_sectors: hardware.info().capacity_sectors,
            hardware,
            log,
            verify_writes: true,
            multiblock_reads_disabled: false,
            write_batching: WriteBatching::Unprobed,
            locked_write_failures: 0,
            blind_chunk_blocks: MAX_TRANSFER_BLOCKS,
            qualified_blind_blocks: SAFE_BLIND_WRITE_BLOCKS,
        }
    }
    pub fn hardware(&self) -> &HardwareCard {
        &self.hardware
    }
    pub fn hardware_mut(&mut self) -> &mut HardwareCard {
        &mut self.hardware
    }
    pub fn set_write_readback(&mut self, enabled: bool) {
        self.verify_writes = enabled;
    }
    fn physical_sector(&self, sector: u64) -> Result<u64, HardwareError> {
        if sector < self.capacity_sectors {
            Ok(sector)
        } else {
            Err(HardwareError::OutOfRange)
        }
    }
    fn physical_block_range(&self, first: u64, bytes: usize) -> Result<u64, HardwareError> {
        crate::validate_block_range(self.capacity_sectors, first, bytes)?;
        Ok(first)
    }
    pub fn read_blocks(
        &mut self,
        logical_first: u64,
        output: &mut [u8],
    ) -> Result<(), HardwareError> {
        let physical_first = self.physical_block_range(logical_first, output.len())?;
        let block_count = (output.len() / 512) as u64;
        if block_count > 1 && !self.multiblock_reads_disabled {
            match self.hardware.read_blocks(physical_first, output) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    // The failed transfer was aborted by the driver; retry the
                    // request with the single-sector command this board has
                    // already proven before reporting anything upward.
                    self.multiblock_reads_disabled = true;
                    (self.log)(format_args!(
                        "  sdhci: CMD18 x{block_count} failed ({error:?}); single-sector reads for this session\n"
                    ));
                }
            }
        }
        for (index, sector) in output.chunks_exact_mut(512).enumerate() {
            sector.copy_from_slice(&self.hardware.read_sector(physical_first + index as u64)?);
        }
        Ok(())
    }

    pub fn write_blocks_tracked(
        &mut self,
        logical_first: u64,
        data: &[u8],
        on_command_published: impl FnOnce(),
    ) -> Result<(), HardwareError> {
        let physical_first = self.physical_block_range(logical_first, data.len())?;
        let block_count = (data.len() / 512) as u64;
        // The publication hook must fire exactly once even when a batched
        // attempt already published CMD25 before failing: the mutation was
        // submitted to the card either way.
        let mut hook = Some(on_command_published);
        if let WriteBatching::Locked(mode) = self.write_batching {
            if block_count > 1 {
                // A transient failure (for example a long card-internal
                // garbage-collection stall) must not permanently give up the
                // locked mode: retry once, fall back to single-sector for
                // just this request, and disable only on repeated failures.
                for attempt in 1..=2u32 {
                    let result = if mode == MultiBlockWriteMode::BlindPio {
                        self.write_blind(logical_first, physical_first, data, &mut hook)
                    } else {
                        write_batch_in_mode(
                            &mut self.hardware,
                            physical_first,
                            data,
                            mode,
                            &mut hook,
                        )
                    };
                    match result {
                        Ok(()) => {
                            self.locked_write_failures = 0;
                            return Ok(());
                        }
                        Err(error) => {
                            (self.log)(format_args!(
                                "  sdhci: locked CMD25 x{block_count} via {mode:?} failed ({error:?}), attempt {attempt}\n"
                            ));
                        }
                    }
                }
                self.locked_write_failures = self.locked_write_failures.saturating_add(1);
                if self.locked_write_failures >= 3 {
                    self.write_batching = WriteBatching::Disabled;
                    (self.log)(format_args!(
                        "  sdhci: repeated locked-mode failures; single-sector writes for this session\n"
                    ));
                }
            }
        } else if block_count > 1 && self.write_batching == WriteBatching::Unprobed {
            let probing = true;
            {
                let state = self.hardware.diagnostic_host_state();
                (self.log)(format_args!(
                    "  sdhci host state: hc1 {:#04x}, blkgap {:#04x}, hc2 {:#06x}, mshc {:#010x}, txrx {:#010x}, phycfg {:#010x}\n",
                    state[0], state[1], state[2], state[3], state[4], state[5]
                ));
            }
            let mut workarounds_applied = false;
            for &(needs_workarounds, mode) in &WRITE_MODE_LADDER {
                if needs_workarounds && !workarounds_applied {
                    workarounds_applied = true;
                    self.hardware.apply_write_stall_workarounds();
                    (self.log)(format_args!(
                        "  sdhci: applied write-stall workarounds (block-gap clear, clock-gate disable)\n"
                    ));
                }
                let attempt =
                    write_batch_in_mode(&mut self.hardware, physical_first, data, mode, &mut hook);
                match attempt {
                    Ok(()) => {
                        if probing && !self.verify_written(logical_first, data) {
                            (self.log)(format_args!(
                                "  sdhci: CMD25 x{block_count} via {mode:?} completed but read-back mismatched; rejecting the mode\n"
                            ));
                            continue;
                        }
                        if self.write_batching != WriteBatching::Locked(mode) {
                            self.write_batching = WriteBatching::Locked(mode);
                            (self.log)(format_args!(
                                "  sdhci: CMD25 x{block_count} ok via {mode:?}; batched writes locked to it\n"
                            ));
                        }
                        return Ok(());
                    }
                    Err(error) => {
                        let interrupt_status = self.hardware.last_interrupt_status();
                        let response = self.hardware.response_word();
                        let present = self.hardware.present_state();
                        (self.log)(format_args!(
                            "  sdhci: CMD25 x{block_count} via {mode:?} failed ({error:?}, int {interrupt_status:#010x}, r1 {response:#010x}, present {present:#010x})\n"
                        ));
                    }
                }
            }
            // Last probe stage: the 1-bit bus is a corner no vendor software
            // exercises for CMD25; try the standard 4-bit width once.
            if probing {
                match self.hardware.enable_four_bit_bus() {
                    Ok(()) => {
                        (self.log)(format_args!(
                            "  sdhci: switched to 4-bit bus; retrying CMD25\n"
                        ));
                        for mode in [
                            MultiBlockWriteMode::AutoCmd12,
                            MultiBlockWriteMode::OpenEnded,
                            MultiBlockWriteMode::BlindPio,
                        ] {
                            let attempt = write_batch_in_mode(
                                &mut self.hardware,
                                physical_first,
                                data,
                                mode,
                                &mut hook,
                            );
                            match attempt {
                                Ok(()) => {
                                    if !self.verify_written(logical_first, data) {
                                        (self.log)(format_args!(
                                            "  sdhci: 4-bit CMD25 x{block_count} via {mode:?} completed but read-back mismatched; rejecting the mode\n"
                                        ));
                                        continue;
                                    }
                                    self.write_batching = WriteBatching::Locked(mode);
                                    (self.log)(format_args!(
                                        "  sdhci: CMD25 x{block_count} ok via {mode:?} on the 4-bit bus; batched writes locked to it\n"
                                    ));
                                    return Ok(());
                                }
                                Err(error) => {
                                    let response = self.hardware.response_word();
                                    let present = self.hardware.present_state();
                                    (self.log)(format_args!(
                                        "  sdhci: 4-bit CMD25 x{block_count} via {mode:?} failed ({error:?}, r1 {response:#010x}, present {present:#010x})\n"
                                    ));
                                }
                            }
                        }
                        self.hardware.disable_four_bit_bus();
                        (self.log)(format_args!("  sdhci: returned to the 1-bit bus\n"));
                    }
                    Err(error) => {
                        (self.log)(format_args!(
                            "  sdhci: 4-bit bus switch failed ({error:?}); staying on 1-bit\n"
                        ));
                    }
                }
            }
            if self.write_batching != WriteBatching::Disabled {
                self.write_batching = WriteBatching::Disabled;
                (self.log)(format_args!(
                    "  sdhci: single-sector writes for this session\n"
                ));
            }
        }
        for (index, sector) in data.chunks_exact(512).enumerate() {
            let mut block = [0u8; 512];
            block.copy_from_slice(sector);
            self.hardware
                .write_sector_tracked(physical_first + index as u64, &block, || {
                    if let Some(hook) = hook.take() {
                        hook();
                    }
                })?;
        }
        Ok(())
    }

    /// Batched write through blind CMD25 bursts with adaptive sizing: bursts
    /// larger than the qualified size are read back and compared before the
    /// size is trusted, any mismatch or hardware error shrinks the burst
    /// (floor [`SAFE_BLIND_WRITE_BLOCKS`], which is always safe) and rewrites
    /// the same chunk, so no corruption can persist and no failure at the
    /// floor size is masked.
    fn write_blind(
        &mut self,
        logical_first: u64,
        physical_first: u64,
        data: &[u8],
        hook: &mut Option<impl FnOnce()>,
    ) -> Result<(), HardwareError> {
        let mut offset = 0usize;
        while offset < data.len() {
            let chunk_bytes = (self.blind_chunk_blocks as usize * 512).min(data.len() - offset);
            let chunk = &data[offset..offset + chunk_bytes];
            let attempt = self.hardware.write_blocks_tracked_with_mode(
                physical_first + (offset / 512) as u64,
                chunk,
                MultiBlockWriteMode::BlindPio,
                || {
                    if let Some(hook) = hook.take() {
                        hook();
                    }
                },
            );
            match attempt {
                Ok(()) => {
                    let blocks = (chunk.len() / 512) as u32;
                    if blocks > self.qualified_blind_blocks {
                        if !self.verify_writes {
                            // Read-back disabled by the operator: trust the
                            // burst at this size without reading it back. Trades
                            // the silent-corruption guard for roughly half the
                            // write I/O.
                            self.qualified_blind_blocks = blocks;
                        } else if self.verify_written(logical_first + (offset / 512) as u64, chunk)
                        {
                            self.qualified_blind_blocks = blocks;
                            (self.log)(format_args!(
                                "  sdhci: blind CMD25 burst x{blocks} qualified by read-back\n"
                            ));
                        } else {
                            let reduced = (blocks / 2).max(SAFE_BLIND_WRITE_BLOCKS);
                            (self.log)(format_args!(
                                "  sdhci: blind CMD25 burst x{blocks} read-back mismatched; shrinking to x{reduced}\n"
                            ));
                            self.blind_chunk_blocks = reduced;
                            continue;
                        }
                    }
                    offset += chunk.len();
                }
                Err(error) if self.blind_chunk_blocks > SAFE_BLIND_WRITE_BLOCKS => {
                    let reduced = (self.blind_chunk_blocks / 2).max(SAFE_BLIND_WRITE_BLOCKS);
                    (self.log)(format_args!(
                        "  sdhci: blind CMD25 burst x{} failed ({error:?}); shrinking to x{reduced}\n",
                        self.blind_chunk_blocks
                    ));
                    self.blind_chunk_blocks = reduced;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Read the just-written range back through the proven read path and
    /// compare, before a freshly probed write mode is allowed to carry real
    /// storage traffic.
    fn verify_written(&mut self, logical_first: u64, data: &[u8]) -> bool {
        let mut readback = vec![0u8; data.len()];
        match self.read_blocks(logical_first, &mut readback) {
            Ok(()) => readback == data,
            Err(_) => false,
        }
    }

    pub fn read_sector(&mut self, logical_sector: u64) -> Result<[u8; 512], HardwareError> {
        let physical_sector = self.physical_sector(logical_sector)?;
        self.hardware.read_sector(physical_sector)
    }

    pub fn write_sector_tracked(
        &mut self,
        logical_sector: u64,
        data: &[u8; 512],
        on_command_published: impl FnOnce(),
    ) -> Result<(), HardwareError> {
        let physical_sector = self.physical_sector(logical_sector)?;
        self.hardware
            .write_sector_tracked(physical_sector, data, on_command_published)
    }

    pub fn flush_tracked(
        &mut self,
        on_command_published: impl FnOnce(),
    ) -> Result<(), HardwareError> {
        self.hardware.flush_tracked(on_command_published)
    }
}
