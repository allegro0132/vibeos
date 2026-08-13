//! Capability-scoped `lsblk` over bindings already present in this session.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use vibeos_core::cap::{BlockRangeState, Rights};

use crate::{
    BoundResourcePlan, CapabilityCommandContext, CapabilityCommandFuture, ExpandedArgument,
    PlannerError, ResolvedArgument, Span, Status,
};

const DEFAULT_COLUMNS: &[&str] = &["NAME", "SIZE", "RO", "TYPE"];
const VALID_COLUMNS: &[&str] = &[
    "NAME", "SIZE", "RO", "TYPE", "START", "LOG-SEC", "PHY-SEC", "STATE",
];

fn planner_error(span: Span, message: &'static str) -> PlannerError {
    PlannerError { span, message }
}

pub fn lsblk_planner(args: &[ExpandedArgument]) -> Result<BoundResourcePlan, PlannerError> {
    let mut explicit_arguments = Vec::new();
    let mut need_columns = false;
    let mut options = true;
    for (index, argument) in args.iter().enumerate() {
        match argument {
            ExpandedArgument::CapabilityPath { tail, span, .. } => {
                if !tail.is_empty() {
                    return Err(planner_error(*span, "lsblk range operand must be @NAME"));
                }
                explicit_arguments.push(index);
            }
            ExpandedArgument::Value { value, span } => {
                if need_columns {
                    validate_columns(value, *span)?;
                    need_columns = false;
                    continue;
                }
                if options && value == "--" {
                    options = false;
                } else if options && value == "-o" {
                    need_columns = true;
                } else if options && value.starts_with("-o") && value.len() > 2 {
                    validate_columns(&value[2..], *span)?;
                } else if options
                    && value.starts_with('-')
                    && value.len() > 1
                    && value[1..].chars().all(|flag| "blnJ".contains(flag))
                {
                } else {
                    return Err(planner_error(*span, "unsupported lsblk argument"));
                }
            }
        }
    }
    if need_columns {
        return Err(planner_error(
            args.last()
                .map(ExpandedArgument::span)
                .unwrap_or(Span { start: 0, end: 0 }),
            "lsblk -o requires a column list",
        ));
    }
    Ok(BoundResourcePlan {
        kind: "block-range",
        rights: Rights::READ,
        enumerate_if_empty: explicit_arguments.is_empty(),
        explicit_arguments,
    })
}

fn validate_columns(value: &str, span: Span) -> Result<(), PlannerError> {
    if value.is_empty()
        || value
            .split(',')
            .any(|column| !VALID_COLUMNS.contains(&column))
    {
        Err(planner_error(span, "unsupported lsblk column"))
    } else {
        Ok(())
    }
}

fn parse_columns(values: &[&str]) -> Vec<&'static str> {
    let mut index = 0usize;
    while index < values.len() {
        if values[index] == "-o" {
            if let Some(columns) = values.get(index + 1) {
                return columns
                    .split(',')
                    .filter_map(|column| VALID_COLUMNS.iter().copied().find(|item| *item == column))
                    .collect();
            }
        } else if let Some(columns) = values[index].strip_prefix("-o") {
            if !columns.is_empty() {
                return columns
                    .split(',')
                    .filter_map(|column| VALID_COLUMNS.iter().copied().find(|item| *item == column))
                    .collect();
            }
        }
        index += 1;
    }
    DEFAULT_COLUMNS.to_vec()
}

fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "K", "M", "G", "T", "P", "E"];
    let mut unit = 0usize;
    let mut divisor = 1u64;
    while unit + 1 < UNITS.len() && bytes / divisor >= 1024 {
        divisor = divisor.saturating_mul(1024);
        unit += 1;
    }
    if unit == 0 || bytes % divisor == 0 {
        format!("{}{}", bytes / divisor, UNITS[unit])
    } else {
        let tenths = bytes.saturating_mul(10) / divisor;
        format!("{}.{}{}", tenths / 10, tenths % 10, UNITS[unit])
    }
}

fn state_name(state: BlockRangeState) -> &'static str {
    match state {
        BlockRangeState::Online => "online",
        BlockRangeState::Offline => "offline",
        BlockRangeState::Quarantined => "quarantined",
    }
}

fn json_escape(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            character => output.push(character),
        }
    }
    output
}

fn lsblk_command(ctx: CapabilityCommandContext) -> CapabilityCommandFuture {
    Box::pin(async move {
        let values: Vec<&str> = ctx
            .args
            .iter()
            .filter_map(|argument| match argument {
                ResolvedArgument::Value(value) => Some(value.as_str()),
                _ => None,
            })
            .collect();
        let columns = parse_columns(&values);
        let bytes = values
            .iter()
            .any(|value| value.starts_with('-') && value.contains('b'));
        let no_headings = values
            .iter()
            .any(|value| value.starts_with('-') && value.contains('n'));
        let json = values
            .iter()
            .any(|value| value.starts_with('-') && value.contains('J'));
        let mut rows = Vec::new();
        for argument in &ctx.args {
            let ResolvedArgument::CapabilityBinding {
                resource,
                label,
                writable,
            } = argument
            else {
                continue;
            };
            let info = ctx.block_range_info(*resource)?;
            let size = info
                .block_count
                .checked_mul(u64::from(info.logical_sector_size))
                .ok_or(Status::BudgetExceeded)?;
            let read_only = info.device_read_only || !*writable;
            let mut row = Vec::new();
            for column in &columns {
                row.push(match *column {
                    "NAME" => label.clone(),
                    "SIZE" if bytes => size.to_string(),
                    "SIZE" => human_size(size),
                    "RO" => u8::from(read_only).to_string(),
                    "TYPE" => "range".to_string(),
                    "START" => info.start_block.to_string(),
                    "LOG-SEC" => info.logical_sector_size.to_string(),
                    "PHY-SEC" => info.physical_sector_size.to_string(),
                    "STATE" => state_name(info.state).to_string(),
                    _ => return Err(Status::Faulted),
                });
            }
            rows.push(row);
        }
        if json {
            let mut output = String::from("{\"blockdevices\":[");
            for (row_index, row) in rows.iter().enumerate() {
                if row_index != 0 {
                    output.push(',');
                }
                output.push('{');
                for (column_index, (column, value)) in columns.iter().zip(row).enumerate() {
                    if column_index != 0 {
                        output.push(',');
                    }
                    output.push_str(&format!(
                        "\"{}\":\"{}\"",
                        column.to_ascii_lowercase(),
                        json_escape(value)
                    ));
                }
                output.push('}');
            }
            output.push_str("]}\n");
            return Ok(output);
        }
        let mut output = String::new();
        if !no_headings {
            output.push_str(&columns.join(" "));
            output.push('\n');
        }
        for row in rows {
            output.push_str(&row.join(" "));
            output.push('\n');
        }
        Ok(output)
    })
}

pub fn install_lsblk_command(session: &mut crate::Session) {
    session.install_bound_resource_command("lsblk", 0, 128, lsblk_planner, lsblk_command);
}
