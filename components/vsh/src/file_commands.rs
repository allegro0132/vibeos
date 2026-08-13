//! Linux-shaped applets over explicitly admitted `FileTreeRoot` operands.

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use vibeos_core::cap::Rights;
use vibeos_file_store::{FileError, FileTreeRoot, FileType, RelPath};

use crate::{
    CapabilityCommandContext, CapabilityCommandFuture, CapabilityCommandSpec, ExpandedArgument,
    PathRequirement, PlannerError, ResolvedArgument, Span, Status, StreamMode,
};

fn usage(span: Span, message: &'static str) -> PlannerError {
    PlannerError { span, message }
}

fn path_indices(args: &[ExpandedArgument]) -> impl Iterator<Item = usize> + '_ {
    args.iter()
        .enumerate()
        .filter_map(|(i, arg)| arg.path().map(|_| i))
}

fn require_paths_with_options(
    args: &[ExpandedArgument],
    rights: Rights,
    long: &[&str],
    short: &str,
) -> Result<Vec<PathRequirement>, PlannerError> {
    let mut options = true;
    let mut out = Vec::new();
    for (index, arg) in args.iter().enumerate() {
        if let Some(value) = arg.value() {
            if options && value == "--" {
                options = false;
                continue;
            }
            if options && value.starts_with("--") && long.contains(&value) {
                continue;
            }
            if options
                && value.starts_with('-')
                && value.len() > 1
                && value[1..].chars().all(|flag| short.contains(flag))
            {
                continue;
            }
            if options && value.starts_with('-') {
                return Err(usage(arg.span(), "unsupported command option"));
            }
            return Err(usage(
                arg.span(),
                "bare paths are not allowed; use @ROOT/path",
            ));
        }
        out.push(PathRequirement {
            argument: index,
            rights,
        });
    }
    if out.is_empty() {
        return Err(usage(
            args.first()
                .map(ExpandedArgument::span)
                .unwrap_or(Span { start: 0, end: 0 }),
            "at least one capability path is required",
        ));
    }
    Ok(out)
}

pub fn read_paths_planner(args: &[ExpandedArgument]) -> Result<Vec<PathRequirement>, PlannerError> {
    require_paths_with_options(args, Rights::READ, &[], "1aAldRhHL")
}

pub fn cat_paths_planner(args: &[ExpandedArgument]) -> Result<Vec<PathRequirement>, PlannerError> {
    require_paths_with_options(args, Rights::READ, &[], "")
}

pub fn stat_paths_planner(args: &[ExpandedArgument]) -> Result<Vec<PathRequirement>, PlannerError> {
    let mut requirements = Vec::new();
    let mut need_format = false;
    let mut options = true;
    for (argument, arg) in args.iter().enumerate() {
        if let Some(value) = arg.value() {
            if need_format {
                need_format = false;
                continue;
            }
            if options && value == "--" {
                options = false;
                continue;
            }
            if options && value == "-L" {
                continue;
            }
            if options && value == "-c" {
                need_format = true;
                continue;
            }
            if options && value.starts_with("-c") && value.len() > 2 {
                continue;
            }
            return Err(usage(
                arg.span(),
                if value.starts_with('-') {
                    "unsupported stat option"
                } else {
                    "bare paths are not allowed; use @ROOT/path"
                },
            ));
        }
        requirements.push(PathRequirement {
            argument,
            rights: Rights::READ,
        });
    }
    if need_format {
        return Err(usage(
            args.last()
                .map(ExpandedArgument::span)
                .unwrap_or(Span { start: 0, end: 0 }),
            "stat -c requires a format",
        ));
    }
    if requirements.is_empty() {
        return Err(usage(
            Span { start: 0, end: 0 },
            "stat requires a capability path",
        ));
    }
    Ok(requirements)
}

pub fn readlink_paths_planner(
    args: &[ExpandedArgument],
) -> Result<Vec<PathRequirement>, PlannerError> {
    require_paths_with_options(args, Rights::READ, &[], "f")
}

pub fn mkdir_paths_planner(
    args: &[ExpandedArgument],
) -> Result<Vec<PathRequirement>, PlannerError> {
    require_paths_with_options(args, Rights::WRITE, &[], "p")
}

pub fn rm_paths_planner(args: &[ExpandedArgument]) -> Result<Vec<PathRequirement>, PlannerError> {
    require_paths_with_options(args, Rights::WRITE, &[], "fdrR")
}

pub fn write_file_planner(args: &[ExpandedArgument]) -> Result<Vec<PathRequirement>, PlannerError> {
    for arg in args {
        if let Some(value) = arg.value() {
            if value != "--append" && value != "--" {
                return Err(usage(arg.span(), "unsupported write option"));
            }
        }
    }
    let paths: Vec<_> = path_indices(args).collect();
    if paths.len() != 1 {
        return Err(usage(
            args.first()
                .map(ExpandedArgument::span)
                .unwrap_or(Span { start: 0, end: 0 }),
            "write requires exactly one capability path",
        ));
    }
    let append = args.iter().any(|arg| arg.value() == Some("--append"));
    Ok(vec![PathRequirement {
        argument: paths[0],
        rights: if append {
            Rights::READ.union(Rights::WRITE)
        } else {
            Rights::WRITE
        },
    }])
}

pub fn mutate_paths_planner(
    args: &[ExpandedArgument],
) -> Result<Vec<PathRequirement>, PlannerError> {
    require_paths_with_options(args, Rights::WRITE, &[], "nT")
}

pub fn copy_paths_planner(args: &[ExpandedArgument]) -> Result<Vec<PathRequirement>, PlannerError> {
    for arg in args {
        if let Some(value) = arg.value() {
            if value == "--"
                || (value.starts_with('-') && value[1..].chars().all(|c| "rRHLPnT".contains(c)))
            {
                continue;
            }
            return Err(usage(
                arg.span(),
                if value.starts_with('-') {
                    "unsupported cp option"
                } else {
                    "bare paths are not allowed; use @ROOT/path"
                },
            ));
        }
    }
    let paths: Vec<_> = path_indices(args).collect();
    if paths.len() < 2 {
        return Err(usage(
            args.first()
                .map(ExpandedArgument::span)
                .unwrap_or(Span { start: 0, end: 0 }),
            "cp requires source and destination capability paths",
        ));
    }
    Ok(paths
        .iter()
        .enumerate()
        .map(|(position, argument)| PathRequirement {
            argument: *argument,
            rights: if position + 1 == paths.len() {
                Rights::WRITE
            } else {
                Rights::READ
            },
        })
        .collect())
}

pub fn link_paths_planner(args: &[ExpandedArgument]) -> Result<Vec<PathRequirement>, PlannerError> {
    let mut options = true;
    let mut symbolic = false;
    let mut relative = false;
    let mut value_operands = 0usize;
    for arg in args {
        if let Some(value) = arg.value() {
            if options && value == "--" {
                options = false;
                continue;
            }
            if options && value.starts_with('-') && value.len() > 1 {
                if !value[1..].chars().all(|c| "fLPTsr".contains(c)) {
                    return Err(usage(arg.span(), "unsupported ln option"));
                }
                symbolic |= value[1..].contains('s');
                relative |= value[1..].contains('r');
            } else {
                value_operands += 1;
            }
        }
    }
    let paths: Vec<_> = path_indices(args).collect();
    if symbolic {
        if (relative && (paths.len() != 2 || value_operands != 0))
            || (!relative && (paths.len() != 1 || value_operands != 1))
        {
            return Err(usage(
                Span { start: 0, end: 0 },
                "ln -s requires one relative target and one destination",
            ));
        }
        return Ok(paths
            .iter()
            .enumerate()
            .map(|(position, argument)| PathRequirement {
                argument: *argument,
                rights: if position + 1 == paths.len() {
                    Rights::WRITE
                } else {
                    Rights::READ
                },
            })
            .collect());
    }
    if paths.len() != 2 || value_operands != 0 {
        return Err(usage(
            Span { start: 0, end: 0 },
            "ln requires two capability paths",
        ));
    }
    Ok(vec![
        PathRequirement {
            argument: paths[0],
            rights: Rights::READ,
        },
        PathRequirement {
            argument: paths[1],
            rights: Rights::WRITE,
        },
    ])
}

fn status(error: FileError) -> Status {
    match error {
        FileError::BudgetExceeded => Status::BudgetExceeded,
        FileError::Busy | FileError::Conflict => Status::Unavailable,
        _ => Status::Returned(1),
    }
}

fn resolved_paths(
    args: &[ResolvedArgument],
) -> Result<Vec<(vibeos_core::cap::Cap, String, String)>, Status> {
    args.iter()
        .filter_map(|arg| match arg {
            ResolvedArgument::CapabilityPath {
                root, label, tail, ..
            } => Some(Ok((*root, label.clone(), tail.clone()))),
            ResolvedArgument::Value(_) | ResolvedArgument::CapabilityBinding { .. } => None,
        })
        .collect()
}

fn options(args: &[ResolvedArgument]) -> impl Iterator<Item = &str> {
    args.iter().filter_map(|arg| match arg {
        ResolvedArgument::Value(value) => Some(value.as_str()),
        _ => None,
    })
}

fn has_short_flag(args: &[ResolvedArgument], wanted: char) -> bool {
    let mut enabled = true;
    for option in options(args) {
        if enabled && option == "--" {
            enabled = false;
        } else if enabled && option.starts_with('-') && !option.starts_with("--") {
            if option[1..].chars().any(|flag| flag == wanted) {
                return true;
            }
        }
    }
    false
}

fn last_short_flag(args: &[ResolvedArgument], accepted: &str) -> Option<char> {
    let mut selected = None;
    let mut enabled = true;
    for option in options(args) {
        if enabled && option == "--" {
            enabled = false;
        } else if enabled && option.starts_with('-') && !option.starts_with("--") {
            for flag in option[1..].chars() {
                if accepted.contains(flag) {
                    selected = Some(flag);
                }
            }
        }
    }
    selected
}

fn file_type_name(kind: FileType) -> &'static str {
    match kind {
        FileType::Regular => "file",
        FileType::Directory => "directory",
        FileType::Symlink => "symbolic link",
    }
}

#[derive(Clone, Copy)]
struct LsOptions {
    long: bool,
    directory: bool,
    all: bool,
    almost_all: bool,
    recursive: bool,
    follow_all: bool,
    follow_command_line: bool,
}

fn append_ls_entry(
    output: &mut String,
    name: &str,
    meta: &vibeos_file_store::Metadata,
    long: bool,
) {
    if long {
        output.push_str(&format!(
            "{} {} {} {} {}\n",
            file_type_name(meta.file_type),
            meta.link_count,
            meta.size,
            meta.change_generation,
            name
        ));
    } else {
        output.push_str(name);
        output.push('\n');
    }
}

fn list_directory(
    snapshot: &vibeos_file_store::FsSnapshotLease,
    path: &RelPath,
    display: &str,
    options: LsOptions,
    visited: &mut BTreeSet<u64>,
    output: &mut String,
) -> Result<(), FileError> {
    let directory_meta = snapshot.stat(path, options.follow_all)?;
    if !visited.insert(directory_meta.file_id) {
        return Err(FileError::SymlinkLoop);
    }
    if options.recursive {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(display);
        output.push_str(":\n");
    }
    if options.all {
        append_ls_entry(output, ".", &directory_meta, options.long);
        let parent = path
            .parent_and_name()
            .map(|(parent, _)| parent)
            .unwrap_or_else(|_| RelPath::root());
        append_ls_entry(output, "..", &snapshot.stat(&parent, true)?, options.long);
    }
    let mut descend = Vec::new();
    for (name, lstat) in snapshot.list(path, false)? {
        if !options.all && !options.almost_all && name.starts_with('.') {
            continue;
        }
        let child = path.joined_name(&name)?;
        let meta = if options.follow_all {
            snapshot.stat(&child, true)?
        } else {
            lstat
        };
        append_ls_entry(output, &name, &meta, options.long);
        if options.recursive && meta.file_type == FileType::Directory {
            descend.push((name, child));
        }
    }
    for (name, child) in descend {
        let child_display = if display.is_empty() {
            name
        } else {
            format!("{display}/{name}")
        };
        list_directory(snapshot, &child, &child_display, options, visited, output)?;
    }
    visited.remove(&directory_meta.file_id);
    Ok(())
}

fn ls_command(ctx: CapabilityCommandContext) -> CapabilityCommandFuture {
    Box::pin(async move {
        let follow = last_short_flag(&ctx.args, "HL");
        let options = LsOptions {
            long: has_short_flag(&ctx.args, 'l'),
            directory: has_short_flag(&ctx.args, 'd'),
            all: has_short_flag(&ctx.args, 'a'),
            almost_all: has_short_flag(&ctx.args, 'A'),
            recursive: has_short_flag(&ctx.args, 'R'),
            follow_all: follow == Some('L'),
            follow_command_line: matches!(follow, Some('H' | 'L')),
        };
        let mut out = String::new();
        for (cap, label, tail) in resolved_paths(&ctx.args)? {
            let path = RelPath::parse(&tail).map_err(status)?;
            let lease = ctx.lookup::<FileTreeRoot>(cap, Rights::READ)?;
            lease
                .with(|root| {
                    let snapshot = root.snapshot();
                    let meta = snapshot.stat(&path, options.follow_command_line)?;
                    if meta.file_type != FileType::Directory || options.directory {
                        let name = path
                            .file_name()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| format!("@{label}"));
                        append_ls_entry(&mut out, &name, &meta, options.long);
                        return Ok(());
                    }
                    let display = if tail.is_empty() {
                        format!("@{label}")
                    } else {
                        format!("@{label}/{tail}")
                    };
                    list_directory(
                        &snapshot,
                        &path,
                        &display,
                        options,
                        &mut BTreeSet::new(),
                        &mut out,
                    )
                })
                .map_err(status)?;
        }
        Ok(out)
    })
}

fn stat_command(ctx: CapabilityCommandContext) -> CapabilityCommandFuture {
    Box::pin(async move {
        let follow = options(&ctx.args).any(|x| x == "-L");
        let values: Vec<&str> = options(&ctx.args).collect();
        let format = values.iter().enumerate().find_map(|(index, value)| {
            if *value == "-c" {
                values.get(index + 1).copied()
            } else {
                value.strip_prefix("-c").filter(|tail| !tail.is_empty())
            }
        });
        let mut out = String::new();
        for (cap, label, tail) in resolved_paths(&ctx.args)? {
            let path = RelPath::parse(&tail).map_err(status)?;
            let meta = ctx
                .lookup::<FileTreeRoot>(cap, Rights::READ)?
                .with(|root| root.snapshot().stat(&path, follow))
                .map_err(status)?;
            let display_name = format!("@{}/{}", label, tail);
            if let Some(format) = format {
                let link_target = ctx.lookup::<FileTreeRoot>(cap, Rights::READ)?.with(|root| {
                    root.snapshot()
                        .readlink(&path)
                        .map(ToString::to_string)
                        .ok()
                });
                out.push_str(&format_stat(
                    format,
                    &display_name,
                    link_target.as_deref(),
                    &meta,
                )?);
                out.push('\n');
            } else {
                out.push_str(&format!(
                    "{}: type={} size={} links={} inode={} generation={}\n",
                    display_name,
                    file_type_name(meta.file_type),
                    meta.size,
                    meta.link_count,
                    meta.file_id,
                    meta.change_generation
                ));
            }
        }
        Ok(out)
    })
}

fn format_stat(
    format: &str,
    name: &str,
    link_target: Option<&str>,
    meta: &vibeos_file_store::Metadata,
) -> Result<String, Status> {
    let mut output = String::new();
    let mut chars = format.chars();
    while let Some(character) = chars.next() {
        if character != '%' {
            output.push(character);
            continue;
        }
        match chars.next().ok_or(Status::Returned(2))? {
            '%' => output.push('%'),
            'n' => output.push_str(name),
            'N' => {
                output.push_str(name);
                if let Some(target) = link_target {
                    output.push_str(" -> ");
                    output.push_str(target);
                }
            }
            'F' => output.push_str(file_type_name(meta.file_type)),
            's' => output.push_str(&meta.size.to_string()),
            'h' => output.push_str(&meta.link_count.to_string()),
            'i' => output.push_str(&meta.file_id.to_string()),
            _ => return Err(Status::Returned(2)),
        }
    }
    Ok(output)
}

fn cat_command(ctx: CapabilityCommandContext) -> CapabilityCommandFuture {
    Box::pin(async move {
        for (cap, _label, tail) in resolved_paths(&ctx.args)? {
            let path = RelPath::parse(&tail).map_err(status)?;
            let chunks = ctx
                .lookup::<FileTreeRoot>(cap, Rights::READ)?
                .with(|root| root.snapshot().read_owned_chunks(&path))
                .map_err(status)?;
            for chunk in chunks {
                let result = ctx.write_stdout(chunk.as_ref().to_vec()).await;
                if result != Status::Success {
                    return Err(result);
                }
            }
        }
        Ok(String::new())
    })
}

fn readlink_command(ctx: CapabilityCommandContext) -> CapabilityCommandFuture {
    Box::pin(async move {
        let canonical = options(&ctx.args).any(|x| x == "-f");
        let mut out = String::new();
        for (cap, label, tail) in resolved_paths(&ctx.args)? {
            let path = RelPath::parse(&tail).map_err(status)?;
            let value = ctx
                .lookup::<FileTreeRoot>(cap, Rights::READ)?
                .with(|root| {
                    let snapshot = root.snapshot();
                    if canonical {
                        snapshot
                            .canonical_path(&path)
                            .map(|p| format!("@{label}/{p}"))
                    } else {
                        snapshot.readlink(&path).map(ToString::to_string)
                    }
                })
                .map_err(status)?;
            out.push_str(&value);
            out.push('\n');
        }
        Ok(out)
    })
}

fn write_command(ctx: CapabilityCommandContext) -> CapabilityCommandFuture {
    Box::pin(async move {
        let append = options(&ctx.args).any(|x| x == "--append");
        let (cap, _, tail) = resolved_paths(&ctx.args)?
            .pop()
            .ok_or(Status::Returned(2))?;
        let mut chunks = Vec::new();
        while let Some(chunk) = ctx.read_stdin_chunk().await? {
            chunks.push(chunk);
        }
        let path = RelPath::parse(&tail).map_err(status)?;
        let rights = if append {
            Rights::READ.union(Rights::WRITE)
        } else {
            Rights::WRITE
        };
        ctx.lookup::<FileTreeRoot>(cap, rights)?
            .with(|root| {
                let mut tx = root.begin()?;
                tx.write_chunks(&path, chunks, append)?;
                tx.commit()
            })
            .map_err(status)?;
        Ok(String::new())
    })
}

fn mkdir_command(ctx: CapabilityCommandContext) -> CapabilityCommandFuture {
    Box::pin(async move {
        let parents = options(&ctx.args).any(|x| x == "-p");
        let paths = resolved_paths(&ctx.args)?;
        let (first, _, _) = paths.first().ok_or(Status::Returned(2))?;
        let first = *first;
        let parsed: Result<Vec<_>, _> = paths
            .iter()
            .map(|(_, _, tail)| RelPath::parse(tail))
            .collect();
        let parsed = parsed.map_err(status)?;
        ctx.lookup::<FileTreeRoot>(first, Rights::WRITE)?
            .with(|root| {
                let namespace = root.snapshot().namespace();
                for (cap, _, _) in &paths {
                    let same = ctx
                        .lookup::<FileTreeRoot>(*cap, Rights::WRITE)?
                        .with(|other| other.snapshot().namespace());
                    if same != namespace {
                        return Err(Status::Returned(1));
                    }
                }
                let mut tx = root.begin().map_err(status)?;
                for path in &parsed {
                    tx.mkdir(path, parents).map_err(status)?;
                }
                tx.commit().map_err(status)?;
                Ok(())
            })?;
        Ok(String::new())
    })
}

fn rm_command(ctx: CapabilityCommandContext) -> CapabilityCommandFuture {
    Box::pin(async move {
        let recursive = has_short_flag(&ctx.args, 'r') || has_short_flag(&ctx.args, 'R');
        let directory = has_short_flag(&ctx.args, 'd');
        let force = has_short_flag(&ctx.args, 'f');
        let paths = resolved_paths(&ctx.args)?;
        let (first, _, _) = paths.first().ok_or(Status::Returned(2))?;
        let parsed: Result<Vec<_>, _> = paths
            .iter()
            .map(|(_, _, tail)| RelPath::parse(tail))
            .collect();
        let parsed = parsed.map_err(status)?;
        ctx.lookup::<FileTreeRoot>(*first, Rights::WRITE)?
            .with(|root| {
                let namespace = root.snapshot().namespace();
                for (cap, _, _) in &paths {
                    if ctx
                        .lookup::<FileTreeRoot>(*cap, Rights::WRITE)?
                        .with(|other| other.snapshot().namespace())
                        != namespace
                    {
                        return Err(Status::Returned(1));
                    }
                }
                let mut tx = root.begin().map_err(status)?;
                for path in &parsed {
                    if let Err(error) = tx.remove(path, recursive, directory) {
                        if !(force && error == FileError::NotFound) {
                            return Err(status(error));
                        }
                    }
                }
                tx.commit().map_err(status)?;
                Ok(())
            })?;
        Ok(String::new())
    })
}

fn cp_command(ctx: CapabilityCommandContext) -> CapabilityCommandFuture {
    Box::pin(async move {
        let recursive = has_short_flag(&ctx.args, 'r') || has_short_flag(&ctx.args, 'R');
        let no_clobber = has_short_flag(&ctx.args, 'n');
        let no_target_directory = has_short_flag(&ctx.args, 'T');
        let link_mode = last_short_flag(&ctx.args, "HLP");
        let follow_source = match (recursive, link_mode) {
            (_, Some('L')) | (true, Some('H')) => true,
            (false, Some('H')) | (false, None) => true,
            _ => false,
        };
        let follow_all = recursive && link_mode == Some('L');
        let paths = resolved_paths(&ctx.args)?;
        if paths.len() < 2 {
            return Err(Status::Returned(2));
        }
        let (destination_cap, _, destination_tail) = paths.last().cloned().unwrap();
        let destination = RelPath::parse(&destination_tail).map_err(status)?;
        let mut sources = Vec::new();
        for (cap, _, tail) in &paths[..paths.len() - 1] {
            let path = RelPath::parse(tail).map_err(status)?;
            let snapshot = ctx
                .lookup::<FileTreeRoot>(*cap, Rights::READ)?
                .with(|root| root.snapshot());
            sources.push((snapshot, path));
        }
        ctx.lookup::<FileTreeRoot>(destination_cap, Rights::WRITE)?
            .with(|root| {
                let before = root.snapshot();
                let destination_is_directory = before
                    .stat(&destination, true)
                    .is_ok_and(|m| m.file_type == FileType::Directory);
                if sources.len() > 1 && (!destination_is_directory || no_target_directory) {
                    return Err(Status::Returned(1));
                }
                let mut tx = root.begin().map_err(status)?;
                for (source, source_path) in &sources {
                    let target = if destination_is_directory && !no_target_directory {
                        destination
                            .joined_name(source_path.file_name().ok_or(Status::Returned(1))?)
                            .map_err(status)?
                    } else {
                        destination.clone()
                    };
                    if no_clobber && before.stat(&target, false).is_ok() {
                        continue;
                    }
                    tx.copy_from(
                        source,
                        source_path,
                        &target,
                        recursive,
                        follow_source,
                        follow_all,
                    )
                    .map_err(status)?;
                }
                tx.commit().map_err(status)?;
                Ok(())
            })?;
        Ok(String::new())
    })
}

fn mv_command(ctx: CapabilityCommandContext) -> CapabilityCommandFuture {
    Box::pin(async move {
        let no_clobber = has_short_flag(&ctx.args, 'n');
        let no_target_directory = has_short_flag(&ctx.args, 'T');
        let paths = resolved_paths(&ctx.args)?;
        if paths.len() != 2 {
            return Err(Status::Returned(2));
        }
        let (source_cap, _, source_tail) = &paths[0];
        let (destination_cap, _, destination_tail) = &paths[1];
        let source = RelPath::parse(source_tail).map_err(status)?;
        let mut destination = RelPath::parse(destination_tail).map_err(status)?;
        let source_lease = ctx.lookup::<FileTreeRoot>(*source_cap, Rights::WRITE)?;
        let destination_lease = ctx.lookup::<FileTreeRoot>(*destination_cap, Rights::WRITE)?;
        let source_namespace = source_lease.with(|root| root.snapshot().namespace());
        let destination_namespace = destination_lease.with(|root| root.snapshot().namespace());
        if source_namespace != destination_namespace {
            return Err(Status::Returned(1));
        }
        destination_lease
            .with(|root| {
                if !no_target_directory
                    && root
                        .snapshot()
                        .stat(&destination, true)
                        .is_ok_and(|m| m.file_type == FileType::Directory)
                {
                    destination = destination
                        .joined_name(source.file_name().ok_or(FileError::RootProtected)?)?;
                }
                let mut tx = root.begin()?;
                tx.rename(&source, &destination, no_clobber)?;
                tx.commit()
            })
            .map_err(status)?;
        Ok(String::new())
    })
}

fn ln_command(ctx: CapabilityCommandContext) -> CapabilityCommandFuture {
    Box::pin(async move {
        let symbolic = has_short_flag(&ctx.args, 's');
        let relative = has_short_flag(&ctx.args, 'r');
        let follow = last_short_flag(&ctx.args, "LP") == Some('L');
        let force = has_short_flag(&ctx.args, 'f');
        let paths = resolved_paths(&ctx.args)?;
        if symbolic {
            let (destination_cap, _, destination_tail) = paths.last().ok_or(Status::Returned(2))?;
            let destination = RelPath::parse(destination_tail).map_err(status)?;
            let target = if relative {
                if paths.len() != 2 {
                    return Err(Status::Returned(2));
                }
                let (target_cap, _, target_tail) = &paths[0];
                let target_namespace = ctx
                    .lookup::<FileTreeRoot>(*target_cap, Rights::READ)?
                    .with(|root| root.snapshot().namespace());
                let destination_namespace = ctx
                    .lookup::<FileTreeRoot>(*destination_cap, Rights::WRITE)?
                    .with(|root| root.snapshot().namespace());
                if target_namespace != destination_namespace {
                    return Err(Status::Returned(1));
                }
                let target = RelPath::parse(target_tail).map_err(status)?;
                let (parent, _) = destination.parent_and_name().map_err(status)?;
                RelPath::relative_from_directory(&parent, &target)
            } else {
                let mut options_enabled = true;
                let mut target = None;
                for argument in &ctx.args {
                    let ResolvedArgument::Value(value) = argument else {
                        continue;
                    };
                    if options_enabled && value == "--" {
                        options_enabled = false;
                    } else if !(options_enabled && value.starts_with('-')) {
                        target = Some(value.clone());
                        break;
                    }
                }
                target.ok_or(Status::Returned(2))?
            };
            ctx.lookup::<FileTreeRoot>(*destination_cap, Rights::WRITE)?
                .with(|root| {
                    let mut tx = root.begin()?;
                    if force {
                        match tx.remove(&destination, false, false) {
                            Ok(()) | Err(FileError::NotFound) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    tx.symlink(&target, &destination)?;
                    tx.commit()
                })
                .map_err(status)?;
        } else {
            if paths.len() != 2 {
                return Err(Status::Returned(2));
            }
            let source = RelPath::parse(&paths[0].2).map_err(status)?;
            let destination = RelPath::parse(&paths[1].2).map_err(status)?;
            let source_namespace = ctx
                .lookup::<FileTreeRoot>(paths[0].0, Rights::READ)?
                .with(|root| root.snapshot().namespace());
            let destination_lease = ctx.lookup::<FileTreeRoot>(paths[1].0, Rights::WRITE)?;
            if destination_lease.with(|root| root.snapshot().namespace()) != source_namespace {
                return Err(Status::Returned(1));
            }
            destination_lease
                .with(|root| {
                    let mut tx = root.begin()?;
                    if force {
                        match tx.remove(&destination, false, false) {
                            Ok(()) | Err(FileError::NotFound) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    tx.hard_link(&source, &destination, follow)?;
                    tx.commit()
                })
                .map_err(status)?;
        }
        Ok(String::new())
    })
}

pub const FILE_COMMANDS: &[CapabilityCommandSpec] = &[
    CapabilityCommandSpec {
        name: "ls",
        min_args: 1,
        max_args: 128,
        stdin: StreamMode::Closed,
        planner: read_paths_planner,
        handler: ls_command,
    },
    CapabilityCommandSpec {
        name: "stat",
        min_args: 1,
        max_args: 128,
        stdin: StreamMode::Closed,
        planner: stat_paths_planner,
        handler: stat_command,
    },
    CapabilityCommandSpec {
        name: "cat",
        min_args: 1,
        max_args: 128,
        stdin: StreamMode::Closed,
        planner: cat_paths_planner,
        handler: cat_command,
    },
    CapabilityCommandSpec {
        name: "readlink",
        min_args: 1,
        max_args: 128,
        stdin: StreamMode::Closed,
        planner: readlink_paths_planner,
        handler: readlink_command,
    },
    CapabilityCommandSpec {
        name: "write",
        min_args: 1,
        max_args: 3,
        stdin: StreamMode::Required,
        planner: write_file_planner,
        handler: write_command,
    },
    CapabilityCommandSpec {
        name: "mkdir",
        min_args: 1,
        max_args: 128,
        stdin: StreamMode::Closed,
        planner: mkdir_paths_planner,
        handler: mkdir_command,
    },
    CapabilityCommandSpec {
        name: "rm",
        min_args: 1,
        max_args: 128,
        stdin: StreamMode::Closed,
        planner: rm_paths_planner,
        handler: rm_command,
    },
    CapabilityCommandSpec {
        name: "cp",
        min_args: 2,
        max_args: 128,
        stdin: StreamMode::Closed,
        planner: copy_paths_planner,
        handler: cp_command,
    },
    CapabilityCommandSpec {
        name: "mv",
        min_args: 2,
        max_args: 4,
        stdin: StreamMode::Closed,
        planner: mutate_paths_planner,
        handler: mv_command,
    },
    CapabilityCommandSpec {
        name: "ln",
        min_args: 2,
        max_args: 5,
        stdin: StreamMode::Closed,
        planner: link_paths_planner,
        handler: ln_command,
    },
];

pub fn install_file_commands(session: &mut crate::Session) {
    crate::install_capability_commands(session, FILE_COMMANDS);
}
