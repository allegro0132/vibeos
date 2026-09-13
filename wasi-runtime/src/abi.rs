//! Preview 1 function signatures. i = i32, l = i64; every function except exit returns errno.
pub(crate) fn signature(name: &str) -> Option<&'static str> {
    Some(match name {
        "args_get"
        | "args_sizes_get"
        | "environ_get"
        | "environ_sizes_get"
        | "clock_res_get"
        | "fd_fdstat_get"
        | "fd_fdstat_set_flags"
        | "fd_filestat_get"
        | "fd_prestat_get"
        | "fd_renumber"
        | "fd_tell"
        | "random_get"
        | "sock_shutdown" => "ii",
        "clock_time_get" => "ili",
        "fd_advise" => "illi",
        "fd_allocate" => "ill",
        "fd_close" | "fd_datasync" | "fd_sync" | "proc_raise" | "proc_exit" => "i",
        "fd_fdstat_set_rights" => "ill",
        "fd_filestat_set_size" => "il",
        "fd_filestat_set_times" => "illi",
        "fd_pread" | "fd_pwrite" => "iiili",
        "fd_prestat_dir_name"
        | "path_create_directory"
        | "path_remove_directory"
        | "path_unlink_file"
        | "sock_accept" => "iii",
        "fd_read" | "fd_write" | "poll_oneoff" => "iiii",
        "fd_readdir" => "iiili",
        "fd_seek" => "ilii",
        "path_filestat_get" | "path_symlink" => "iiiii",
        "path_filestat_set_times" => "iiiilli",
        "path_link" => "iiiiiii",
        "path_open" => "iiiiillii",
        "path_readlink" | "path_rename" | "sock_recv" => "iiiiii",
        "sock_send" => "iiiii",
        "sched_yield" => "",
        _ => return None,
    })
}
/// wasi-threads: `wasi::thread-spawn(start_arg: i32) -> i32` (tid >= 1 or -errno).
/// Kept outside the Preview 1 table so single-threaded engines never link it.
#[allow(dead_code)]
pub(crate) const THREAD_SPAWN_MODULE: &str = "wasi";
#[allow(dead_code)]
pub(crate) const THREAD_SPAWN_NAME: &str = "thread-spawn";
#[allow(dead_code)]
pub(crate) const THREAD_START_EXPORT: &str = "wasi_thread_start";
#[allow(dead_code)]
pub(crate) const AGAIN: i32 = 6;
pub(crate) const SUCCESS: i32 = 0;
pub(crate) const BADF: i32 = 8;
pub(crate) const FAULT: i32 = 21;
pub(crate) const IO: i32 = 29;
pub(crate) const NOSYS: i32 = 52;
pub(crate) const PIPE: i32 = 64;
pub(crate) const SPIPE: i32 = 70;
