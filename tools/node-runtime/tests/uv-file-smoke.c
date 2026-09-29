/* QEMU capability-rooted descriptor prerequisite, not module-loader acceptance. */
#include "uv.h"
#include "vibeos-files.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

extern void vibeos_uv_probe_revoke_files(void);
extern int _open(const char*, int, int);
static const char source[] = "export const answer = 42;\n";
struct files {
  uv_loop_t loop;
  uv_fs_t request;
  int fd, failed;
  unsigned callbacks;
};

static unsigned open_callbacks;
static int opened_fd, open_failed, open_cancelled;
static void mutating_open_done(uv_fs_t* req) {
  if (open_cancelled) {
    if (req->result != UV_ECANCELED) open_failed = 1;
  } else {
    if (req->result < 3) open_failed = 1;
    opened_fd = (int) req->result;
  }
  open_callbacks++;
  uv_fs_req_cleanup(req);
}
static int mutating_open_smoke(void) {
  uv_loop_t loop;
  uv_fs_t req;
  if (uv_loop_init(&loop)) return 330;
  char path[] = "async-open";
  if (uv_fs_open(&loop, &req, path, O_CREAT | O_EXCL | O_RDWR, 0600, mutating_open_done) || open_callbacks) return 331;
  memset(path, 'x', sizeof(path) - 1);
  if (uv_run(&loop, UV_RUN_DEFAULT) || open_failed || open_callbacks != 1) return 332;
  uv_buf_t bytes = uv_buf_init("preserved", 9);
  if (uv_fs_write(NULL, &req, opened_fd, &bytes, 1, -1, NULL) != 9) return 333;
  uv_fs_req_cleanup(&req);
  if (uv_fs_close(NULL, &req, opened_fd, NULL)) return 333;
  uv_fs_req_cleanup(&req);
  open_cancelled = 1;
  if (uv_fs_open(&loop, &req, "async-open", O_WRONLY | O_TRUNC, 0, mutating_open_done) ||
      uv_cancel((uv_req_t*) &req) || uv_run(&loop, UV_RUN_DEFAULT) || open_failed || open_callbacks != 2) return 334;
  if (uv_fs_stat(NULL, &req, "async-open", NULL) || req.statbuf.st_size != 9) return 335;
  uv_fs_req_cleanup(&req);
  if (uv_fs_open(&loop, &req, "cancel-open", O_CREAT | O_WRONLY, 0600, mutating_open_done) ||
      uv_cancel((uv_req_t*) &req) || uv_run(&loop, UV_RUN_DEFAULT) || open_failed || open_callbacks != 3) return 336;
  if (uv_fs_stat(NULL, &req, "cancel-open", NULL) != UV_ENOENT) return 337;
  uv_fs_req_cleanup(&req);
  open_cancelled = 0;
  if (uv_fs_open(&loop, &req, "async-open", O_WRONLY | O_TRUNC, 0, mutating_open_done) ||
      uv_run(&loop, UV_RUN_DEFAULT) || open_failed || open_callbacks != 4) return 338;
  if (uv_fs_fstat(NULL, &req, opened_fd, NULL) || req.statbuf.st_size != 0) return 339;
  uv_fs_req_cleanup(&req);
  if (uv_fs_close(NULL, &req, opened_fd, NULL)) return 340;
  uv_fs_req_cleanup(&req);
  if (uv_fs_unlink(NULL, &req, "async-open", NULL)) return 340;
  uv_fs_req_cleanup(&req);
  if (uv_loop_close(&loop)) return 341;
  puts("UV OPEN async_create=1 async_truncate=1 copied_path=1 cancelled=2 preserved=1 PASS");
  return 0;
}

static unsigned copy_callbacks;
static int copy_failed, copy_expected;
static void copy_done(uv_fs_t* req) {
  if (req->result != copy_expected) copy_failed = 1;
  copy_callbacks++;
  uv_fs_req_cleanup(req);
}
static int copy_readback(const char* path, const char* expected) {
  uv_fs_t req;
  int fd = uv_fs_open(NULL, &req, path, O_RDONLY, 0, NULL);
  uv_fs_req_cleanup(&req);
  if (fd < 3) return 1;
  char bytes[64] = {0};
  uv_buf_t buffer = uv_buf_init(bytes, sizeof(bytes));
  int count = uv_fs_read(NULL, &req, fd, &buffer, 1, -1, NULL);
  uv_fs_req_cleanup(&req);
  int status = uv_fs_close(NULL, &req, fd, NULL);
  uv_fs_req_cleanup(&req);
  return status || count != (int) strlen(expected) || memcmp(bytes, expected, strlen(expected));
}
static int copy_smoke(void) {
  uv_loop_t loop;
  uv_fs_t req;
  if (uv_loop_init(&loop)) return 300;
  if (uv_fs_copyfile(NULL, &req, "main.js", "copy-a", UV_FS_COPYFILE_EXCL, NULL)) return 301;
  uv_fs_req_cleanup(&req);
  if (uv_fs_copyfile(NULL, &req, "copy-a", "copy-b", UV_FS_COPYFILE_FICLONE, NULL)) return 302;
  uv_fs_req_cleanup(&req);
  if (uv_fs_copyfile(NULL, &req, "main.js", "copy-a", UV_FS_COPYFILE_EXCL, NULL) != UV_EEXIST) return 303;
  uv_fs_req_cleanup(&req);
  if (uv_fs_copyfile(NULL, &req, "main.js", "copy-force", UV_FS_COPYFILE_FICLONE_FORCE, NULL) != UV_ENOTSUP) return 304;
  uv_fs_req_cleanup(&req);
  if (uv_fs_copyfile(NULL, &req, "main.js", "copy-invalid", 8, NULL) != UV_EINVAL) return 305;
  uv_fs_req_cleanup(&req);
  if (uv_fs_copyfile(NULL, &req, "src", "copy-invalid", 0, NULL) != UV_EISDIR) return 306;
  uv_fs_req_cleanup(&req);
  if (uv_fs_copyfile(NULL, &req, "main.js", "../escape", 0, NULL) != UV_EACCES) return 307;
  uv_fs_req_cleanup(&req);
  int fd = uv_fs_open(NULL, &req, "copy-a", O_RDWR, 0, NULL);
  uv_fs_req_cleanup(&req);
  if (fd < 3) return 308;
  uv_buf_t bang = uv_buf_init("!", 1);
  if (uv_fs_write(NULL, &req, fd, &bang, 1, 0, NULL) != 1) return 309;
  uv_fs_req_cleanup(&req);
  if (uv_fs_close(NULL, &req, fd, NULL)) return 309;
  uv_fs_req_cleanup(&req);
  if (copy_readback("copy-b", source) || copy_readback("main.js", source)) return 310;
  if (uv_fs_link(NULL, &req, "copy-b", "copy-alias", NULL)) return 311;
  uv_fs_req_cleanup(&req);
  if (uv_fs_copyfile(NULL, &req, "copy-b", "copy-alias", 0, NULL) != UV_EINVAL) return 312;
  uv_fs_req_cleanup(&req);
  if (uv_fs_symlink(NULL, &req, "copy-b", "copy-link", 0, NULL)) return 313;
  uv_fs_req_cleanup(&req);
  if (uv_fs_copyfile(NULL, &req, "copy-a", "copy-link", 0, NULL)) return 314;
  uv_fs_req_cleanup(&req);
  char changed[sizeof(source)]; memcpy(changed, source, sizeof(source)); changed[0] = '!';
  if (copy_readback("copy-alias", changed) || copy_readback("copy-b", changed)) return 315;
  char destination[] = "copy-c";
  if (uv_fs_copyfile(&loop, &req, "src/link.js", destination, 0, copy_done) || copy_callbacks) return 316;
  memset(destination, 'x', sizeof(destination) - 1);
  if (uv_run(&loop, UV_RUN_DEFAULT) || copy_callbacks != 1 || copy_failed || copy_readback("copy-c", source)) return 317;
  vibeos_native_file_stat_t before, after;
  if (vibeos_native_path_stat("/", 1, 1, &before)) return 318;
  copy_expected = UV_ECANCELED;
  if (uv_fs_copyfile(&loop, &req, "main.js", "copy-cancel", 0, copy_done) ||
      uv_cancel((uv_req_t*) &req) || uv_run(&loop, UV_RUN_DEFAULT) || copy_callbacks != 2 || copy_failed ||
      vibeos_native_path_stat("/", 1, 1, &after) || before.generation != after.generation) return 319;
  if (uv_fs_statfs(NULL, &req, "/", NULL) != UV_ENOTSUP || req.ptr) return 320;
  uv_fs_req_cleanup(&req);
  if (uv_fs_statfs(NULL, &req, "../escape", NULL) != UV_EACCES) return 321;
  uv_fs_req_cleanup(&req);
  copy_expected = UV_ENOTSUP;
  if (uv_fs_statfs(&loop, &req, "/", copy_done) || uv_run(&loop, UV_RUN_DEFAULT) ||
      copy_callbacks != 3 || copy_failed) return 322;
  const char* paths[] = { "copy-a", "copy-b", "copy-alias", "copy-link", "copy-c" };
  for (unsigned i = 0; i < 5; i++) {
    if (uv_fs_unlink(NULL, &req, paths[i], NULL)) return 323;
    uv_fs_req_cleanup(&req);
  }
  if (uv_fs_stat(NULL, &req, "copy-cancel", NULL) != UV_ENOENT) return 324;
  uv_fs_req_cleanup(&req);
  if (uv_loop_close(&loop)) return 325;
  puts("UV COPY content=1 independent=1 links=1 exclusive=1 async=1 cancelled=1 statfs_unsupported=1 PASS");
  return 0;
}

static char temporary_name[128];
static int temporary_fd, temporary_failed;
static unsigned temporary_callbacks;
static int temporary_cancel;
static void temporary_done(uv_fs_t* req) {
  if (temporary_cancel) {
    if (req->result != UV_ECANCELED || strcmp(req->path, "cancel-temp-XXXXXX")) temporary_failed = 1;
  } else {
    if (req->result < 0 || strlen(req->path) >= sizeof(temporary_name)) temporary_failed = 1;
    else {
      strcpy(temporary_name, req->path);
      temporary_fd = (int) req->result;
    }
  }
  temporary_callbacks++;
  uv_fs_req_cleanup(req);
}
static int temporary_smoke(void) {
  uv_loop_t loop;
  uv_fs_t req;
  char first[128], second[128];
  if (uv_loop_init(&loop)) return 260;
  if (uv_fs_mkdtemp(NULL, &req, "bad-template", NULL) != UV_EINVAL) return 261;
  uv_fs_req_cleanup(&req);
  if (uv_fs_mkstemp(NULL, &req, "XX", NULL) != UV_EINVAL) return 261;
  uv_fs_req_cleanup(&req);
  if (uv_fs_mkdtemp(NULL, &req, "../escape-XXXXXX", NULL) != UV_EACCES ||
      strcmp(req.path, "../escape-XXXXXX")) return 262;
  uv_fs_req_cleanup(&req);
  const char pattern[] = "temp-file-XXXXXX";
  int fd = uv_fs_mkstemp(NULL, &req, pattern, NULL);
  if (fd < 3 || !strcmp(req.path, pattern) || strncmp(req.path, "temp-file-", 10) ||
      strlen(req.path) != strlen(pattern) || strcmp(pattern, "temp-file-XXXXXX")) return 263;
  strcpy(first, req.path);
  uv_fs_req_cleanup(&req);
  uv_buf_t data = uv_buf_init("temporary", 9);
  if (uv_fs_write(NULL, &req, fd, &data, 1, -1, NULL) != 9) return 264;
  uv_fs_req_cleanup(&req);
  if (uv_fs_close(NULL, &req, fd, NULL)) return 264;
  uv_fs_req_cleanup(&req);
  char copied[] = "temp-file-XXXXXX";
  if (uv_fs_mkstemp(&loop, &req, copied, temporary_done) || temporary_callbacks) return 265;
  memset(copied, 'x', sizeof(copied) - 1);
  if (uv_run(&loop, UV_RUN_DEFAULT) || temporary_callbacks != 1 || temporary_failed ||
      temporary_fd < 3 || !strcmp(temporary_name, first) || strncmp(temporary_name, "temp-file-", 10)) return 266;
  strcpy(second, temporary_name);
  if (uv_fs_close(NULL, &req, temporary_fd, NULL)) return 267;
  uv_fs_req_cleanup(&req);
  if (uv_fs_stat(NULL, &req, first, NULL) || req.statbuf.st_size != 9) return 268;
  uv_fs_req_cleanup(&req);
  fd = uv_fs_open(NULL, &req, first, O_RDONLY, 0, NULL);
  if (fd < 3) return 268;
  uv_fs_req_cleanup(&req);
  char bytes[9];
  uv_buf_t readback = uv_buf_init(bytes, sizeof(bytes));
  if (uv_fs_read(NULL, &req, fd, &readback, 1, -1, NULL) != 9 || memcmp(bytes, "temporary", 9)) return 268;
  uv_fs_req_cleanup(&req);
  if (uv_fs_close(NULL, &req, fd, NULL)) return 268;
  uv_fs_req_cleanup(&req);
  if (uv_fs_unlink(NULL, &req, first, NULL)) return 269;
  uv_fs_req_cleanup(&req);
  if (uv_fs_unlink(NULL, &req, second, NULL)) return 269;
  uv_fs_req_cleanup(&req);
  if (uv_fs_mkdtemp(NULL, &req, "temp-dir-XXXXXX", NULL) || !strcmp(req.path, "temp-dir-XXXXXX")) return 270;
  strcpy(first, req.path);
  uv_fs_req_cleanup(&req);
  if (uv_fs_stat(NULL, &req, first, NULL) || !S_ISDIR(req.statbuf.st_mode)) return 271;
  uv_fs_req_cleanup(&req);
  if (uv_fs_mkdtemp(&loop, &req, "temp-dir-XXXXXX", temporary_done) ||
      uv_run(&loop, UV_RUN_DEFAULT) || temporary_callbacks != 2 || temporary_failed || temporary_fd ||
      !strcmp(first, temporary_name)) return 272;
  if (uv_fs_rmdir(NULL, &req, first, NULL)) return 273;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rmdir(NULL, &req, temporary_name, NULL)) return 273;
  uv_fs_req_cleanup(&req);
  vibeos_native_file_stat_t before, after;
  if (vibeos_native_path_stat("/", 1, 1, &before)) return 274;
  temporary_cancel = 1;
  for (int directory = 0; directory < 2; directory++) {
    int status = directory ? uv_fs_mkdtemp(&loop, &req, "cancel-temp-XXXXXX", temporary_done)
                           : uv_fs_mkstemp(&loop, &req, "cancel-temp-XXXXXX", temporary_done);
    if (status || uv_cancel((uv_req_t*) &req) || uv_run(&loop, UV_RUN_DEFAULT)) return 275;
  }
  if (temporary_callbacks != 4 || temporary_failed || vibeos_native_path_stat("/", 1, 1, &after) ||
      before.generation != after.generation || uv_loop_close(&loop)) return 276;
  puts("UV TEMP sync=2 async=2 unique=1 content=1 cancelled=2 no_mutation=1 PASS");
  return 0;
}

static uv_dir_t* revoked_directory;
static uv_dir_t* opened_directory;
static unsigned directory_callbacks;
static int directory_failed;
static ssize_t directory_expected;
static const char* directory_name;
static void directory_done(uv_fs_t* req) {
  if (req->result != directory_expected) directory_failed = 1;
  if (req->fs_type == UV_FS_OPENDIR && !req->result) opened_directory = req->ptr;
  if (directory_name && req->result == 1) {
    uv_dir_t* dir = req->ptr;
    if (strcmp(dir->dirents[0].name, directory_name)) directory_failed = 1;
  }
  directory_callbacks++;
  uv_fs_req_cleanup(req);
}
static int directory_smoke(void) {
  uv_loop_t loop;
  uv_fs_t req;
  uv_dirent_t entries[2] = {{0}};
  if (uv_loop_init(&loop)) return 230;
  if (uv_fs_mkdir(NULL, &req, "uv-directory", 0700, NULL)) return 231;
  uv_fs_req_cleanup(&req);
  int fd = uv_fs_open(NULL, &req, "uv-directory/a", O_CREAT | O_RDWR, 0600, NULL);
  if (fd < 3) return 232;
  uv_fs_req_cleanup(&req);
  if (uv_fs_close(NULL, &req, fd, NULL)) return 232;
  uv_fs_req_cleanup(&req);
  if (uv_fs_mkdir(NULL, &req, "uv-directory/b", 0700, NULL)) return 233;
  uv_fs_req_cleanup(&req);
  if (uv_fs_symlink(NULL, &req, "a", "uv-directory/c", 0, NULL)) return 234;
  uv_fs_req_cleanup(&req);
  if (uv_fs_opendir(NULL, &req, "uv-directory/a", NULL) != UV_ENOTDIR) return 235;
  uv_fs_req_cleanup(&req);
  if (uv_fs_opendir(NULL, &req, "../escape", NULL) != UV_EACCES) return 235;
  uv_fs_req_cleanup(&req);
  directory_expected = 0;
  char path[] = "uv-directory";
  if (uv_fs_opendir(&loop, &req, path, directory_done) || directory_callbacks) return 236;
  memset(path, 'x', sizeof(path) - 1);
  if (uv_run(&loop, UV_RUN_DEFAULT) || directory_callbacks != 1 || directory_failed || !opened_directory) return 237;
  uv_dir_t* dir = opened_directory;
  dir->dirents = entries;
  dir->nentries = 1;
  if (uv_fs_readdir(NULL, &req, dir, NULL) != 1 || strcmp(entries[0].name, "a") || entries[0].type != UV_DIRENT_FILE) return 238;
  uv_fs_req_cleanup(&req);
  if (entries[0].name) return 239;
  directory_expected = UV_ECANCELED;
  if (uv_fs_readdir(&loop, &req, dir, directory_done) || uv_cancel((uv_req_t*) &req) ||
      uv_run(&loop, UV_RUN_DEFAULT) || directory_callbacks != 2 || directory_failed) return 240;
  directory_expected = 1;
  directory_name = "b";
  if (uv_fs_readdir(&loop, &req, dir, directory_done) || directory_callbacks != 2 ||
      uv_run(&loop, UV_RUN_DEFAULT) || directory_callbacks != 3 || directory_failed || entries[0].type != UV_DIRENT_DIR) return 241;
  directory_name = NULL;
  dir->nentries = 2;
  if (uv_fs_readdir(NULL, &req, dir, NULL) != 1 || strcmp(entries[0].name, "c") || entries[0].type != UV_DIRENT_LINK) return 242;
  uv_fs_req_cleanup(&req);
  if (uv_fs_readdir(NULL, &req, dir, NULL) != 0) return 243;
  uv_fs_req_cleanup(&req);
  directory_expected = UV_ECANCELED;
  if (uv_fs_closedir(&loop, &req, dir, directory_done) || uv_cancel((uv_req_t*) &req) ||
      uv_run(&loop, UV_RUN_DEFAULT) || directory_callbacks != 4 || directory_failed) return 244;
  if (uv_fs_readdir(NULL, &req, dir, NULL)) return 245;
  uv_fs_req_cleanup(&req);
  directory_expected = 0;
  if (uv_fs_closedir(&loop, &req, dir, directory_done) || uv_run(&loop, UV_RUN_DEFAULT) ||
      directory_callbacks != 5 || directory_failed) return 246;
  if (uv_fs_opendir(NULL, &req, "uv-directory/b", NULL)) return 247;
  dir = req.ptr;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rmdir(NULL, &req, "uv-directory/b", NULL)) return 248;
  uv_fs_req_cleanup(&req);
  if (uv_fs_mkdir(NULL, &req, "uv-directory/b", 0700, NULL)) return 248;
  uv_fs_req_cleanup(&req);
  entries[0].name = "unchanged";
  dir->dirents = entries;
  dir->nentries = 1;
  if (uv_fs_readdir(NULL, &req, dir, NULL) != UV_ENOENT || strcmp(entries[0].name, "unchanged")) return 249;
  uv_fs_req_cleanup(&req);
  if (uv_fs_closedir(NULL, &req, dir, NULL)) return 250;
  uv_fs_req_cleanup(&req);
  if (uv_fs_unlink(NULL, &req, "uv-directory/a", NULL)) return 253;
  uv_fs_req_cleanup(&req);
  if (uv_fs_unlink(NULL, &req, "uv-directory/c", NULL)) return 253;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rmdir(NULL, &req, "uv-directory/b", NULL)) return 253;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rmdir(NULL, &req, "uv-directory", NULL)) return 253;
  uv_fs_req_cleanup(&req);
  if (uv_fs_opendir(NULL, &req, "/src", NULL)) return 251;
  revoked_directory = req.ptr;
  uv_fs_req_cleanup(&req);
  if (uv_loop_close(&loop)) return 252;
  puts("UV DIRECTORY types=3 cursor=1 eof=1 async=3 cancelled=2 replaced=1 PASS");
  return 0;
}

static unsigned read_callbacks;
static ssize_t expected_read;
static void read_done(uv_fs_t* req) {
  if (req->result == expected_read) read_callbacks++;
  uv_fs_req_cleanup(req);
}
static unsigned write_callbacks, truncate_callbacks;
static void write_done(uv_fs_t* req) {
  if (req->result == 2) write_callbacks++;
  uv_fs_req_cleanup(req);
}
static void truncate_done(uv_fs_t* req) {
  if (req->result == 0) truncate_callbacks++;
  uv_fs_req_cleanup(req);
}
static unsigned tree_callbacks;
static void tree_done(uv_fs_t* req) {
  if (req->result == 0) tree_callbacks++;
  uv_fs_req_cleanup(req);
}
static unsigned scan_callbacks;
static void scan_done(uv_fs_t* req) {
  uv_dirent_t entry;
  if (req->result == 1 && !uv_fs_scandir_next(req, &entry) &&
      !strcmp(entry.name, "link.js") && entry.type == UV_DIRENT_LINK &&
      uv_fs_scandir_next(req, &entry) == UV_EOF) scan_callbacks++;
  uv_fs_req_cleanup(req);
}
static unsigned access_callbacks;
static void access_done(uv_fs_t* req) {
  if (req->result == 0) access_callbacks++;
  uv_fs_req_cleanup(req);
}
static unsigned sync_callbacks;
static int sync_failed;
static void sync_done(uv_fs_t* req) {
  int expected = req->data ? UV_ECANCELED : 0;
  if (req->result != expected) sync_failed = 1;
  sync_callbacks++;
  uv_fs_req_cleanup(req);
}
static int sync_smoke(void) {
  uv_loop_t loop = {0};
  uv_fs_t req, pending[3] = {0};
  vibeos_native_file_stat_t before, after;
  if (uv_loop_init(&loop)) return 260;
  int fd = uv_fs_open(&loop, &req, "sync-file", O_RDWR | O_CREAT | O_EXCL, 0600, NULL);
  uv_fs_req_cleanup(&req);
  if (fd < 3) return 261;
  uv_buf_t data = uv_buf_init("sync", 4);
  if (uv_fs_write(&loop, &req, fd, &data, 1, -1, NULL) != 4) return 262;
  uv_fs_req_cleanup(&req);
  int64_t mutation = vibeos_native_file_write_begin(fd, "S", 1);
  if (mutation <= 0 || uv_fs_fsync(&loop, &req, fd, NULL) != UV_EBUSY) return 263;
  uv_fs_req_cleanup(&req);
  if (vibeos_native_mutation_poll((uint64_t) mutation) != 1 || vibeos_native_file_stat(fd, &before)) return 264;
  if (uv_fs_fsync(&loop, &req, fd, NULL)) return 265;
  uv_fs_req_cleanup(&req);
  if (uv_fs_fdatasync(&loop, &req, fd, NULL)) return 266;
  uv_fs_req_cleanup(&req);
  sync_callbacks = 0; sync_failed = 0;
  pending[2].data = &loop;
  if (uv_fs_fsync(&loop, &pending[0], fd, sync_done) ||
      uv_fs_fdatasync(&loop, &pending[1], fd, sync_done) ||
      uv_fs_fsync(&loop, &pending[2], fd, sync_done) || sync_callbacks ||
      uv_cancel((uv_req_t*) &pending[2]) || uv_run(&loop, UV_RUN_DEFAULT) ||
      sync_failed || sync_callbacks != 3) return 267;
  if (vibeos_native_file_stat(fd, &after) || memcmp(&before, &after, sizeof(before))) return 268;
  char content[6] = {0}; uv_buf_t read = uv_buf_init(content, sizeof(content));
  if (uv_fs_read(&loop, &req, fd, &read, 1, 0, NULL) != 5 || strcmp(content, "syncS")) return 269;
  uv_fs_req_cleanup(&req);
  if (uv_fs_fsync(&loop, &req, 1, NULL) != UV_EINVAL) return 270;
  uv_fs_req_cleanup(&req);
  if (uv_fs_close(&loop, &req, fd, NULL)) return 271;
  uv_fs_req_cleanup(&req);
  if (uv_fs_fsync(&loop, &req, fd, NULL) != UV_EBADF) return 272;
  uv_fs_req_cleanup(&req);
  if (uv_fs_unlink(&loop, &req, "sync-file", NULL)) return 273;
  uv_fs_req_cleanup(&req);
  if (uv_loop_close(&loop)) return 274;
  puts("UV FSYNC committed=1 busy=1 async=2 cancelled=1 unchanged=1 PASS");
  return 0;
}

static unsigned metadata_callbacks, metadata_seen;
static int metadata_failed;
static const uv_fs_type metadata_types[] = {UV_FS_CHMOD, UV_FS_FCHMOD,
  UV_FS_CHOWN, UV_FS_FCHOWN, UV_FS_LCHOWN, UV_FS_UTIME, UV_FS_FUTIME, UV_FS_LUTIME};
static int metadata_call(unsigned which, uv_loop_t* loop, uv_fs_t* req, int fd, uv_fs_cb cb) {
  switch (which) {
    case 0: return uv_fs_chmod(loop, req, "main.js", 0000, cb);
    case 1: return uv_fs_fchmod(loop, req, fd, 0000, cb);
    case 2: return uv_fs_chown(loop, req, "main.js", 99, 99, cb);
    case 3: return uv_fs_fchown(loop, req, fd, 99, 99, cb);
    case 4: return uv_fs_lchown(loop, req, "src/link.js", 99, 99, cb);
    case 5: return uv_fs_utime(loop, req, "main.js", 100, 200, cb);
    case 6: return uv_fs_futime(loop, req, fd, 100, 200, cb);
    case 7: return uv_fs_lutime(loop, req, "src/link.js", 100, 200, cb);
    default: return UV_EINVAL;
  }
}
static void metadata_done(uv_fs_t* req) {
  unsigned index = (unsigned) (uintptr_t) req->data;
  int expected = index == 8 ? UV_ECANCELED : UV_ENOTSUP;
  if (index > 8 || req->result != expected || req->fs_type != metadata_types[index % 8] ||
      (metadata_seen & (1u << index))) metadata_failed = 1;
  metadata_seen |= 1u << index;
  metadata_callbacks++;
  uv_fs_req_cleanup(req);
}
static int metadata_smoke(void) {
  uv_loop_t loop = {0};
  uv_fs_t req, async[9] = {0};
  vibeos_native_file_stat_t before, after;
  if (uv_loop_init(&loop) || vibeos_native_path_stat("main.js", 7, 1, &before)) return 250;
  int fd = uv_fs_open(&loop, &req, "main.js", O_RDONLY, 0, NULL);
  uv_fs_req_cleanup(&req);
  if (fd < 3) return 251;
  metadata_callbacks = metadata_seen = 0; metadata_failed = 0;
  for (unsigned i = 0; i < 8; i++) {
    if (metadata_call(i, &loop, &req, fd, NULL) != UV_ENOTSUP ||
        req.result != UV_ENOTSUP || req.fs_type != metadata_types[i]) return 252;
    uv_fs_req_cleanup(&req);
    async[i].data = (void*) (uintptr_t) i;
    if (metadata_call(i, &loop, &async[i], fd, metadata_done) || metadata_callbacks) return 253;
  }
  async[8].data = (void*) (uintptr_t) 8;
  if (metadata_call(0, &loop, &async[8], fd, metadata_done) ||
      uv_cancel((uv_req_t*) &async[8]) || uv_loop_close(&loop) != UV_EBUSY) return 254;
  if (uv_run(&loop, UV_RUN_DEFAULT) || metadata_failed || metadata_callbacks != 9 || metadata_seen != 511) return 255;
  if (vibeos_native_path_stat("main.js", 7, 1, &after) || memcmp(&before, &after, sizeof(before))) return 256;
  char content[sizeof(source)] = {0};
  uv_buf_t buffer = uv_buf_init(content, sizeof(content));
  if (uv_fs_read(&loop, &req, fd, &buffer, 1, 0, NULL) != sizeof(source)-1 || strcmp(content, source)) return 257;
  uv_fs_req_cleanup(&req);
  if (uv_fs_close(&loop, &req, fd, NULL)) return 258;
  uv_fs_req_cleanup(&req);
  if (uv_loop_close(&loop)) return 259;
  puts("UV METADATA unsupported=8 deferred=8 cancelled=1 unchanged=1 PASS");
  return 0;
}

static unsigned link_callbacks;
static void readlink_done(uv_fs_t* req) {
  if (req->result == 0 && req->ptr && !strcmp(req->ptr, "../main.js")) link_callbacks++;
  uv_fs_req_cleanup(req);
}
static unsigned cancelled;
static void cancel_done(uv_fs_t* req) {
  if (req->result == UV_ECANCELED) cancelled++;
  uv_fs_req_cleanup(req);
}
static unsigned unlinked;
static void unlink_done(uv_fs_t* req) {
  if (req->result == 0) unlinked++;
  uv_fs_req_cleanup(req);
}
static void closed(uv_fs_t* req) {
  struct files* s = req->loop->data;
  if (req->result) s->failed = 1;
  s->callbacks++;
  uv_fs_req_cleanup(req);
}

static void opened(uv_fs_t* req) {
  struct files* s = req->loop->data;
  uv_fs_t stat;
  s->callbacks++;
  if (req->result < 3) { s->failed = 1; uv_fs_req_cleanup(req); return; }
  s->fd = (int) req->result;
  uv_fs_req_cleanup(req);
  if (uv_fs_fstat(&s->loop, &stat, s->fd, NULL) ||
      stat.statbuf.st_size != sizeof(source) - 1 ||
      !S_ISREG(stat.statbuf.st_mode) || stat.statbuf.st_ino < 2 ||
      stat.statbuf.st_nlink != 1 || stat.ptr != &stat.statbuf) s->failed = 1;
  uv_fs_req_cleanup(&stat);
  vibeos_uv_probe_revoke_files();
  if (uv_fs_copyfile(NULL, &stat, "main.js", "revoked-copy", 0, NULL) != UV_EACCES) s->failed = 1;
  uv_fs_req_cleanup(&stat);
  if (uv_fs_statfs(NULL, &stat, "/", NULL) != UV_EACCES) s->failed = 1;
  uv_fs_req_cleanup(&stat);
  if (!s->failed) puts("UV COPY revoked=1 statfs_revoked=1 PASS");
  if (uv_fs_mkstemp(NULL, &stat, "revoked-temp-XXXXXX", NULL) != UV_EACCES ||
      strcmp(stat.path, "revoked-temp-XXXXXX")) s->failed = 1;
  uv_fs_req_cleanup(&stat);
  if (uv_fs_mkdtemp(NULL, &stat, "revoked-temp-XXXXXX", NULL) != UV_EACCES ||
      strcmp(stat.path, "revoked-temp-XXXXXX")) s->failed = 1;
  uv_fs_req_cleanup(&stat);
  if (!s->failed) puts("UV TEMP revoked=2 PASS");
  uv_dirent_t entry = { "untouched", UV_DIRENT_UNKNOWN };
  revoked_directory->dirents = &entry;
  revoked_directory->nentries = 1;
  if (uv_fs_readdir(NULL, &stat, revoked_directory, NULL) != UV_EACCES ||
      strcmp(entry.name, "untouched")) s->failed = 1;
  uv_fs_req_cleanup(&stat);
  if (uv_fs_closedir(NULL, &stat, revoked_directory, NULL)) s->failed = 1;
  uv_fs_req_cleanup(&stat);
  revoked_directory = NULL;
  if (!s->failed) puts("UV DIRECTORY revoked=1 close_after_revoke=1 PASS");
  if (uv_fs_fsync(NULL, &stat, s->fd, NULL) != UV_EACCES) s->failed = 1;
  uv_fs_req_cleanup(&stat);
  if (uv_fs_fdatasync(NULL, &stat, s->fd, NULL) != UV_EACCES) s->failed = 1;
  uv_fs_req_cleanup(&stat);
  if (uv_fs_link(NULL, &stat, "main.js", "revoked-hard", NULL) != UV_EACCES) s->failed = 1;
  uv_fs_req_cleanup(&stat);
  if (uv_fs_symlink(NULL, &stat, "main.js", "revoked-soft", 0, NULL) != UV_EACCES) s->failed = 1;
  uv_fs_req_cleanup(&stat);
  char cwd[16] = "untouched";
  size_t cwd_size = sizeof(cwd);
  if (uv_cwd(cwd, &cwd_size) != UV_EACCES || strcmp(cwd, "untouched") ||
      cwd_size != sizeof(cwd) || uv_chdir("/") != UV_EACCES) s->failed = 1;
  if (uv_fs_fstat(&s->loop, &stat, s->fd, NULL) != UV_EACCES) s->failed = 1;
  uv_fs_req_cleanup(&stat);
  /* Reuse the completed request, with a new deferred close callback. */
  if (uv_fs_close(&s->loop, req, s->fd, closed) || s->callbacks != 1)
    s->failed = 1;
}

static unsigned link_callbacks;
static int link_expected, link_failed;
static void link_done(uv_fs_t* req) {
  if (req->result != link_expected) link_failed = 1;
  link_callbacks++;
  uv_fs_req_cleanup(req);
}
static int link_smoke(void) {
  uv_loop_t loop = {0};
  uv_fs_t req;
  if (uv_loop_init(&loop)) return 220;
  int fd = uv_fs_open(&loop, &req, "link-origin", O_CREAT | O_EXCL | O_WRONLY, 0600, NULL);
  uv_fs_req_cleanup(&req);
  if (fd < 3) return 221;
  uv_buf_t data = uv_buf_init("abc", 3);
  if (uv_fs_write(&loop, &req, fd, &data, 1, -1, NULL) != 3) return 222;
  uv_fs_req_cleanup(&req);
  if (uv_fs_close(&loop, &req, fd, NULL)) return 223;
  uv_fs_req_cleanup(&req);
  if (uv_fs_link(&loop, &req, "link-origin", "link-hard", NULL)) return 224;
  uv_fs_req_cleanup(&req);
  if (uv_fs_stat(&loop, &req, "link-origin", NULL) || req.statbuf.st_nlink != 2) return 225;
  uint64_t inode = req.statbuf.st_ino;
  uv_fs_req_cleanup(&req);
  if (uv_fs_stat(&loop, &req, "link-hard", NULL) || req.statbuf.st_ino != inode || req.statbuf.st_size != 3) return 226;
  uv_fs_req_cleanup(&req);
  if (uv_fs_symlink(&loop, &req, "../link-origin", "src/new-link", 0, NULL)) return 227;
  uv_fs_req_cleanup(&req);
  if (uv_fs_readlink(&loop, &req, "src/new-link", NULL) || strcmp(req.ptr, "../link-origin")) return 228;
  uv_fs_req_cleanup(&req);
  if (uv_fs_stat(&loop, &req, "src/new-link", NULL) || req.statbuf.st_ino != inode) return 229;
  uv_fs_req_cleanup(&req);
  if (uv_fs_symlink(&loop, &req, "../../escape", "src/escape-link", 0, NULL) != UV_EACCES) return 230;
  uv_fs_req_cleanup(&req);
  if (uv_fs_link(&loop, &req, "link-origin", "../escape-hard", NULL) != UV_EACCES) return 231;
  uv_fs_req_cleanup(&req);
  if (uv_fs_link(&loop, &req, "link-origin", "link-hard", NULL) != UV_EEXIST) return 232;
  uv_fs_req_cleanup(&req);
  if (uv_fs_symlink(&loop, &req, "/link-origin", "absolute-link", 0, NULL) != UV_ENOTSUP) return 233;
  uv_fs_req_cleanup(&req);
  link_callbacks = 0; link_failed = 0; link_expected = 0;
  char target[] = "../link-origin", destination[] = "src/async-link";
  if (uv_fs_symlink(&loop, &req, target, destination, 0, link_done) || link_callbacks) return 234;
  memset(target, 'X', sizeof(target)); memset(destination, 'X', sizeof(destination));
  if (uv_run(&loop, UV_RUN_DEFAULT) || link_failed || link_callbacks != 1) return 235;
  if (uv_fs_readlink(&loop, &req, "src/async-link", NULL) || strcmp(req.ptr, "../link-origin")) return 236;
  uv_fs_req_cleanup(&req);
  if (uv_fs_link(&loop, &req, "link-origin", "async-hard", link_done) ||
      uv_run(&loop, UV_RUN_DEFAULT) || link_failed || link_callbacks != 2) return 237;
  link_expected = UV_ECANCELED;
  if (uv_fs_link(&loop, &req, "link-origin", "cancel-hard", link_done) ||
      uv_cancel((uv_req_t*) &req) || uv_run(&loop, UV_RUN_DEFAULT) || link_failed || link_callbacks != 3) return 238;
  if (uv_fs_lstat(&loop, &req, "cancel-hard", NULL) != UV_ENOENT) return 239;
  uv_fs_req_cleanup(&req);
  if (uv_fs_stat(&loop, &req, "async-hard", NULL) || req.statbuf.st_ino != inode || req.statbuf.st_nlink != 3) return 240;
  uv_fs_req_cleanup(&req);
  const char* paths[] = {"src/new-link", "src/async-link", "link-origin", "link-hard", "async-hard"};
  for (unsigned i = 0; i < 5; i++) {
    if (uv_fs_unlink(&loop, &req, paths[i], NULL)) return 241;
    uv_fs_req_cleanup(&req);
  }
  if (uv_loop_close(&loop)) return 242;
  puts("UV LINKS literal=1 inode=1 async=2 cancel=1 escape=1 PASS");
  return 0;
}

static int cwd_smoke(void) {
  uv_fs_t req;
  char cwd[32] = "untouched";
  size_t size = 1;
  if (uv_cwd(cwd, &size) != UV_ENOBUFS || size != 2 || strcmp(cwd, "untouched")) return 201;
  size = sizeof(cwd);
  if (uv_cwd(cwd, &size) || size != 1 || strcmp(cwd, "/") || uv_chdir("src")) return 202;
  size = sizeof(cwd);
  if (uv_cwd(cwd, &size) || size != 4 || strcmp(cwd, "/src")) return 203;
  if (uv_fs_stat(NULL, &req, "link.js", NULL) || req.statbuf.st_size != sizeof(source)-1) return 204;
  uv_fs_req_cleanup(&req);
  int fd = uv_fs_open(NULL, &req, "../main.js", O_RDONLY, 0, NULL);
  uv_fs_req_cleanup(&req);
  if (fd < 3 || uv_fs_close(NULL, &req, fd, NULL)) return 205;
  uv_fs_req_cleanup(&req);
  if (uv_chdir("link.js") != UV_ENOTDIR || uv_chdir("missing") != UV_ENOENT ||
      uv_chdir("../../") != UV_EACCES) return 206;
  size = sizeof(cwd);
  if (uv_cwd(cwd, &size) || strcmp(cwd, "/src")) return 207;
  fd = uv_fs_open(NULL, &req, "cwd-file", O_WRONLY | O_CREAT | O_EXCL, 0600, NULL);
  uv_fs_req_cleanup(&req);
  if (fd < 3 || uv_fs_close(NULL, &req, fd, NULL)) return 208;
  uv_fs_req_cleanup(&req);
  if (uv_fs_stat(NULL, &req, "/src/cwd-file", NULL)) return 209;
  uv_fs_req_cleanup(&req);
  if (uv_fs_unlink(NULL, &req, "cwd-file", NULL)) return 210;
  uv_fs_req_cleanup(&req);
  if (uv_chdir("..") || uv_fs_mkdir(NULL, &req, "cwd-original", 0700, NULL)) return 211;
  uv_fs_req_cleanup(&req);
  if (uv_chdir("cwd-original") ||
      uv_fs_rename(NULL, &req, "/cwd-original", "/cwd-moved", NULL)) return 212;
  uv_fs_req_cleanup(&req);
  if (uv_fs_mkdir(NULL, &req, "/cwd-original", 0700, NULL)) return 213;
  uv_fs_req_cleanup(&req);
  size = sizeof(cwd);
  if (uv_cwd(cwd, &size) != UV_ENOENT || uv_chdir(".") != UV_ENOENT || uv_chdir("/")) return 214;
  if (uv_fs_rmdir(NULL, &req, "cwd-original", NULL)) return 215;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rmdir(NULL, &req, "cwd-moved", NULL)) return 216;
  uv_fs_req_cleanup(&req);
  puts("UV CWD root=1 relative=1 short=1 escape=1 identity=1 PASS");
  return 0;
}

int vibeos_uv_file_smoke(void) {
  int open_status = mutating_open_smoke();
  if (open_status) return open_status;
  int copy_status = copy_smoke();
  if (copy_status) return copy_status;
  int temporary_status = temporary_smoke();
  if (temporary_status) return temporary_status;
  int directory_status = directory_smoke();
  if (directory_status) return directory_status;
  int sync_status = sync_smoke();
  if (sync_status) return sync_status;
  int metadata_status = metadata_smoke();
  if (metadata_status) return metadata_status;
  int link_status = link_smoke();
  if (link_status) return link_status;
  int cwd_status = cwd_smoke();
  if (cwd_status) return cwd_status;
  struct files s;
  uv_fs_t req;
  char bytes[64] = {0};
  uv_buf_t buffer = {bytes, sizeof(bytes)};
  memset(&s, 0, sizeof(s));
  s.loop.data = &s;
  if (uv_loop_init(&s.loop)) return 1;
  struct stat native_stat;
  if (stat("/src/link.js", &native_stat) || !S_ISREG(native_stat.st_mode) ||
      native_stat.st_size != sizeof(source) - 1) return 20;
  if (stat("/", &native_stat) || !S_ISDIR(native_stat.st_mode)) return 21;
  unsigned char saved_stat[sizeof(native_stat)];
  memcpy(saved_stat, &native_stat, sizeof(native_stat));
  if (stat("../main.js", &native_stat) != -1 || errno != EACCES ||
      memcmp(&native_stat, saved_stat, sizeof(native_stat))) return 22;
  if (stat("loop", &native_stat) != -1 || errno != ELOOP) return 23;
  if (stat("missing", &native_stat) != -1 || errno != ENOENT) return 24;
  if (link("main.js", "copy.js") != -1 || errno != ENOTSUP) return 25;
  if (stat("copy.js", &native_stat) != -1 || errno != ENOENT) return 26;
  if (sleep(0)) return 27;
  uint64_t sleep_start = uv_hrtime();
  if (sleep(1) || uv_hrtime() - sleep_start < 1000000000) return 28;
  if (uv_fs_unlink(&s.loop, &req, "delete-sync", NULL)) return 30;
  uv_fs_req_cleanup(&req);
  if (stat("delete-sync", &native_stat) != -1 || errno != ENOENT) return 31;
  if (uv_fs_unlink(&s.loop, &req, "../main.js", NULL) != UV_EACCES) return 32;
  uv_fs_req_cleanup(&req);
  if (uv_fs_unlink(&s.loop, &req, "src", NULL) != UV_EISDIR) return 33;
  uv_fs_req_cleanup(&req);
  cancelled = 0;
  if (uv_fs_unlink(&s.loop, &req, "main.js", cancel_done) ||
      uv_cancel((uv_req_t*) &req) || cancelled ||
      uv_cancel((uv_req_t*) &req) != UV_EBUSY ||
      uv_loop_close(&s.loop) != UV_EBUSY) return 38;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || cancelled != 1 ||
      uv_cancel((uv_req_t*) &req) != UV_EBUSY) return 39;
  if (stat("main.js", &native_stat) || native_stat.st_size != sizeof(source) - 1)
    return 40;
  puts("UV CANCEL queued=1 callback=1 file_preserved=1 PASS");
  unsigned char short_target[3] = {0xa5, 0xa5, 0xa5};
  if (vibeos_native_readlink("src/link.js", 11, short_target, sizeof(short_target)) != -10 ||
      short_target[0] != 0xa5 || short_target[1] != 0xa5 || short_target[2] != 0xa5)
    return 41;
  if (uv_fs_readlink(&s.loop, &req, "loop", NULL) || strcmp(req.ptr, "loop")) return 42;
  uv_fs_req_cleanup(&req);
  if (uv_fs_readlink(&s.loop, &req, "main.js", NULL) != UV_EINVAL) return 43;
  uv_fs_req_cleanup(&req);
  if (uv_fs_readlink(&s.loop, &req, "../src/link.js", NULL) != UV_EACCES) return 44;
  uv_fs_req_cleanup(&req);
  link_callbacks = 0;
  if (uv_fs_readlink(&s.loop, &req, "src/link.js", readlink_done) || link_callbacks)
    return 45;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || link_callbacks != 1) return 46;
  if (uv_fs_access(&s.loop, &req, "src/link.js", R_OK | W_OK, NULL)) return 48;
  uv_fs_req_cleanup(&req);
  if (uv_fs_access(&s.loop, &req, "missing", F_OK, NULL) != UV_ENOENT) return 49;
  uv_fs_req_cleanup(&req);
  if (uv_fs_access(&s.loop, &req, "../main.js", F_OK, NULL) != UV_EACCES) return 50;
  uv_fs_req_cleanup(&req);
  if (uv_fs_access(&s.loop, &req, "main.js", X_OK, NULL) != UV_ENOTSUP) return 51;
  uv_fs_req_cleanup(&req);
  if (uv_fs_access(&s.loop, &req, "main.js", 8, NULL) != UV_EINVAL) return 52;
  uv_fs_req_cleanup(&req);
  access_callbacks = 0;
  if (uv_fs_access(&s.loop, &req, "main.js", R_OK, access_done) || access_callbacks)
    return 53;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || access_callbacks != 1) return 54;
  unlinked = 0;
  if (uv_fs_unlink(&s.loop, &req, "delete-async", unlink_done) || unlinked ||
      uv_loop_close(&s.loop) != UV_EBUSY) return 34;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || unlinked != 1) return 35;
  if (stat("delete-async", &native_stat) != -1 || errno != ENOENT) return 36;
  int created = uv_fs_open(&s.loop, &req, "generated.js", O_RDWR | O_CREAT | O_EXCL, 0644, NULL);
  if (created < 3) return 114;
  uv_fs_req_cleanup(&req);
  uv_buf_t generated = uv_buf_init("console.log(42);", 16);
  if (uv_fs_write(&s.loop, &req, created, &generated, 1, -1, NULL) != 16) return 115;
  uv_fs_req_cleanup(&req);
  if (uv_fs_open(&s.loop, &req, "generated.js", O_WRONLY | O_CREAT | O_EXCL, 0644, NULL) != UV_EEXIST) return 116;
  uv_fs_req_cleanup(&req);
  if (uv_fs_open(&s.loop, &req, "src/link.js", O_WRONLY | O_CREAT | O_EXCL, 0644, NULL) != UV_EEXIST) return 117;
  uv_fs_req_cleanup(&req);
  if (uv_fs_open(&s.loop, &req, "../generated.js", O_WRONLY | O_CREAT, 0644, NULL) != UV_EACCES) return 118;
  uv_fs_req_cleanup(&req);
  if (_open("generated.js", O_WRONLY | O_CREAT | O_EXCL, 0644) != -1 || errno != EEXIST) return 131;
  int appender = uv_fs_open(&s.loop, &req, "generated.js", O_WRONLY | O_APPEND, 0, NULL);
  if (appender < 3) return 119;
  uv_fs_req_cleanup(&req);
  if (vibeos_native_file_seek(appender, 0, SEEK_SET)) return 120;
  uv_buf_t newline = uv_buf_init("\n", 1);
  if (uv_fs_write(&s.loop, &req, appender, &newline, 1, -1, NULL) != 1) return 121;
  uv_fs_req_cleanup(&req);
  if (uv_fs_close(&s.loop, &req, appender, NULL)) return 122;
  uv_fs_req_cleanup(&req);
  if (vibeos_native_file_seek(created, 0, SEEK_SET)) return 123;
  if (uv_fs_read(&s.loop, &req, created, &buffer, 1, -1, NULL) != 17 || memcmp(bytes, "console.log(42);\n", 17)) return 124;
  uv_fs_req_cleanup(&req);
  int truncated = uv_fs_open(&s.loop, &req, "generated.js", O_WRONLY | O_TRUNC, 0, NULL);
  if (truncated < 3) return 125;
  uv_fs_req_cleanup(&req);
  if (uv_fs_close(&s.loop, &req, truncated, NULL)) return 126;
  uv_fs_req_cleanup(&req);
  if (uv_fs_fstat(&s.loop, &req, created, NULL) || req.statbuf.st_size) return 127;
  uv_fs_req_cleanup(&req);
  if (uv_fs_close(&s.loop, &req, created, NULL)) return 128;
  uv_fs_req_cleanup(&req);
  if (uv_fs_unlink(&s.loop, &req, "generated.js", NULL)) return 129;
  uv_fs_req_cleanup(&req);
  int writable = uv_fs_open(&s.loop, &req, "write-test", O_RDWR, 0, NULL);
  if (writable < 3) return 92;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rename(&s.loop, &req, "write-test", "write-renamed", NULL)) return 93;
  uv_fs_req_cleanup(&req);
  if (vibeos_native_file_seek(writable, 2, SEEK_SET) != 2) return 94;
  uv_buf_t edit = uv_buf_init("XY", 2);
  if (uv_fs_write(&s.loop, &req, writable, &edit, 1, -1, NULL) != 2) return 95;
  uv_fs_req_cleanup(&req);
  if (vibeos_native_file_seek(writable, 0, SEEK_SET)) return 96;
  if (uv_fs_read(&s.loop, &req, writable, &buffer, 1, -1, NULL) != 6 || memcmp(bytes, "abXYef", 6)) return 97;
  uv_fs_req_cleanup(&req);
  if (uv_fs_ftruncate(&s.loop, &req, writable, 2, NULL)) return 98;
  uv_fs_req_cleanup(&req);
  if (uv_fs_ftruncate(&s.loop, &req, writable, 5, NULL)) return 99;
  uv_fs_req_cleanup(&req);
  if (uv_fs_fstat(&s.loop, &req, writable, NULL) || req.statbuf.st_size != 5) return 100;
  uv_fs_req_cleanup(&req);
  if (vibeos_native_file_seek(writable, 0, SEEK_SET)) return 101;
  if (uv_fs_read(&s.loop, &req, writable, &buffer, 1, -1, NULL) != 5 || memcmp(bytes, "ab\0\0\0", 5)) return 102;
  uv_fs_req_cleanup(&req);
  write_callbacks = truncate_callbacks = 0;
  if (vibeos_native_file_seek(writable, 2, SEEK_SET) != 2) return 132;
  if (uv_fs_write(&s.loop, &req, writable, &edit, 1, -1, write_done) || write_callbacks) return 133;
  if (uv_loop_close(&s.loop) != UV_EBUSY) return 134;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || write_callbacks != 1) return 135;
  unsigned cancelled_before = cancelled;
  if (uv_fs_write(&s.loop, &req, writable, &edit, 1, -1, cancel_done) ||
      uv_cancel((uv_req_t*) &req) || cancelled != cancelled_before) return 136;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || cancelled != cancelled_before + 1) return 137;
  if (vibeos_native_file_seek(writable, 0, SEEK_SET)) return 138;
  if (uv_fs_read(&s.loop, &req, writable, &buffer, 1, -1, NULL) != 5 || memcmp(bytes, "abXY\0", 5)) return 139;
  uv_fs_req_cleanup(&req);
  if (uv_fs_ftruncate(&s.loop, &req, writable, 0, cancel_done) || uv_cancel((uv_req_t*) &req)) return 140;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || cancelled != cancelled_before + 2) return 141;
  if (uv_fs_fstat(&s.loop, &req, writable, NULL) || req.statbuf.st_size != 5) return 142;
  uv_fs_req_cleanup(&req);
  if (uv_fs_ftruncate(&s.loop, &req, writable, 3, truncate_done) || truncate_callbacks) return 143;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || truncate_callbacks != 1) return 144;
  if (uv_fs_fstat(&s.loop, &req, writable, NULL) || req.statbuf.st_size != 3) return 145;
  uv_fs_req_cleanup(&req);
  read_callbacks = 0;
  expected_read = 3;
  memset(bytes, 0xa5, sizeof(bytes));
  if (vibeos_native_file_seek(writable, 0, SEEK_SET)) return 146;
  if (uv_fs_read(&s.loop, &req, writable, &buffer, 1, -1, read_done) || read_callbacks ||
      (unsigned char) bytes[0] != 0xa5) return 147;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || read_callbacks != 1 || memcmp(bytes, "abX", 3)) return 148;
  expected_read = 0;
  if (uv_fs_read(&s.loop, &req, writable, &buffer, 1, -1, read_done) || read_callbacks != 1) return 149;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || read_callbacks != 2) return 150;
  if (vibeos_native_file_seek(writable, 0, SEEK_SET)) return 151;
  memset(bytes, 0xa5, sizeof(bytes));
  unsigned read_cancelled_before = cancelled;
  if (uv_fs_read(&s.loop, &req, writable, &buffer, 1, -1, cancel_done) || uv_cancel((uv_req_t*) &req)) return 152;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || cancelled != read_cancelled_before + 1 ||
      (unsigned char) bytes[0] != 0xa5 || vibeos_native_file_seek(writable, 0, SEEK_CUR)) return 153;
  int64_t native_read = vibeos_native_file_read_begin(writable, 3);
  if (native_read <= 0 || vibeos_native_file_read_poll(native_read, bytes, 1) != -9 ||
      (unsigned char) bytes[0] != 0xa5) return 154;
  if (vibeos_native_file_read_poll(native_read, bytes, sizeof(bytes)) != 3 || memcmp(bytes, "abX", 3) ||
      vibeos_native_file_read_poll(native_read, bytes, sizeof(bytes)) != -1) return 155;
  uv_buf_t positioned = uv_buf_init(bytes, 2);
  if (vibeos_native_file_seek(writable, 0, SEEK_CUR) != 3) return 160;
  if (uv_fs_read(&s.loop, &req, writable, &positioned, 1, 1, NULL) != 2 || memcmp(bytes, "bX", 2)) return 161;
  uv_fs_req_cleanup(&req);
  uv_buf_t replacement = uv_buf_init("YZ", 2);
  if (uv_fs_write(&s.loop, &req, writable, &replacement, 1, 1, NULL) != 2 ||
      vibeos_native_file_seek(writable, 0, SEEK_CUR) != 3) return 162;
  uv_fs_req_cleanup(&req);
  unsigned writes_before = write_callbacks;
  if (uv_fs_write(&s.loop, &req, writable, &edit, 1, 0, write_done) || write_callbacks != writes_before) return 163;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || write_callbacks != writes_before + 1 ||
      vibeos_native_file_seek(writable, 0, SEEK_CUR) != 3) return 164;
  expected_read = 2;
  unsigned reads_before = read_callbacks;
  if (uv_fs_read(&s.loop, &req, writable, &positioned, 1, 1, read_done) || read_callbacks != reads_before) return 165;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || read_callbacks != reads_before + 1 || memcmp(bytes, "YZ", 2) ||
      vibeos_native_file_seek(writable, 0, SEEK_CUR) != 3) return 166;
  if (uv_fs_read(&s.loop, &req, writable, &positioned, 1, -2, NULL) != UV_EINVAL) return 167;
  uv_fs_req_cleanup(&req);
  if (uv_fs_write(&s.loop, &req, writable, &edit, 1, INT64_MAX, NULL) != UV_EINVAL) return 168;
  uv_fs_req_cleanup(&req);
  if (uv_fs_read(&s.loop, &req, 0, &positioned, 1, 0, NULL) != UV_ESPIPE) return 169;
  uv_fs_req_cleanup(&req);
  if (uv_fs_fstat(&s.loop, &req, writable, NULL) || req.statbuf.st_size != 3) return 170;
  uv_fs_req_cleanup(&req);
  if (uv_fs_close(&s.loop, &req, writable, NULL)) return 103;
  uv_fs_req_cleanup(&req);
  int readonly_fd = uv_fs_open(&s.loop, &req, "write-renamed", O_RDONLY, 0, NULL);
  if (readonly_fd < 3) return 104;
  uv_fs_req_cleanup(&req);
  if (uv_fs_write(&s.loop, &req, readonly_fd, &edit, 1, -1, NULL) != UV_EBADF) return 105;
  uv_fs_req_cleanup(&req);
  if (uv_fs_ftruncate(&s.loop, &req, readonly_fd, 0, NULL) != UV_EBADF) return 106;
  uv_fs_req_cleanup(&req);
  if (uv_fs_close(&s.loop, &req, readonly_fd, NULL)) return 107;
  uv_fs_req_cleanup(&req);
  if (uv_fs_unlink(&s.loop, &req, "write-renamed", NULL)) return 108;
  uv_fs_req_cleanup(&req);
  /* Mutations return to the original fixture before directory enumeration. */
  if (uv_fs_mkdir(&s.loop, &req, "out", 0755, NULL)) return 67;
  uv_fs_req_cleanup(&req);
  if (uv_fs_mkdir(&s.loop, &req, "out", 0755, NULL) != UV_EEXIST) return 68;
  uv_fs_req_cleanup(&req);
  if (uv_fs_mkdir(&s.loop, &req, "../out", 0755, NULL) != UV_EACCES) return 69;
  uv_fs_req_cleanup(&req);
  if (uv_fs_mkdir(&s.loop, &req, "out/child", 0700, NULL)) return 70;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rmdir(&s.loop, &req, "out", NULL) != UV_ENOTEMPTY) return 71;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rmdir(&s.loop, &req, "main.js", NULL) != UV_ENOTDIR) return 72;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rmdir(&s.loop, &req, "src/link.js", NULL) != UV_ENOTDIR) return 73;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rename(&s.loop, &req, "main.js", "out", NULL) != UV_EISDIR) return 74;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rename(&s.loop, &req, "out", "main.js", NULL) != UV_ENOTDIR) return 75;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rename(&s.loop, &req, "out", "../out", NULL) != UV_EACCES) return 76;
  uv_fs_req_cleanup(&req);
  tree_callbacks = 0;
  if (uv_fs_rename(&s.loop, &req, "out", "renamed", tree_done) || tree_callbacks) return 77;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || tree_callbacks != 1) return 78;
  if (uv_fs_stat(&s.loop, &req, "out", NULL) != UV_ENOENT) return 79;
  uv_fs_req_cleanup(&req);
  if (uv_fs_stat(&s.loop, &req, "renamed/child", NULL) || !S_ISDIR(req.statbuf.st_mode)) return 80;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rmdir(&s.loop, &req, "renamed/child", tree_done) || tree_callbacks != 1) return 81;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || tree_callbacks != 2) return 82;
  if (uv_fs_rmdir(&s.loop, &req, "renamed", NULL)) return 83;
  uv_fs_req_cleanup(&req);
  if (uv_fs_mkdir(&s.loop, &req, "temporary", 0755, tree_done) || tree_callbacks != 2) return 84;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || tree_callbacks != 3) return 85;
  if (uv_fs_rmdir(&s.loop, &req, "temporary", NULL)) return 86;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rename(&s.loop, &req, "main.js", "moved.js", NULL)) return 87;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rename(&s.loop, &req, "moved.js", "main.js", NULL)) return 88;
  uv_fs_req_cleanup(&req);
  uv_dirent_t entry;
  if (uv_fs_scandir(&s.loop, &req, "/", 0, NULL) != 3) return 56;
  const char* names[] = {"loop", "main.js", "src"};
  uv_dirent_type_t types[] = {UV_DIRENT_LINK, UV_DIRENT_FILE, UV_DIRENT_DIR};
  for (unsigned i = 0; i < 3; ++i)
    if (uv_fs_scandir_next(&req, &entry) || strcmp(entry.name, names[i]) ||
        entry.type != types[i]) return 57;
  if (uv_fs_scandir_next(&req, &entry) != UV_EOF ||
      uv_fs_scandir_next(&req, &entry) != UV_EOF) return 58;
  uv_fs_req_cleanup(&req);
  /* Partial iteration must release both visited and unvisited records. */
  if (uv_fs_scandir(&s.loop, &req, "/", 0, NULL) != 3 ||
      uv_fs_scandir_next(&req, &entry)) return 59;
  uv_fs_req_cleanup(&req);
  uv_fs_req_cleanup(&req);
  if (uv_fs_scandir(&s.loop, &req, "main.js", 0, NULL) != UV_ENOTDIR) return 60;
  uv_fs_req_cleanup(&req);
  if (uv_fs_scandir(&s.loop, &req, "../", 0, NULL) != UV_EACCES) return 61;
  uv_fs_req_cleanup(&req);
  if (uv_fs_scandir(&s.loop, &req, "missing", 0, NULL) != UV_ENOENT) return 62;
  uv_fs_req_cleanup(&req);
  if (uv_fs_scandir(&s.loop, &req, "src", 1, NULL) != UV_EINVAL) return 63;
  uv_fs_req_cleanup(&req);
  scan_callbacks = 0;
  if (uv_fs_scandir(&s.loop, &req, "src", 0, scan_done) || scan_callbacks) return 64;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || scan_callbacks != 1) return 65;
  if (uv_fs_stat(&s.loop, &req, "/", NULL) || !S_ISDIR(req.statbuf.st_mode)) return 14;
  uv_fs_req_cleanup(&req);
  if (uv_fs_lstat(&s.loop, &req, "src/link.js", NULL) || !S_ISLNK(req.statbuf.st_mode)) return 15;
  uv_fs_req_cleanup(&req);
  if (uv_fs_stat(&s.loop, &req, "src/link.js", NULL) || !S_ISREG(req.statbuf.st_mode) ||
      req.statbuf.st_size != sizeof(source) - 1) return 16;
  uv_fs_req_cleanup(&req);
  if (uv_fs_realpath(&s.loop, &req, "./src/link.js", NULL) ||
      strcmp(req.ptr, "/main.js")) return 17;
  uv_fs_req_cleanup(&req);
  if (uv_fs_realpath(&s.loop, &req, "../main.js", NULL) != UV_EACCES) return 18;
  uv_fs_req_cleanup(&req);
  if (uv_fs_realpath(&s.loop, &req, "loop", NULL) != UV_ELOOP) return 19;
  uv_fs_req_cleanup(&req);
  if (uv_fs_open(&s.loop, &req, "../main.js", O_RDONLY, 0, NULL) != UV_EACCES) return 2;
  uv_fs_req_cleanup(&req);
  if (uv_fs_open(&s.loop, &req, "missing", O_RDONLY, 0, NULL) != UV_ENOENT) return 3;
  uv_fs_req_cleanup(&req);
  if (uv_fs_open(&s.loop, &req, "main.js", O_WRONLY | O_NONBLOCK, 0, NULL) != UV_ENOTSUP) return 4;
  uv_fs_req_cleanup(&req);
  int fd = uv_fs_open(&s.loop, &req, "/src/link.js", O_RDONLY, 0, NULL);
  if (fd < 3 || uv_guess_handle(fd) != UV_FILE) return 5;
  uv_fs_req_cleanup(&req);
  if (uv_fs_read(&s.loop, &req, fd, &buffer, 1, -1, NULL) != sizeof(source) - 1 ||
      memcmp(bytes, source, sizeof(source) - 1)) return 6;
  uv_fs_req_cleanup(&req);
  if (uv_fs_close(&s.loop, &req, fd, NULL)) return 7;
  uv_fs_req_cleanup(&req);
  if (uv_fs_fstat(&s.loop, &req, fd, NULL) != UV_EBADF || uv_guess_handle(fd) != UV_UNKNOWN_HANDLE) return 8;
  uv_fs_req_cleanup(&req);
  int revoke_writer = uv_fs_open(&s.loop, &req, "main.js", O_WRONLY, 0, NULL);
  if (revoke_writer < 3) return 109;
  uv_fs_req_cleanup(&req);
  if (uv_fs_read(&s.loop, &req, revoke_writer, &buffer, 1, -1, NULL) != UV_EBADF) return 110;
  uv_fs_req_cleanup(&req);
  int revoke_reader = uv_fs_open(&s.loop, &req, "main.js", O_RDONLY, 0, NULL);
  if (revoke_reader < 3) return 156;
  uv_fs_req_cleanup(&req);
  int64_t revoked_read = vibeos_native_file_read_begin(revoke_reader, 8);
  if (revoked_read <= 0) return 157;
  if (uv_fs_open(&s.loop, &s.request, "main.js", O_RDONLY, 0, opened) ||
      s.callbacks != 0 || uv_loop_close(&s.loop) != UV_EBUSY) return 9;
  if (uv_run(&s.loop, UV_RUN_DEFAULT) || s.failed || s.callbacks != 2) return 10;
  if (uv_fs_open(&s.loop, &req, "main.js", O_RDONLY, 0, NULL) != UV_EACCES) return 11;
  uv_fs_req_cleanup(&req);
  if (stat("main.js", &native_stat) != -1 || errno != EACCES) return 29;
  if (uv_fs_unlink(&s.loop, &req, "main.js", NULL) != UV_EACCES) return 37;
  uv_fs_req_cleanup(&req);
  if (uv_fs_readlink(&s.loop, &req, "src/link.js", NULL) != UV_EACCES) return 47;
  uv_fs_req_cleanup(&req);
  if (uv_fs_access(&s.loop, &req, "main.js", F_OK, NULL) != UV_EACCES) return 55;
  uv_fs_req_cleanup(&req);
  if (uv_fs_scandir(&s.loop, &req, "/", 0, NULL) != UV_EACCES) return 66;
  uv_fs_req_cleanup(&req);
  if (uv_fs_mkdir(&s.loop, &req, "forbidden", 0755, NULL) != UV_EACCES) return 89;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rmdir(&s.loop, &req, "src", NULL) != UV_EACCES) return 90;
  uv_fs_req_cleanup(&req);
  if (uv_fs_rename(&s.loop, &req, "main.js", "forbidden", NULL) != UV_EACCES) return 91;
  uv_fs_req_cleanup(&req);
  if (uv_fs_write(&s.loop, &req, revoke_writer, &edit, 1, -1, NULL) != UV_EACCES) return 111;
  uv_fs_req_cleanup(&req);
  if (uv_fs_ftruncate(&s.loop, &req, revoke_writer, 0, NULL) != UV_EACCES) return 112;
  uv_fs_req_cleanup(&req);
  if (uv_fs_close(&s.loop, &req, revoke_writer, NULL)) return 113;
  uv_fs_req_cleanup(&req);
  if (uv_fs_open(&s.loop, &req, "denied-create", O_WRONLY | O_CREAT, 0644, NULL) != UV_EACCES) return 130;
  uv_fs_req_cleanup(&req);
  memset(bytes, 0xa5, sizeof(bytes));
  if (vibeos_native_file_read_poll(revoked_read, bytes, sizeof(bytes)) != -3 ||
      (unsigned char) bytes[0] != 0xa5 ||
      vibeos_native_file_read_poll(revoked_read, bytes, sizeof(bytes)) != -1) return 158;
  if (uv_fs_close(&s.loop, &req, revoke_reader, NULL)) return 159;
  uv_fs_req_cleanup(&req);
  if (uv_loop_close(&s.loop)) return 12;
  puts("UV POSITIONED sync=2 async=2 cursor=1 invalid=1 pipe=1 PASS");
  puts("UV ASYNC READ bytes=3 eof=1 cancel=1 retry=1 revoked_delivery=1 PASS");
  puts("UV ASYNC FILE write=1 truncate=1 deferred=1 cancelled=2 content=1 PASS");
  puts("UV CREATE content=1 exclusive=1 append=1 truncate=1 revoked=1 PASS");
  puts("UV WRITE identity=1 content=1 truncate=1 modes=1 revoked=1 PASS");
  puts("UV TREE mkdir=1 rename=1 rmdir=1 async=3 types=1 revoked=1 PASS");
  puts("UV SCANDIR types=3 sorted=1 cleanup=1 async=1 revoked=1 PASS");
  puts("UV ACCESS read_write=1 missing=1 escape=1 async=1 revoked=1 PASS");
  puts("UV READLINK literal=1 short_buffer=1 async=1 escape=1 revoked=1 PASS");
  puts("UV UNLINK sync=1 async=1 escape=1 directory=1 revoked=1 PASS");
  puts("NATIVE LIBC stat=1 escape=1 revoked=1 link_denied=1 sleep=1 PASS");
  puts("UV FILE open=1 read=1 stat=1 close=1 revoked=1 callbacks=2 PASS");
  puts("UV PATH stat=1 lstat=1 realpath=1 symlink=1 escape=1 loop=1 PASS");
  return 0;
}
