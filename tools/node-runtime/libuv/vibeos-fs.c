/* Capability-backed libuv IO requests. No worker thread or ambient fd table. */
#include "uv.h"
#include "uv-common.h"
#include "vibeos-stdio.h"
#include "vibeos-files.h"
#include "vibeos-entropy.h"
#include <sys/stat.h>
#include "vibeos-requests.h"
#include <limits.h>
#include <stdlib.h>

static ssize_t result(ptrdiff_t value) {
  if (value >= 0) return value;
  switch (value) {
    case -1: return UV_EBADF;
    case -2: return UV_EFAULT;
    case -3: return UV_EACCES;
    case -4: return UV_EPIPE;
    case -6: return UV_ENOENT;
    case -7: return UV_EISDIR;
    case -8: return UV_EBUSY;
    case -9: return UV_EINVAL;
    case -10: return UV_ENAMETOOLONG;
    case -11: return UV_ENOTDIR;
    case -12: return UV_ELOOP;
    case -13: return UV_ENOTSUP;
    case -14: return UV_EMFILE;
    case -15: return UV_EAGAIN;
    case -16: return UV_ENOMEM;
    case -17: return UV_EEXIST;
    case -18: return UV_ENOTEMPTY;
    default: return UV_EIO;
  }
}

int uv_chdir(const char* directory) {
  if (!directory) return UV_EINVAL;
  size_t length = strnlen(directory, 4097);
  if (length > 4096) return UV_ENAMETOOLONG;
  return (int) result(vibeos_native_chdir(directory, length));
}

int uv_cwd(char* buffer, size_t* size) {
  if (!buffer || !size || !*size) return UV_EINVAL;
  ptrdiff_t length = vibeos_native_getcwd(NULL, 0);
  if (length < 0) return (int) result(length);
  if (*size <= (size_t) length) {
    *size = (size_t) length + 1;
    return UV_ENOBUFS;
  }
  length = vibeos_native_getcwd(buffer, *size);
  if (length < 0) return (int) result(length);
  *size = (size_t) length;
  return 0;
}

static void io_work(struct uv__work* work) {
  uv_fs_t* req = container_of(work, uv_fs_t, work_req);
  unsigned i;
  req->result = 0;
  for (i = 0; i < req->nbufs; ++i) {
    if (req->bufs[i].len == 0) continue;
    if (req->file >= 3) {
      /* Keep the requested offset separate from the pending native ID. */
      if (req->statbuf.st_size == 0) {
        int64_t id = req->fs_type == UV_FS_READ
            ? vibeos_native_file_read_begin_at(req->file, req->bufs[i].len, req->off)
            : vibeos_native_file_write_begin_at(req->file, req->bufs[i].base, req->bufs[i].len, req->off);
        if (id < 0) { req->result = result(id); break; }
        req->statbuf.st_size = (uint64_t) id;
      }
      req->result = result(req->fs_type == UV_FS_READ
          ? vibeos_native_file_read_poll(req->statbuf.st_size, req->bufs[i].base, req->bufs[i].len)
          : vibeos_native_mutation_poll(req->statbuf.st_size));
    } else {
      req->result = result(req->fs_type == UV_FS_READ
          ? vibeos_native_try_read(req->file, req->bufs[i].base, req->bufs[i].len)
          : vibeos_native_try_write(req->file, req->bufs[i].base, req->bufs[i].len));
    }
    break; /* A short read is a valid libuv result. */
  }
}

static void io_queued(struct uv__work* work) {
  work->work = io_work; /* Once polled, the backend operation owns completion. */
  io_work(work);
}

static void io_done(struct uv__work* work, int status) {
  uv_fs_t* req = container_of(work, uv_fs_t, work_req);
  if (status != 0) req->result = status;
  req->cb(req);
}

static int fs_io(uv_fs_type type, uv_loop_t* loop, uv_fs_t* req, uv_file fd,
               const uv_buf_t bufs[], unsigned int nbufs,
               int64_t offset, uv_fs_cb cb) {
  unsigned i;
  if (!req) return UV_EINVAL;
  req->fs_type = type;
  req->type = UV_FS;
  req->loop = loop;
  req->cb = cb;
  req->path = NULL;
  req->new_path = NULL;
  req->ptr = NULL;
  req->bufs = NULL;
  req->nbufs = 0;
  req->work_req.loop = NULL;
  req->off = 0;
  req->result = UV_EINVAL;
  if (!bufs || nbufs == 0 || (cb && !loop)) return UV_EINVAL;
  if (offset < -1) return UV_EINVAL;
  if (offset >= 0 && fd >= 0 && fd < 3) { req->result = UV_ESPIPE; return UV_ESPIPE; }
  req->statbuf.st_size = 0;
  for (i = 0; i < nbufs; ++i)
    if ((!bufs[i].base && bufs[i].len) || bufs[i].len > __PTRDIFF_MAX__)
      return UV_EINVAL;
  if (nbufs > SIZE_MAX / sizeof(*bufs)) return UV_EINVAL;
  req->bufs = nbufs <= ARRAY_SIZE(req->bufsml) ? req->bufsml :
              uv__malloc(nbufs * sizeof(*bufs));
  if (!req->bufs) { req->result = UV_ENOMEM; return UV_ENOMEM; }
  memcpy(req->bufs, bufs, nbufs * sizeof(*bufs));
  req->nbufs = nbufs;
  req->file = fd;
  req->off = offset;
  req->result = 0;
  if (!cb) {
    for (i = 0; i < nbufs; ++i) {
      if (bufs[i].len == 0) continue;
      if (fd >= 3) {
        req->result = result(type == UV_FS_READ
            ? vibeos_native_file_read_at(fd, bufs[i].base, bufs[i].len, offset)
            : vibeos_native_file_write_at(fd, bufs[i].base, bufs[i].len, offset));
      } else {
        req->result = result(type == UV_FS_READ
            ? vibeos_native_read(fd, bufs[i].base, bufs[i].len)
            : vibeos_native_write(fd, bufs[i].base, bufs[i].len));
      }
      break;
    }
    return (int) req->result;
  }
  req->result = UV_EAGAIN;
  req->work_req.loop = loop;
  req->work_req.work = io_queued;
  req->work_req.done = io_done;
  uv__req_register(loop);
  uv__queue_insert_tail(&loop->wq, &req->work_req.wq);
  return 0;
}

int uv_fs_read(uv_loop_t* loop, uv_fs_t* req, uv_file fd,
               const uv_buf_t bufs[], unsigned int nbufs,
               int64_t offset, uv_fs_cb cb) {
  return fs_io(UV_FS_READ, loop, req, fd, bufs, nbufs, offset, cb);
}

int uv_fs_write(uv_loop_t* loop, uv_fs_t* req, uv_file fd,
                const uv_buf_t bufs[], unsigned int nbufs,
                int64_t offset, uv_fs_cb cb) {
  return fs_io(UV_FS_WRITE, loop, req, fd, bufs, nbufs, offset, cb);
}

static int control_init(uv_loop_t* loop, uv_fs_t* req, uv_fs_type type,
                        uv_fs_cb cb) {
  if (!req) return UV_EINVAL;
  req->type = UV_FS;
  req->fs_type = type;
  req->loop = loop;
  req->cb = cb;
  req->path = NULL;
  req->new_path = NULL;
  req->ptr = NULL;
  req->bufs = NULL;
  req->nbufs = 0;
  req->work_req.loop = NULL;
  req->off = 0;
  req->result = UV_EINVAL;
  return cb && !loop ? UV_EINVAL : 0;
}

/* Match upstream scandir_next/cleanup's system allocator. */
struct scan_result { uv__dirent_t** entries; size_t count, capacity; };
static int scan_emit(void* context, const void* name, size_t length, uint32_t kind) {
  struct scan_result* scan = context;
  if (scan->count == INT_MAX || length > SIZE_MAX - sizeof(uv__dirent_t) - 1)
    return -16;
  if (scan->count == scan->capacity) {
    size_t capacity = scan->capacity ? scan->capacity * 2 : 16;
    if (capacity > SIZE_MAX / sizeof(*scan->entries)) return -16;
    void* entries = realloc(scan->entries, capacity * sizeof(*scan->entries));
    if (!entries) return -16;
    scan->entries = entries;
    scan->capacity = capacity;
  }
  uv__dirent_t* entry = malloc(sizeof(*entry) + length + 1);
  if (!entry) return -16;
  entry->d_type = kind == 2 ? DT_REG : kind == 3 ? DT_DIR : DT_LNK;
  memcpy(entry->d_name, name, length);
  entry->d_name[length] = 0;
  scan->entries[scan->count++] = entry;
  return 0;
}

/* A directory owns a stable enumeration, with authority and inode identity
 * revalidated before every delivery. Renamed/deleted directories fail closed.
 * As in libuv, callers must serialize use of each uv_dir_t and clean each
 * readdir request before replacing dirents or closing the directory. */
struct directory {
  uv_dir_t public;
  struct scan_result scan;
  char* path;
  uint64_t inode;
  size_t cursor;
};
static void directory_free(struct directory* dir) {
  for (size_t i = 0; i < dir->scan.count; ++i) free(dir->scan.entries[i]);
  free(dir->scan.entries);
  uv__free(dir->path);
  uv__free(dir);
}
static void directory_open(uv_fs_t* req) {
  char path[4097];
  vibeos_native_file_stat_t stat;
  ptrdiff_t status = vibeos_native_realpath(req->path, strlen(req->path), path, sizeof(path));
  if (status < 0) { req->result = result(status); return; }
  status = vibeos_native_path_stat(path, strlen(path), 1, &stat);
  if (status) { req->result = result(status); return; }
  if (stat.kind != 3) { req->result = UV_ENOTDIR; return; }
  struct directory* dir = uv__calloc(1, sizeof(*dir));
  if (!dir) { req->result = UV_ENOMEM; return; }
  dir->path = uv__strdup(path);
  if (!dir->path) { directory_free(dir); req->result = UV_ENOMEM; return; }
  dir->inode = stat.file_id;
  status = vibeos_native_scandir(path, strlen(path), scan_emit, &dir->scan);
  if (status) { directory_free(dir); req->result = result(status); return; }
  req->ptr = &dir->public;
  req->result = 0;
}
static void directory_read(uv_fs_t* req) {
  struct directory* dir = req->ptr;
  vibeos_native_file_stat_t stat;
  int status = vibeos_native_path_stat(dir->path, strlen(dir->path), 1, &stat);
  if (status) { req->result = result(status); return; }
  if (stat.kind != 3 || stat.file_id != dir->inode) { req->result = UV_ENOENT; return; }
  size_t count = dir->scan.count - dir->cursor;
  if (count > dir->public.nentries) count = dir->public.nentries;
  req->result = 0;
  for (size_t i = 0; i < count; ++i) {
    uv__dirent_t* entry = dir->scan.entries[dir->cursor + i];
    uv_dirent_t* output = &dir->public.dirents[i];
    output->name = uv__strdup(entry->d_name);
    if (!output->name) {
      /* Allocation failure does not consume entries. */
      uv__fs_readdir_cleanup(req);
      req->result = UV_ENOMEM;
      return;
    }
    output->type = uv__fs_get_dirent_type(entry);
    req->result++;
  }
  dir->cursor += count;
}

static int is_temporary(const uv_fs_t* req) {
  return req->fs_type == UV_FS_MKDTEMP || req->fs_type == UV_FS_MKSTEMP;
}
static int needs_native_stack(const uv_fs_t* req) {
  return is_temporary(req) || req->fs_type == UV_FS_COPYFILE ||
         (req->fs_type == UV_FS_OPEN && (req->flags & (O_CREAT | O_TRUNC)));
}
static void temporary_work(uv_fs_t* req) {
  size_t length = strlen(req->path);
  if (length < 6 || memcmp(req->path + length - 6, "XXXXXX", 6)) {
    req->result = UV_EINVAL;
    return;
  }
  static const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
  char* suffix = (char*) req->path + length - 6;
  req->result = UV_EEXIST;
  for (unsigned attempt = 0; attempt < 128; attempt++) {
    uint8_t random[6];
    if (vibeos_native_entropy(random, sizeof(random))) { req->result = UV_EIO; break; }
    for (unsigned i = 0; i < 6; i++) suffix[i] = alphabet[random[i] & 63];
    if (req->fs_type == UV_FS_MKDTEMP)
      req->result = result(vibeos_native_tree_change(1, req->path, length, NULL, 0, 0));
    else
      req->result = result(vibeos_native_open(req->path, length,
          vibeos_native_open_mode(O_RDWR | O_CREAT | O_EXCL)));
    if (req->result >= 0) return;
    if (req->result != UV_EEXIST) break;
  }
  memcpy(suffix, "XXXXXX", 6);
}

static void control_work(struct uv__work* work) {
  uv_fs_t* req = container_of(work, uv_fs_t, work_req);
  switch (req->fs_type) {
    /* FileTreeRoot uses capabilities and generations, not Unix owners,
     * mode bits or mutable wall-clock timestamps. Never pretend to apply
     * metadata that the backing service cannot represent. */
    case UV_FS_CHMOD: case UV_FS_FCHMOD:
    case UV_FS_CHOWN: case UV_FS_FCHOWN: case UV_FS_LCHOWN:
    case UV_FS_UTIME: case UV_FS_FUTIME: case UV_FS_LUTIME:
      req->result = UV_ENOTSUP;
      return;
    default: break;
  }
  if (req->fs_type == UV_FS_COPYFILE) {
    req->result = result(vibeos_native_copyfile(req->path, strlen(req->path),
        req->new_path, strlen(req->new_path), (uint32_t) req->flags));
  } else if (req->fs_type == UV_FS_STATFS) {
    vibeos_native_file_stat_t metadata;
    int status = vibeos_native_path_stat(req->path, strlen(req->path), 1, &metadata);
    req->result = status ? result(status) : UV_ENOTSUP;
  } else if (is_temporary(req)) {
    temporary_work(req);
  } else if (req->fs_type == UV_FS_OPENDIR) {
    directory_open(req);
  } else if (req->fs_type == UV_FS_READDIR) {
    directory_read(req);
  } else if (req->fs_type == UV_FS_CLOSEDIR) {
    directory_free(req->ptr); /* Releasing memory remains legal after revocation. */
    req->ptr = NULL;
    req->result = 0;
  } else if (req->fs_type == UV_FS_FSYNC || req->fs_type == UV_FS_FDATASYNC) {
    req->result = result(vibeos_native_file_sync(req->file));
  } else if (req->fs_type == UV_FS_OPEN) {
    req->result = result(vibeos_native_open(req->path, strlen(req->path),
                                           vibeos_native_open_mode(req->flags)));
  } else if (req->fs_type == UV_FS_FTRUNCATE) {
    if (!req->cb) {
      req->result = result(vibeos_native_file_truncate(req->file, (int64_t) req->statbuf.st_size));
    } else {
      if (req->off == 0) {
        req->off = vibeos_native_file_truncate_begin(req->file, (int64_t) req->statbuf.st_size);
        if (req->off < 0) { req->result = result(req->off); req->off = 0; return; }
      }
      req->result = result(vibeos_native_mutation_poll((uint64_t) req->off));
      if (req->result != UV_EAGAIN) req->off = 0;
    }
  } else if (req->fs_type == UV_FS_SCANDIR) {
    struct scan_result scan = {0};
    int status = vibeos_native_scandir(req->path, strlen(req->path), scan_emit, &scan);
    if (status) {
      for (size_t i = 0; i < scan.count; ++i) free(scan.entries[i]);
      free(scan.entries);
      req->result = result(status);
    } else {
      req->ptr = scan.entries;
      req->result = (ssize_t) scan.count;
    }
  } else if (req->fs_type == UV_FS_ACCESS) {
    req->result = result(vibeos_native_access(req->path, strlen(req->path), (uint32_t) req->flags));
  } else if (req->fs_type == UV_FS_MKDIR || req->fs_type == UV_FS_RMDIR ||
             req->fs_type == UV_FS_RENAME || req->fs_type == UV_FS_SYMLINK || req->fs_type == UV_FS_LINK) {
    uint32_t operation = req->fs_type == UV_FS_MKDIR ? 1 :
                         req->fs_type == UV_FS_RMDIR ? 2 : req->fs_type == UV_FS_RENAME ? 3 :
                         req->fs_type == UV_FS_SYMLINK ? 4 : 5;
    if (!req->cb || req->off == 0) {
      int64_t status = vibeos_native_tree_change(operation, req->path, strlen(req->path),
          req->new_path, req->new_path ? strlen(req->new_path) : 0, req->cb != NULL);
      if (!req->cb || status < 0) { req->result = result(status); return; }
      req->off = status;
    }
    req->result = result(vibeos_native_mutation_poll((uint64_t) req->off));
    if (req->result != UV_EAGAIN) req->off = 0;
  } else if (req->fs_type == UV_FS_UNLINK) {
    if (!req->cb) {
      req->result = result(vibeos_native_unlink(req->path, strlen(req->path)));
    } else {
      if (req->off == 0) {
        req->off = vibeos_native_unlink_begin(req->path, strlen(req->path));
        if (req->off < 0) { req->result = result(req->off); req->off = 0; return; }
      }
      req->result = result(vibeos_native_mutation_poll((uint64_t) req->off));
      if (req->result != UV_EAGAIN) req->off = 0;
    }
  } else if (req->fs_type == UV_FS_CLOSE) {
    req->result = result(vibeos_native_close(req->file));
  } else if (req->fs_type == UV_FS_REALPATH || req->fs_type == UV_FS_READLINK) {
    char* canonical = uv__malloc(4098);
    if (!canonical) { req->result = UV_ENOMEM; return; }
    ptrdiff_t length = req->fs_type == UV_FS_READLINK
        ? vibeos_native_readlink(req->path, strlen(req->path), canonical, 4098)
        : vibeos_native_realpath(req->path, strlen(req->path), canonical, 4098);
    req->result = length < 0 ? result(length) : 0;
    if (length < 0) uv__free(canonical);
    else req->ptr = canonical;
  } else {
    vibeos_native_file_stat_t stat;
    assert(req->fs_type == UV_FS_FSTAT || req->fs_type == UV_FS_STAT || req->fs_type == UV_FS_LSTAT);
    req->result = result(req->fs_type == UV_FS_FSTAT
        ? vibeos_native_file_stat(req->file, &stat)
        : vibeos_native_path_stat(req->path, strlen(req->path), req->fs_type == UV_FS_STAT, &stat));
    if (req->result == 0) {
      memset(&req->statbuf, 0, sizeof(req->statbuf));
      req->statbuf.st_mode = stat.kind == 2 ? (S_IFREG | 0444) :
                             stat.kind == 3 ? (S_IFDIR | 0555) : (S_IFLNK | 0777);
      req->statbuf.st_ino = stat.file_id;
      req->statbuf.st_size = stat.size;
      req->statbuf.st_nlink = stat.links;
      req->statbuf.st_gen = stat.generation;
      req->statbuf.st_blksize = 4096;
      req->ptr = &req->statbuf;
    }
  }
}

static void control_queued(struct uv__work* work) {
  work->work = control_work;
  control_work(work);
}

static int control_submit(uv_fs_t* req) {
  req->work_req.work = control_queued;
  req->work_req.done = io_done;
  if (!req->cb) {
    control_work(&req->work_req);
    return (int) req->result;
  }
  req->result = UV_EAGAIN;
  req->work_req.loop = req->loop;
  uv__req_register(req->loop);
  uv__queue_insert_tail(&req->loop->wq, &req->work_req.wq);
  return 0;
}

int uv_fs_open(uv_loop_t* loop, uv_fs_t* req, const char* path,
               int flags, int mode, uv_fs_cb cb) {
  int error = control_init(loop, req, UV_FS_OPEN, cb);
  if (error) return error;
  /* Unix mode is not a source of authority. Mutating opens are dispatched
   * on the native stack so publication can park without crossing C++ frames. */
  if ((flags & O_CREAT) && (mode < 0 || (mode & ~0777))) {
    req->result = UV_ENOTSUP; return UV_ENOTSUP;
  }
  if (!path) return UV_EINVAL;
  size_t length = strnlen(path, 4097);
  if (length > 4096) { req->result = UV_ENAMETOOLONG; return UV_ENAMETOOLONG; }
  req->path = uv__strndup(path, length);
  if (!req->path) { req->result = UV_ENOMEM; return UV_ENOMEM; }
  req->flags = flags;
  return control_submit(req);
}

static int path_request_flags(uv_fs_type type, uv_loop_t* loop, uv_fs_t* req,
                              const char* path, int flags, uv_fs_cb cb) {
  int error = control_init(loop, req, type, cb);
  if (error) return error;
  if (!path) return UV_EINVAL;
  size_t length = strnlen(path, 4097);
  if (length > 4096) { req->result = UV_ENAMETOOLONG; return UV_ENAMETOOLONG; }
  req->path = uv__strndup(path, length);
  if (!req->path) { req->result = UV_ENOMEM; return UV_ENOMEM; }
  req->flags = flags;
  return control_submit(req);
}

static int path_request(uv_fs_type type, uv_loop_t* loop, uv_fs_t* req,
                        const char* path, uv_fs_cb cb) {
  return path_request_flags(type, loop, req, path, 0, cb);
}

static int fd_request(uv_fs_type type, uv_loop_t* loop,
                                   uv_fs_t* req, uv_file fd, uv_fs_cb cb) {
  int error = control_init(loop, req, type, cb);
  if (error) return error;
  req->file = fd;
  return control_submit(req);
}
int uv_fs_chmod(uv_loop_t* loop, uv_fs_t* req, const char* path, int mode, uv_fs_cb cb) {
  return path_request_flags(UV_FS_CHMOD, loop, req, path, mode, cb);
}
int uv_fs_fchmod(uv_loop_t* loop, uv_fs_t* req, uv_file fd, int mode, uv_fs_cb cb) {
  (void) mode;
  return fd_request(UV_FS_FCHMOD, loop, req, fd, cb);
}
int uv_fs_fsync(uv_loop_t* loop, uv_fs_t* req, uv_file fd, uv_fs_cb cb) {
  return fd_request(UV_FS_FSYNC, loop, req, fd, cb);
}
int uv_fs_fdatasync(uv_loop_t* loop, uv_fs_t* req, uv_file fd, uv_fs_cb cb) {
  return fd_request(UV_FS_FDATASYNC, loop, req, fd, cb);
}
int uv_fs_chown(uv_loop_t* loop, uv_fs_t* req, const char* path, uv_uid_t uid, uv_gid_t gid, uv_fs_cb cb) {
  (void) uid; (void) gid;
  return path_request(UV_FS_CHOWN, loop, req, path, cb);
}
int uv_fs_fchown(uv_loop_t* loop, uv_fs_t* req, uv_file fd, uv_uid_t uid, uv_gid_t gid, uv_fs_cb cb) {
  (void) uid; (void) gid;
  return fd_request(UV_FS_FCHOWN, loop, req, fd, cb);
}
int uv_fs_lchown(uv_loop_t* loop, uv_fs_t* req, const char* path, uv_uid_t uid, uv_gid_t gid, uv_fs_cb cb) {
  (void) uid; (void) gid;
  return path_request(UV_FS_LCHOWN, loop, req, path, cb);
}
int uv_fs_utime(uv_loop_t* loop, uv_fs_t* req, const char* path, double atime, double mtime, uv_fs_cb cb) {
  (void) atime; (void) mtime;
  return path_request(UV_FS_UTIME, loop, req, path, cb);
}
int uv_fs_futime(uv_loop_t* loop, uv_fs_t* req, uv_file fd, double atime, double mtime, uv_fs_cb cb) {
  (void) atime; (void) mtime;
  return fd_request(UV_FS_FUTIME, loop, req, fd, cb);
}
int uv_fs_lutime(uv_loop_t* loop, uv_fs_t* req, const char* path, double atime, double mtime, uv_fs_cb cb) {
  (void) atime; (void) mtime;
  return path_request(UV_FS_LUTIME, loop, req, path, cb);
}

int uv_fs_mkdir(uv_loop_t* loop, uv_fs_t* req, const char* path, int mode, uv_fs_cb cb) {
  /* Unix mode does not create or restrict capability rights. */
  if (mode < 0 || (mode & ~0777)) {
    int error = control_init(loop, req, UV_FS_MKDIR, cb);
    if (!error) req->result = UV_ENOTSUP;
    return error ? error : UV_ENOTSUP;
  }
  return path_request(UV_FS_MKDIR, loop, req, path, cb);
}

int uv_fs_rmdir(uv_loop_t* loop, uv_fs_t* req, const char* path, uv_fs_cb cb) {
  return path_request(UV_FS_RMDIR, loop, req, path, cb);
}

static int two_paths(uv_fs_type type, uv_loop_t* loop, uv_fs_t* req,
                     const char* path, const char* destination, int flags, uv_fs_cb cb) {
  int error = control_init(loop, req, type, cb);
  if (error) return error;
  if (!path || !destination) return UV_EINVAL;
  size_t length = strnlen(path, 4097), other = strnlen(destination, 4097);
  if (length > 4096 || other > 4096) {
    req->result = UV_ENAMETOOLONG; return UV_ENAMETOOLONG;
  }
  req->path = uv__strndup(path, length);
  req->new_path = uv__strndup(destination, other);
  req->flags = flags;
  if (!req->path || !req->new_path) { req->result = UV_ENOMEM; return UV_ENOMEM; }
  return control_submit(req);
}

int uv_fs_copyfile(uv_loop_t* loop, uv_fs_t* req, const char* source,
                   const char* destination, int flags, uv_fs_cb cb) {
  return two_paths(UV_FS_COPYFILE, loop, req, source, destination, flags, cb);
}
int uv_fs_statfs(uv_loop_t* loop, uv_fs_t* req, const char* path, uv_fs_cb cb) {
  /* FileTreeRoot has no block-device capacity/allocation accounting contract. */
  return path_request(UV_FS_STATFS, loop, req, path, cb);
}

int uv_fs_rename(uv_loop_t* loop, uv_fs_t* req, const char* path,
                 const char* destination, uv_fs_cb cb) {
  return two_paths(UV_FS_RENAME, loop, req, path, destination, 0, cb);
}
int uv_fs_link(uv_loop_t* loop, uv_fs_t* req, const char* path,
               const char* destination, uv_fs_cb cb) {
  return two_paths(UV_FS_LINK, loop, req, path, destination, 0, cb);
}
int uv_fs_symlink(uv_loop_t* loop, uv_fs_t* req, const char* path,
                  const char* destination, int flags, uv_fs_cb cb) {
  if (flags != 0) {
    int error = control_init(loop, req, UV_FS_SYMLINK, cb);
    if (!error) req->result = UV_ENOTSUP;
    return error ? error : UV_ENOTSUP;
  }
  return two_paths(UV_FS_SYMLINK, loop, req, path, destination, 0, cb);
}

int uv_fs_mkdtemp(uv_loop_t* loop, uv_fs_t* req, const char* pattern, uv_fs_cb cb) {
  return path_request(UV_FS_MKDTEMP, loop, req, pattern, cb);
}
int uv_fs_mkstemp(uv_loop_t* loop, uv_fs_t* req, const char* pattern, uv_fs_cb cb) {
  return path_request(UV_FS_MKSTEMP, loop, req, pattern, cb);
}

int uv_fs_opendir(uv_loop_t* loop, uv_fs_t* req, const char* path, uv_fs_cb cb) {
  return path_request(UV_FS_OPENDIR, loop, req, path, cb);
}
int uv_fs_readdir(uv_loop_t* loop, uv_fs_t* req, uv_dir_t* dir, uv_fs_cb cb) {
  int error = control_init(loop, req, UV_FS_READDIR, cb);
  if (error) return error;
  if (!dir || !dir->dirents || dir->nentries > INT_MAX) return UV_EINVAL;
  req->ptr = dir;
  return control_submit(req);
}
int uv_fs_closedir(uv_loop_t* loop, uv_fs_t* req, uv_dir_t* dir, uv_fs_cb cb) {
  int error = control_init(loop, req, UV_FS_CLOSEDIR, cb);
  if (error) return error;
  if (!dir) return UV_EINVAL;
  req->ptr = dir;
  return control_submit(req);
}

int uv_fs_scandir(uv_loop_t* loop, uv_fs_t* req, const char* path, int flags, uv_fs_cb cb) {
  if (flags != 0) {
    int error = control_init(loop, req, UV_FS_SCANDIR, cb);
    return error ? error : UV_EINVAL;
  }
  return path_request(UV_FS_SCANDIR, loop, req, path, cb);
}

int uv_fs_access(uv_loop_t* loop, uv_fs_t* req, const char* path, int mode, uv_fs_cb cb) {
  return path_request_flags(UV_FS_ACCESS, loop, req, path, mode, cb);
}

int uv_fs_unlink(uv_loop_t* loop, uv_fs_t* req, const char* path, uv_fs_cb cb) {
  return path_request(UV_FS_UNLINK, loop, req, path, cb);
}

int uv_fs_stat(uv_loop_t* loop, uv_fs_t* req, const char* path, uv_fs_cb cb) {
  return path_request(UV_FS_STAT, loop, req, path, cb);
}

int uv_fs_lstat(uv_loop_t* loop, uv_fs_t* req, const char* path, uv_fs_cb cb) {
  return path_request(UV_FS_LSTAT, loop, req, path, cb);
}

int uv_fs_readlink(uv_loop_t* loop, uv_fs_t* req, const char* path, uv_fs_cb cb) {
  return path_request(UV_FS_READLINK, loop, req, path, cb);
}

int uv_fs_realpath(uv_loop_t* loop, uv_fs_t* req, const char* path, uv_fs_cb cb) {
  return path_request(UV_FS_REALPATH, loop, req, path, cb);
}

int uv_fs_close(uv_loop_t* loop, uv_fs_t* req, uv_file fd, uv_fs_cb cb) {
  int error = control_init(loop, req, UV_FS_CLOSE, cb);
  if (error) return error;
  req->file = fd;
  return control_submit(req);
}

int uv_fs_ftruncate(uv_loop_t* loop, uv_fs_t* req, uv_file file, int64_t length, uv_fs_cb cb) {
  int error = control_init(loop, req, UV_FS_FTRUNCATE, cb);
  if (error) return error;
  if (length < 0) { req->result = UV_EINVAL; return UV_EINVAL; }
  req->file = file;
  req->statbuf.st_size = (uint64_t) length;
  return control_submit(req);
}

int uv_fs_fstat(uv_loop_t* loop, uv_fs_t* req, uv_file fd, uv_fs_cb cb) {
  int error = control_init(loop, req, UV_FS_FSTAT, cb);
  if (error) return error;
  req->file = fd;
  return control_submit(req);
}

void uv_fs_req_cleanup(uv_fs_t* req) {
  if (!req) return;
  assert(req->work_req.loop == NULL); /* Caller must await completion first. */
  if (req->fs_type == UV_FS_READDIR) uv__fs_readdir_cleanup(req);
  if (req->fs_type == UV_FS_SCANDIR && req->ptr) uv__fs_scandir_cleanup(req);
  if (req->bufs && req->bufs != req->bufsml) uv__free(req->bufs);
  req->bufs = NULL;
  req->nbufs = 0;
  uv__free((void*) req->new_path);
  req->new_path = NULL;
  uv__free((void*) req->path);
  req->path = NULL;
  if (req->fs_type == UV_FS_REALPATH || req->fs_type == UV_FS_READLINK) uv__free(req->ptr);
  req->ptr = NULL;
}

int uv__vibeos_poll_requests(uv_loop_t* loop) {
  struct uv__queue* q;
  int completed = 0;
  uv__queue_foreach(q, &loop->wq) {
    struct uv__work* work = uv__queue_data(q, struct uv__work, wq);
    uv_fs_t* req = container_of(work, uv_fs_t, work_req);
    /* Entropy and synchronous publication park native C frames. Readiness can
     * run on the Rust executor stack, so only report these requests as ready. */
    if (req->result == UV_EAGAIN && needs_native_stack(req)) { completed = 1; continue; }
    if (req->result == UV_EAGAIN) work->work(work);
    if (req->result != UV_EAGAIN) completed = 1;
  }
  return completed;
}

void uv__vibeos_run_requests(uv_loop_t* loop) {
  struct uv__queue queue;
  uv__vibeos_poll_requests(loop);
  uv__queue_move(&loop->wq, &queue);
  while (!uv__queue_empty(&queue)) {
    struct uv__queue* q = uv__queue_head(&queue);
    struct uv__work* work = uv__queue_data(q, struct uv__work, wq);
    uv_fs_t* req = container_of(work, uv_fs_t, work_req);
    uv__queue_remove(q);
    if (req->result == UV_EAGAIN && needs_native_stack(req)) work->work(work);
    if (req->result == UV_EAGAIN) {
      uv__queue_insert_tail(&loop->wq, q);
      continue;
    }
    uv__req_unregister(loop);
    work->loop = NULL;
    work->done(work, 0); /* Callback may free or resubmit its request. */
  }
}

/* Match libuv's queued-work boundary: a started operation cannot be rolled
 * back by cancelling its callback, especially once a transaction may publish. */
int uv_cancel(uv_req_t* request) {
  if (!request) return UV_EINVAL;
  if (request->type == UV_WORK) return uv__vibeos_cancel_work((uv_work_t*) request);
  if (request->type != UV_FS) return UV_EINVAL;
  uv_fs_t* req = (uv_fs_t*) request;
  if (!req->work_req.loop || req->result != UV_EAGAIN ||
      (req->work_req.work != io_queued && req->work_req.work != control_queued))
    return UV_EBUSY;
  req->result = UV_ECANCELED;
  req->work_req.work = NULL;
  /* Leave registration and storage intact until the one deferred callback. */
  return 0;
}
