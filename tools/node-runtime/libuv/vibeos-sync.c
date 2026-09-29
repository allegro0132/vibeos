/* Synchronization on admitted native tasks. Waiting parks the C/C++ stack;
 * no scheduler spin loop or pthread implementation is involved. */
#include "uv.h"
#include "uv-common.h"
#include "vibeos-sync.h"
#include <limits.h>
#include <stdlib.h>

struct mutex_state {
  void* semaphore;
  int32_t owner;
  unsigned depth;
  int recursive;
};

static int mutex_init(uv_mutex_t* mutex, int recursive) {
  struct mutex_state* state = uv__calloc(1, sizeof(*state));
  if (!state) return UV_ENOMEM;
  state->semaphore = vibeos_native_semaphore_create(1);
  if (!state->semaphore) { uv__free(state); return UV_ENOMEM; }
  state->recursive = recursive;
  mutex->semaphore = state;
  return 0;
}
int uv_mutex_init(uv_mutex_t* mutex) { return mutex_init(mutex, 0); }
int uv_mutex_init_recursive(uv_mutex_t* mutex) { return mutex_init(mutex, 1); }
void uv_mutex_destroy(uv_mutex_t* mutex) {
  struct mutex_state* state = mutex->semaphore;
  assert(state && state->depth == 0);
  vibeos_native_semaphore_destroy(state->semaphore);
  uv__free(state);
  mutex->semaphore = NULL;
}
static int mutex_lock(uv_mutex_t* mutex, int try_only) {
  struct mutex_state* state = mutex->semaphore;
  int32_t current = vibeos_native_thread_id();
  if (state->owner == current) {
    if (!state->recursive) {
      if (try_only) return UV_EBUSY;
      abort(); /* Non-recursive self-lock is a programming error. */
    }
    if (state->depth == UINT_MAX) abort();
    state->depth++;
    return 0;
  }
  int result = vibeos_native_semaphore_wait(state->semaphore, try_only ? 0 : -1);
  if (result < 0) abort();
  if (!result) return UV_EBUSY;
  state->owner = current;
  state->depth = 1;
  return 0;
}
void uv_mutex_lock(uv_mutex_t* mutex) { if (mutex_lock(mutex, 0)) abort(); }
int uv_mutex_trylock(uv_mutex_t* mutex) { return mutex_lock(mutex, 1); }
void uv_mutex_unlock(uv_mutex_t* mutex) {
  struct mutex_state* state = mutex->semaphore;
  assert(state && state->owner == vibeos_native_thread_id() && state->depth);
  if (--state->depth) return;
  state->owner = 0;
  if (vibeos_native_semaphore_signal(state->semaphore) != 0) abort();
}
int uv_sem_init(uv_sem_t* sem, unsigned value) {
  if (value > INT_MAX) return UV_EINVAL;
  sem->semaphore = vibeos_native_semaphore_create((int) value);
  return sem->semaphore ? 0 : UV_ENOMEM;
}
void uv_sem_destroy(uv_sem_t* sem) {
  vibeos_native_semaphore_destroy(sem->semaphore);
  sem->semaphore = NULL;
}
void uv_sem_post(uv_sem_t* sem) {
  if (vibeos_native_semaphore_signal(sem->semaphore) != 0) abort();
}
void uv_sem_wait(uv_sem_t* sem) {
  if (vibeos_native_semaphore_wait(sem->semaphore, -1) != 1) abort();
}
int uv_sem_trywait(uv_sem_t* sem) {
  int result = vibeos_native_semaphore_wait(sem->semaphore, 0);
  if (result < 0) abort();
  return result ? 0 : UV_EAGAIN;
}
int uv_cond_init(uv_cond_t* cond) { cond->generation = 0; return 0; }
void uv_cond_destroy(uv_cond_t* cond) { (void) cond; }
void uv_cond_broadcast(uv_cond_t* cond) {
  __atomic_add_fetch(&cond->generation, 1, __ATOMIC_RELEASE);
  vibeos_native_wake_all(cond);
}
/* Waking extra waiters is permitted: condition waits may return spuriously. */
void uv_cond_signal(uv_cond_t* cond) { uv_cond_broadcast(cond); }
struct condition_wait { uv_cond_t* cond; uint64_t generation; };
static int changed(void* pointer) {
  struct condition_wait* wait = pointer;
  return __atomic_load_n(&wait->cond->generation, __ATOMIC_ACQUIRE) != wait->generation;
}
static int condition_wait(uv_cond_t* cond, uv_mutex_t* mutex, int64_t timeout_us) {
  struct mutex_state* state = mutex->semaphore;
  assert(state && state->depth == 1 && state->owner == vibeos_native_thread_id());
  struct condition_wait wait = {cond, __atomic_load_n(&cond->generation, __ATOMIC_ACQUIRE)};
  uv_mutex_unlock(mutex);
  int result = vibeos_native_wait_until_context(cond, changed, &wait, timeout_us);
  uv_mutex_lock(mutex);
  if (result < 0) abort();
  return result ? 0 : UV_ETIMEDOUT;
}
void uv_cond_wait(uv_cond_t* cond, uv_mutex_t* mutex) {
  if (condition_wait(cond, mutex, -1)) abort();
}
int uv_cond_timedwait(uv_cond_t* cond, uv_mutex_t* mutex, uint64_t timeout_ns) {
  /* Round up so conversion cannot return before the requested duration. */
  uint64_t us = timeout_ns / 1000 + (timeout_ns % 1000 != 0);
  return condition_wait(cond, mutex, (int64_t) us);
}

/* A high bit denotes the exclusive owner; remaining bits count readers.
 * Ready callbacks run on the native stack before/after parking and only touch
 * atomics. They never enter JS, consult native TLS, or retain stack pointers. */
struct rwlock_state { unsigned state; int32_t writer; };
#define WRITER_BIT (1u << 31)
int uv_rwlock_init(uv_rwlock_t* lock) {
  lock->semaphore = uv__calloc(1, sizeof(struct rwlock_state));
  return lock->semaphore ? 0 : UV_ENOMEM;
}
void uv_rwlock_destroy(uv_rwlock_t* lock) {
  struct rwlock_state* state = lock->semaphore;
  assert(state && __atomic_load_n(&state->state, __ATOMIC_ACQUIRE) == 0);
  uv__free(state);
  lock->semaphore = NULL;
}
static int acquire_reader(void* pointer) {
  struct rwlock_state* state = pointer;
  unsigned old = __atomic_load_n(&state->state, __ATOMIC_RELAXED);
  if (old & WRITER_BIT) return 0;
  if (old == WRITER_BIT - 1) abort();
  return __atomic_compare_exchange_n(&state->state, &old, old + 1, 0,
                                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}
static int acquire_writer(void* pointer) {
  struct rwlock_state* state = pointer;
  unsigned old = 0;
  return __atomic_compare_exchange_n(&state->state, &old, WRITER_BIT, 0,
                                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}
int uv_rwlock_tryrdlock(uv_rwlock_t* lock) {
  return acquire_reader(lock->semaphore) ? 0 : UV_EBUSY;
}
void uv_rwlock_rdlock(uv_rwlock_t* lock) {
  if (vibeos_native_wait_until(lock->semaphore, acquire_reader)) abort();
}
void uv_rwlock_rdunlock(uv_rwlock_t* lock) {
  struct rwlock_state* state = lock->semaphore;
  unsigned old = __atomic_fetch_sub(&state->state, 1, __ATOMIC_RELEASE);
  assert(old && !(old & WRITER_BIT));
  if (old == 1) vibeos_native_wake_all(state);
}
int uv_rwlock_trywrlock(uv_rwlock_t* lock) {
  struct rwlock_state* state = lock->semaphore;
  if (!acquire_writer(state)) return UV_EBUSY;
  state->writer = vibeos_native_thread_id();
  return 0;
}
void uv_rwlock_wrlock(uv_rwlock_t* lock) {
  struct rwlock_state* state = lock->semaphore;
  if (vibeos_native_wait_until(state, acquire_writer)) abort();
  state->writer = vibeos_native_thread_id();
}
void uv_rwlock_wrunlock(uv_rwlock_t* lock) {
  struct rwlock_state* state = lock->semaphore;
  assert(state->writer == vibeos_native_thread_id());
  state->writer = 0;
  unsigned old = __atomic_exchange_n(&state->state, 0, __ATOMIC_RELEASE);
  assert(old == WRITER_BIT);
  vibeos_native_wake_all(state);
}
