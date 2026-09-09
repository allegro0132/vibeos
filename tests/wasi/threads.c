/* wasi-threads acceptance fixture: pthreads over the shared linear memory.
 * Build: clang --target=wasm32-wasi-threads -pthread ... (see build-wasi-examples.sh)
 *   (no args)   three workers add to an atomic counter and one hands a value
 *               through a mutex/condvar; prints "sum=3000 cond=1".
 *   exit        a worker calls exit(7) while main waits; the process exits 7.
 *   spawnmany   creates threads until pthread_create fails; prints "eagain=1".
 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static atomic_int counter;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int handed;

static void *worker(void *arg) {
    for (int i = 0; i < 1000; i++) atomic_fetch_add(&counter, 1);
    if ((long)arg == 0) {
        pthread_mutex_lock(&lock);
        handed = 1;
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}
static void *exiter(void *arg) { (void)arg; exit(7); }
static void *idle(void *arg) {
    pthread_mutex_lock(&lock);
    while (!handed) pthread_cond_wait(&cond, &lock);
    pthread_mutex_unlock(&lock);
    return arg;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "exit") == 0) {
        pthread_t t;
        if (pthread_create(&t, NULL, exiter, NULL) != 0) return 2;
        pthread_join(t, NULL);
        return 3; /* unreachable: exit(7) ends the process */
    }
    if (argc > 1 && strcmp(argv[1], "spawnmany") == 0) {
        pthread_t threads[16];
        int created = 0, eagain = 0;
        for (int i = 0; i < 16; i++) {
            int rc = pthread_create(&threads[created], NULL, idle, NULL);
            if (rc == 0) created++;
            else if (rc == EAGAIN) eagain = 1;
            else { printf("error=%d\n", rc); return 2; }
        }
        pthread_mutex_lock(&lock);
        handed = 1;
        pthread_cond_broadcast(&cond);
        pthread_mutex_unlock(&lock);
        for (int i = 0; i < created; i++) pthread_join(threads[i], NULL);
        printf("eagain=%d created=%d\n", eagain, created);
        return 0;
    }
    pthread_t threads[3];
    for (long i = 0; i < 3; i++)
        if (pthread_create(&threads[i], NULL, worker, (void *)i) != 0) return 2;
    pthread_mutex_lock(&lock);
    while (!handed) pthread_cond_wait(&cond, &lock);
    pthread_mutex_unlock(&lock);
    for (int i = 0; i < 3; i++) pthread_join(threads[i], NULL);
    printf("sum=%d cond=%d\n", atomic_load(&counter), handed);
    return 0;
}
