/* Runs ml_idle_wait() (components/tailtiny/src/ml_idle_wait.h) against a real
 * socket pair and eventfd. Built and run by check_idle_wait.py; Linux only,
 * since eventfd is. Prints one line per check and exits 1 if any fails. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "ml_idle_wait.h"

static int failures, checks;

#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    printf("FAIL %s:%d: %s\n", __func__, __LINE__, #cond); } } while (0)

typedef struct { int wake, sock[2]; } fds_t;

static fds_t open_fds(void) {
    fds_t f = { .wake = eventfd(0, EFD_NONBLOCK), .sock = { -1, -1 } };
    if (f.wake < 0 || socketpair(AF_UNIX, SOCK_STREAM, 0, f.sock) != 0) {
        perror("eventfd/socketpair");
        exit(2);
    }
    return f;
}

static void close_fds(fds_t *f) { close(f->wake); close(f->sock[0]); close(f->sock[1]); }

static void signal_fd(int fd) {
    uint64_t one = 1;
    if (write(fd, &one, sizeof(one)) != (ssize_t)sizeof(one)) { perror("write"); exit(2); }
}

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

/* Work queued before the wait (and signalled twice) wakes it once, and the
 * wait then drains the count, so the next one sleeps instead of spinning. */
static void latched_signal_drained(void) {
    fds_t f = open_fds();
    signal_fd(f.wake);
    signal_fd(f.wake);
    CHECK(ml_idle_wait(-1, f.wake, 10) > 0);
    CHECK(ml_idle_wait(-1, f.wake, 10) == 0);
    close_fds(&f);
}

static void *signal_later(void *arg) {
    struct timespec d = { 0, 20 * 1000 * 1000 };
    nanosleep(&d, NULL);
    signal_fd(*(int *)arg);
    return NULL;
}

/* Queued TX interrupts a long wait for relay RX instead of waiting it out. */
static void tx_interrupts_rx_wait(void) {
    fds_t f = open_fds();
    pthread_t producer;
    pthread_create(&producer, NULL, signal_later, &f.wake);
    double start = now_ms();
    int ready = ml_idle_wait(f.sock[0], f.wake, 2000);
    double elapsed = now_ms() - start;
    pthread_join(producer, NULL);
    CHECK(ready > 0);
    CHECK(elapsed < 1500);  /* broad margin for a loaded machine */
    close_fds(&f);
}

/* Relay RX wakes the wait, and the wait leaves the bytes for TLS to read. */
static void rx_wakes_without_consuming(void) {
    fds_t f = open_fds();
    CHECK(write(f.sock[1], "X", 1) == 1);
    CHECK(ml_idle_wait(f.sock[0], f.wake, 10) > 0);
    char byte = 0;
    CHECK(read(f.sock[0], &byte, 1) == 1);
    CHECK(byte == 'X');
    close_fds(&f);
}

/* RX and TX ready together: both are served, and a signal sent after the
 * caller drained its queue isn't lost on the next wait. */
static void rx_and_tx_together(void) {
    fds_t f = open_fds();
    signal_fd(f.wake);
    CHECK(write(f.sock[1], "Y", 1) == 1);
    CHECK(ml_idle_wait(f.sock[0], f.wake, 10) > 0);
    char byte = 0;
    CHECK(read(f.sock[0], &byte, 1) == 1);
    CHECK(byte == 'Y');
    signal_fd(f.wake);
    CHECK(ml_idle_wait(f.sock[0], f.wake, 10) > 0);
    CHECK(ml_idle_wait(f.sock[0], f.wake, 10) == 0);
    close_fds(&f);
}

/* Nothing ready: the wait times out roughly on time. */
static void idle_times_out(void) {
    fds_t f = open_fds();
    double start = now_ms();
    CHECK(ml_idle_wait(f.sock[0], f.wake, 50) == 0);
    CHECK(now_ms() - start >= 40);
    close_fds(&f);
}

/* Out-of-range descriptors are refused rather than written into an fd_set. */
static void bad_descriptors_refused(void) {
    fds_t f = open_fds();
    CHECK(ml_idle_wait(-1, -1, 10) == -1);
    CHECK(ml_idle_wait(FD_SETSIZE, f.wake, 10) == -1);
    CHECK(ml_idle_wait(-1, FD_SETSIZE, 10) == -1);
    close_fds(&f);
}

int main(void) {
    latched_signal_drained();
    tx_interrupts_rx_wait();
    rx_wakes_without_consuming();
    rx_and_tx_together();
    idle_times_out();
    bad_descriptors_refused();
    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
