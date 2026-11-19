/*
 * Host test for the control connection's reads and key parsing (ml_coord.c).
 * Built and run by check_coord_robustness.py, which copies the functions
 * under test out of ml_coord.c into coord_extract.c; this file supplies what
 * they call: a scripted socket, a clock that only moves when the test says
 * so, a fake Noise AEAD and log macros that clobber errno the way a real log
 * call may.
 *
 * What must hold:
 *   1. parse_key32() takes exactly 64 hex digits after an optional prefix,
 *      and leaves the key all zero otherwise.
 *   2. coord_recv_ex(): "no data yet" is EAGAIN with nothing consumed; a
 *      started read finishes across timeouts, or fails with ETIMEDOUT after
 *      30 s without progress or 90 s in total (also when bytes trickle in),
 *      ECANCELED on shutdown, ENOTCONN on close. errno survives the log.
 *   3. noise_recv_impl(): a payload that arrives in pieces is read from where
 *      it stopped (the stream stays aligned); protocol errors set EBADMSG or
 *      EMSGSIZE; a stalled payload is ETIMEDOUT, never EAGAIN.
 *   4. complete_proactive_frames(): a buffer cut off in a frame's header or
 *      payload is completed from the socket and nothing past that frame is
 *      read; a frame that would exceed 16 KB, or whose rest never comes,
 *      fails.
 *   5. fmt_i64() prints int64 like %lld.
 */
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/* ---- stand-ins for what the extracted code uses ---- */

typedef int esp_err_t;
#define ESP_OK 0
#define ESP_ERR_INVALID_MAC 0x10a

typedef struct {
    int coord_sock;
    int events;
} tailtiny_t;

typedef struct {
    uint8_t rx_key[32];
    uint64_t rx_nonce;
} ml_noise_state_t;

static const char *TAG = "ml_coord";
static int g_verbose;

/* A log call may change errno (it allocates, writes to a UART...). This one
 * always does, so code that reads errno after logging is caught. */
static void test_log(const char *lvl, const char *fmt, ...) {
    if (g_verbose) {
        va_list ap;
        va_start(ap, fmt);
        fprintf(stderr, "  [%s] ", lvl);
        vfprintf(stderr, fmt, ap);
        fputc('\n', stderr);
        va_end(ap);
    }
    errno = EAGAIN;
}
#define ESP_LOGE(tag, fmt, ...) do { (void)(tag); test_log("E", fmt, ##__VA_ARGS__); } while (0)
#define ESP_LOGW(tag, fmt, ...) do { (void)(tag); test_log("W", fmt, ##__VA_ARGS__); } while (0)
#define ESP_LOGI(tag, fmt, ...) do { (void)(tag); test_log("I", fmt, ##__VA_ARGS__); } while (0)
#define ESP_LOGD(tag, fmt, ...) do { (void)(tag); test_log("D", fmt, ##__VA_ARGS__); } while (0)

/* Time only moves when the socket "blocks" or the code sleeps */
static uint64_t g_now_ms = 1000000;
static uint64_t ml_get_time_ms(void) { return g_now_ms; }
#define pdMS_TO_TICKS(ms) (ms)
#define vTaskDelay(ticks) (g_now_ms += (ticks))

#define ML_EVT_SHUTDOWN_REQUEST (1 << 6)
#define xEventGroupGetBits(ev) (ev)

#define MALLOC_CAP_8BIT 0
static size_t heap_caps_get_free_size(int caps) { (void)caps; return 123456; }
static void *ml_psram_malloc(size_t n) { return malloc(n); }

/* Fake AEAD: ciphertext = plaintext + a 16-byte tag of (nonce + 0xA5) */
#define FAKE_TAG(nonce) ((uint8_t)((nonce) + 0xA5))
static esp_err_t ml_noise_decrypt(const uint8_t *key, uint64_t nonce, const uint8_t *ad, size_t ad_len,
                                  const uint8_t *ct, size_t ct_len, uint8_t *pt) {
    (void)key; (void)ad; (void)ad_len;
    if (ct_len < 16) return ESP_ERR_INVALID_MAC;
    for (size_t i = ct_len - 16; i < ct_len; i++) {
        if (ct[i] != FAKE_TAG(nonce)) return ESP_ERR_INVALID_MAC;
    }
    if (pt) memcpy(pt, ct, ct_len - 16);
    return ESP_OK;
}

/* Scripted socket. Each step either delivers bytes (after wait_ms, as a
 * recv() that blocked that long), or is a recv() timeout (EAGAIN after
 * wait_ms), a close (0), or an error. Past the script, every recv() is a
 * 2 s timeout, an idle connection. */
enum { S_DATA, S_AGAIN, S_CLOSE, S_ERR };
typedef struct {
    int kind;
    const uint8_t *data;
    size_t len;
    uint32_t wait_ms;
    int err;
    int set_shutdown;       /* set the shutdown bit when this step runs */
} step_t;

static tailtiny_t g_ml;
static const step_t *g_steps;
static int g_nsteps, g_step;
static size_t g_step_off;
static int g_recv_calls;

static void script(const step_t *steps, int n) {
    g_steps = steps;
    g_nsteps = n;
    g_step = 0;
    g_step_off = 0;
    g_recv_calls = 0;
    g_ml.events = 0;
}

static ssize_t ml_recv(int fd, void *buf, size_t len, int flags) {
    (void)fd; (void)flags;
    g_recv_calls++;
    if (g_step >= g_nsteps) {
        g_now_ms += 2000;
        errno = EAGAIN;
        return -1;
    }
    const step_t *s = &g_steps[g_step];
    if (s->set_shutdown) g_ml.events |= ML_EVT_SHUTDOWN_REQUEST;
    if (g_step_off == 0) g_now_ms += s->wait_ms;
    switch (s->kind) {
    case S_AGAIN: g_step++; errno = EAGAIN; return -1;
    case S_CLOSE: g_step++; errno = EAGAIN; return 0;  /* recv() leaves errno as it was */
    case S_ERR:   g_step++; errno = s->err; return -1;
    default: break;
    }
    size_t n = s->len - g_step_off;
    if (n > len) n = len;
    memcpy(buf, s->data + g_step_off, n);
    g_step_off += n;
    if (g_step_off == s->len) { g_step++; g_step_off = 0; }
    return (ssize_t)n;
}

#include "coord_extract.c"

/* ---- checks ---- */

static int g_checks, g_failures;
#define CHECK(cond, ...) do {                                   \
        g_checks++;                                             \
        if (!(cond)) {                                          \
            g_failures++;                                       \
            printf("FAIL %s:%d: ", __func__, __LINE__);         \
            printf(__VA_ARGS__);                                \
            printf("\n");                                       \
        }                                                       \
    } while (0)

static bool all_zero(const uint8_t *k) {
    for (int i = 0; i < 32; i++) if (k[i]) return false;
    return true;
}

static void test_parse_key32(void) {
    const char *hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const char *HEX = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    uint8_t want[32], key[32];
    for (int i = 0; i < 32; i++) want[i] = (uint8_t)i;
    char buf[160];

    CHECK(parse_key32(hex, "nodekey:", key) && memcmp(key, want, 32) == 0, "bare hex");
    CHECK(parse_key32(HEX, "nodekey:", key) && memcmp(key, want, 32) == 0, "upper case");
    snprintf(buf, sizeof(buf), "nodekey:%s", hex);
    CHECK(parse_key32(buf, "nodekey:", key) && memcmp(key, want, 32) == 0, "with prefix");
    snprintf(buf, sizeof(buf), "discokey:%s", hex);
    CHECK(parse_key32(buf, "discokey:", key) && memcmp(key, want, 32) == 0, "disco prefix");
    snprintf(buf, sizeof(buf), "chalpub:%s", hex);
    CHECK(parse_key32(buf, "chalpub:", key) && memcmp(key, want, 32) == 0, "challenge prefix");
    CHECK(parse_key32(hex, NULL, key) && memcmp(key, want, 32) == 0, "no prefix wanted");

    /* Each of these must fail and leave the key all zero, also when it held one */
    const char *bad[] = {
        "", "00", "0001020304",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1",     /* 63 */
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0",   /* 65 */
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00",  /* 66 */
        "0g0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",    /* sscanf took "0g" */
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1g",
        " 00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "-00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "nodekey:",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        memset(key, 0xEE, 32);
        CHECK(!parse_key32(bad[i], "nodekey:", key) && all_zero(key), "accepted \"%s\"", bad[i]);
    }
    snprintf(buf, sizeof(buf), "discokey:%s", hex);
    memset(key, 0xEE, 32);
    CHECK(!parse_key32(buf, "nodekey:", key) && all_zero(key), "wrong prefix accepted");
    snprintf(buf, sizeof(buf), "nodekey:nodekey:%s", hex);
    CHECK(!parse_key32(buf, "nodekey:", key) && all_zero(key), "double prefix accepted");
    memset(key, 0xEE, 32);
    CHECK(!parse_key32(NULL, "nodekey:", key) && all_zero(key), "NULL accepted");

    CHECK(key32_is_zero((const uint8_t[32]){0}), "zero key not zero");
    CHECK(!key32_is_zero(want), "key 00..1f taken as zero");
}

static void test_fmt_i64(void) {
    const int64_t vals[] = { 0, 1, -1, 4955372421395013LL, -4294967296LL, INT64_MAX, INT64_MIN };
    for (size_t i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        char buf[24], want[32];
        snprintf(want, sizeof(want), "%" PRId64, vals[i]);
        CHECK(strcmp(fmt_i64(vals[i], buf), want) == 0, "fmt_i64 %s", want);
    }
}

static const uint8_t ABC[] = "abcdefghijklmnopqrstuvwxyz";

static void test_coord_recv(void) {
    uint8_t buf[64];

    /* Idle: nothing consumed, EAGAIN, at once */
    script(NULL, 0);
    uint64_t t0 = g_now_ms;
    CHECK(coord_recv_ex(&g_ml, buf, 3, false) < 0 && errno == EAGAIN, "idle: errno %d", errno);
    CHECK(g_recv_calls == 1 && g_now_ms - t0 == 2000, "idle: %d recv calls, %lu ms",
          g_recv_calls, (unsigned long)(g_now_ms - t0));

    /* Must-complete: even "nothing yet" is waited for */
    {
        const step_t s[] = { { S_AGAIN, 0, 0, 2000, 0, 0 }, { S_DATA, ABC, 3, 0, 0, 0 } };
        script(s, 2);
        CHECK(coord_recv_ex(&g_ml, buf, 3, true) == 0 && memcmp(buf, "abc", 3) == 0, "must_complete wait");
    }

    /* Partial, two timeouts, then the rest: completes in order */
    {
        const step_t s[] = { { S_DATA, ABC, 2, 0, 0, 0 }, { S_AGAIN, 0, 0, 2000, 0, 0 },
                             { S_AGAIN, 0, 0, 2000, 0, 0 }, { S_DATA, ABC + 2, 3, 0, 0, 0 } };
        script(s, 4);
        CHECK(coord_recv_ex(&g_ml, buf, 5, false) == 0 && memcmp(buf, "abcde", 5) == 0, "partial resume");
    }

    /* Partial, then nothing: ETIMEDOUT about 30 s later, not hours */
    {
        const step_t s[] = { { S_DATA, ABC, 1, 0, 0, 0 } };
        script(s, 1);
        t0 = g_now_ms;
        int r = coord_recv_ex(&g_ml, buf, 5, false);
        uint64_t took = g_now_ms - t0;
        CHECK(r < 0 && errno == ETIMEDOUT, "stall: r %d errno %d", r, errno);
        CHECK(took >= 30000 && took <= 33000, "stall took %lu ms", (unsigned long)took);
    }

    /* A byte every 20 s never lets recv() time out: still bounded, ~90 s */
    {
        step_t s[12];
        for (int i = 0; i < 12; i++) s[i] = (step_t){ S_DATA, ABC + i, 1, i ? 20000 : 0, 0, 0 };
        script(s, 12);
        t0 = g_now_ms;
        int r = coord_recv_ex(&g_ml, buf, 12, false);
        uint64_t took = g_now_ms - t0;
        CHECK(r < 0 && errno == ETIMEDOUT, "trickle: r %d errno %d", r, errno);
        CHECK(took >= 90000 && took <= 110000, "trickle took %lu ms", (unsigned long)took);
    }

    /* Slow but steady (a cellular link): a byte every 5 s for 60 s is fine */
    {
        step_t s[12];
        for (int i = 0; i < 12; i++) s[i] = (step_t){ S_DATA, ABC + i, 1, i ? 5000 : 0, 0, 0 };
        script(s, 12);
        CHECK(coord_recv_ex(&g_ml, buf, 12, false) == 0 && memcmp(buf, ABC, 12) == 0, "slow link");
    }

    /* Closed mid-read: ENOTCONN, never the EAGAIN recv() left behind */
    {
        const step_t s[] = { { S_DATA, ABC, 1, 0, 0, 0 }, { S_CLOSE, 0, 0, 0, 0, 0 } };
        script(s, 2);
        CHECK(coord_recv_ex(&g_ml, buf, 5, false) < 0 && errno == ENOTCONN, "close: errno %d", errno);
        const step_t s2[] = { { S_CLOSE, 0, 0, 0, 0, 0 } };
        script(s2, 1);
        CHECK(coord_recv_ex(&g_ml, buf, 5, false) < 0 && errno == ENOTCONN, "close at start: errno %d", errno);
    }

    /* Shutdown while a started read waits: ECANCELED */
    {
        const step_t s[] = { { S_DATA, ABC, 1, 0, 0, 0 }, { S_AGAIN, 0, 0, 2000, 0, 1 } };
        script(s, 2);
        CHECK(coord_recv_ex(&g_ml, buf, 5, false) < 0 && errno == ECANCELED, "shutdown: errno %d", errno);
    }

    /* A socket error's errno survives the log call */
    {
        const step_t s[] = { { S_ERR, 0, 0, 0, ECONNRESET, 0 } };
        script(s, 1);
        CHECK(coord_recv_ex(&g_ml, buf, 5, false) < 0 && errno == ECONNRESET, "error: errno %d", errno);
    }
}

/* A Noise transport frame as the fake AEAD seals it */
static size_t make_frame(uint8_t *out, uint8_t type, const uint8_t *pt, size_t pt_len, uint64_t nonce) {
    size_t ct = pt_len + 16;
    out[0] = type;
    out[1] = (uint8_t)(ct >> 8);
    out[2] = (uint8_t)ct;
    memcpy(out + 3, pt, pt_len);
    memset(out + 3 + pt_len, FAKE_TAG(nonce), 16);
    return 3 + ct;
}

static void test_noise_recv(void) {
    ml_noise_state_t noise = {0};
    uint8_t pt[100], f1[200], f2[64];
    for (int i = 0; i < 100; i++) pt[i] = (uint8_t)(i * 7);
    size_t l1 = make_frame(f1, 0x04, pt, 100, 0);
    size_t l2 = make_frame(f2, 0x04, (const uint8_t *)"next", 4, 1);
    uint8_t *out = NULL;

    /* Header, half the payload, timeouts, the rest, then the next frame: both
     * decode. Restarting the payload at offset 0 lost the first half. */
    {
        const step_t s[] = { { S_DATA, f1, 3, 0, 0, 0 }, { S_DATA, f1 + 3, 50, 0, 0, 0 },
                             { S_AGAIN, 0, 0, 2000, 0, 0 }, { S_AGAIN, 0, 0, 2000, 0, 0 },
                             { S_DATA, f1 + 53, l1 - 53, 0, 0, 0 }, { S_DATA, f2, l2, 0, 0, 0 } };
        script(s, 6);
        int n = noise_recv_impl(&g_ml, &noise, NULL, 65535, &out);
        CHECK(n == 100 && out && memcmp(out, pt, 100) == 0, "split payload: n %d", n);
        free(out);
        out = NULL;
        n = noise_recv_impl(&g_ml, &noise, NULL, 65535, &out);
        CHECK(n == 4 && out && memcmp(out, "next", 4) == 0, "frame after split payload: n %d", n);
        free(out);
        out = NULL;
        CHECK(noise.rx_nonce == 2, "rx_nonce %lu", (unsigned long)noise.rx_nonce);
    }

    /* Idle: EAGAIN, nothing consumed */
    script(NULL, 0);
    CHECK(noise_recv_impl(&g_ml, &noise, NULL, 65535, &out) < 0 && errno == EAGAIN && !out,
          "idle: errno %d", errno);

    /* Payload stalls: ETIMEDOUT, never EAGAIN (the caller would poll on) */
    {
        const step_t s[] = { { S_DATA, f1, 3, 0, 0, 0 }, { S_DATA, f1 + 3, 10, 0, 0, 0 } };
        script(s, 2);
        noise.rx_nonce = 0;
        CHECK(noise_recv_impl(&g_ml, &noise, NULL, 65535, &out) < 0 && errno == ETIMEDOUT,
              "payload stall: errno %d", errno);
        free(out);
        out = NULL;
    }
    /* Header and nothing else: still a hard error */
    {
        const step_t s[] = { { S_DATA, f1, 3, 0, 0, 0 } };
        script(s, 1);
        CHECK(noise_recv_impl(&g_ml, &noise, NULL, 65535, &out) < 0 && errno == ETIMEDOUT,
              "payload never starts: errno %d", errno);
        free(out);
        out = NULL;
    }

    /* Protocol errors */
    {
        uint8_t bad[200];
        size_t lb = make_frame(bad, 0x02, pt, 10, 0);
        const step_t s[] = { { S_DATA, bad, lb, 0, 0, 0 } };
        script(s, 1);
        CHECK(noise_recv_impl(&g_ml, &noise, NULL, 65535, &out) < 0 && errno == EBADMSG,
              "frame type: errno %d", errno);
        free(out);
        out = NULL;

        const uint8_t short_hdr[] = { 0x04, 0x00, 0x0f };
        const step_t s2[] = { { S_DATA, short_hdr, 3, 0, 0, 0 } };
        script(s2, 1);
        CHECK(noise_recv_impl(&g_ml, &noise, NULL, 65535, &out) < 0 && errno == EBADMSG,
              "shorter than MAC: errno %d", errno);
        free(out);
        out = NULL;

        const uint8_t big_hdr[] = { 0x04, 0xff, 0xff };
        const step_t s3[] = { { S_DATA, big_hdr, 3, 0, 0, 0 } };
        script(s3, 1);
        CHECK(noise_recv_impl(&g_ml, &noise, NULL, 65535, &out) < 0 && errno == EMSGSIZE,
              "oversized: errno %d", errno);
        free(out);
        out = NULL;

        uint8_t small[16];
        const step_t s4[] = { { S_DATA, f1, l1, 0, 0, 0 } };
        script(s4, 1);
        CHECK(noise_recv_impl(&g_ml, &noise, small, sizeof(small), NULL) < 0 && errno == EMSGSIZE,
              "larger than buffer: errno %d", errno);

        noise.rx_nonce = 5;  /* f1 was sealed with nonce 0 */
        script(s4, 1);
        CHECK(noise_recv_impl(&g_ml, &noise, NULL, 65535, &out) < 0 && errno == EBADMSG,
              "decrypt failure: errno %d", errno);
        CHECK(noise.rx_nonce == 5, "rx_nonce moved on a failed decrypt");
        free(out);
        out = NULL;
    }
}

static void test_complete_proactive(void) {
    /* EarlyNoise as Tailscale sends it: magic, length, JSON, then SETTINGS */
    uint8_t f0[64], f1[64], f2[256], n3[64], json[95];
    memset(json, 'j', sizeof(json));
    size_t l0 = make_frame(f0, 0x04, (const uint8_t *)"\xff\xff\xffTS", 5, 0);
    size_t l1 = make_frame(f1, 0x04, (const uint8_t *)"\0\0\0\x5f", 4, 1);
    size_t l2 = make_frame(f2, 0x04, json, sizeof(json), 2);
    size_t l3 = make_frame(n3, 0x04, (const uint8_t *)"settings!", 9, 3);
    uint8_t all[512];
    size_t total = 0;
    memcpy(all + total, f0, l0); total += l0;
    memcpy(all + total, f1, l1); total += l1;
    memcpy(all + total, f2, l2); total += l2;

    /* Cut in F2's payload: its rest is read, the next frame is left alone */
    for (size_t cut = l0 + l1 + 1; cut < total; cut += 7) {
        uint8_t *buf = malloc(cut);
        memcpy(buf, all, cut);
        int len = (int)cut;
        const step_t s[] = { { S_DATA, all + cut, total - cut, 0, 0, 0 }, { S_DATA, n3, l3, 0, 0, 0 } };
        script(s, 2);
        int r = complete_proactive_frames(&g_ml, &buf, &len);
        CHECK(r == 0 && len == (int)total && memcmp(buf, all, total) == 0, "cut at %d: r %d len %d",
              (int)cut, r, len);
        CHECK(g_step == 1 && g_step_off == 0, "cut at %d: read past the frame", (int)cut);
        free(buf);
    }

    /* Cut inside a frame header, arriving a byte at a time */
    for (size_t cut = l0 + 1; cut < l0 + 3; cut++) {
        uint8_t *buf = malloc(cut);
        memcpy(buf, all, cut);
        int len = (int)cut;
        step_t s[200];
        int n = 0;
        for (size_t i = cut; i < l0 + l1; i++) s[n++] = (step_t){ S_DATA, all + i, 1, 0, 0, 0 };
        s[n++] = (step_t){ S_DATA, f2, l2, 0, 0, 0 };
        script(s, n);
        int r = complete_proactive_frames(&g_ml, &buf, &len);
        CHECK(r == 0 && len == (int)(l0 + l1) && memcmp(buf, all, l0 + l1) == 0,
              "header cut at %d: r %d len %d", (int)cut, r, len);
        CHECK(g_step == n - 1 && g_step_off == 0, "header cut at %d: read past the frame", (int)cut);
        free(buf);
    }

    /* Already whole: nothing read */
    {
        uint8_t *buf = malloc(total);
        memcpy(buf, all, total);
        int len = (int)total;
        script(NULL, 0);
        CHECK(complete_proactive_frames(&g_ml, &buf, &len) == 0 && len == (int)total && g_recv_calls == 0,
              "whole buffer");
        free(buf);
    }

    /* A frame that would take more than 16 KB: refused without reading */
    {
        uint8_t *buf = malloc(l0 + 3);
        memcpy(buf, f0, l0);
        buf[l0] = 0x04; buf[l0 + 1] = 0xff; buf[l0 + 2] = 0xff;
        int len = (int)(l0 + 3);
        script(NULL, 0);
        CHECK(complete_proactive_frames(&g_ml, &buf, &len) < 0 && g_recv_calls == 0, "oversized frame");
        free(buf);
    }

    /* The rest never comes: fails, bounded */
    {
        size_t cut = l0 + 5;
        uint8_t *buf = malloc(cut);
        memcpy(buf, all, cut);
        int len = (int)cut;
        script(NULL, 0);
        uint64_t t0 = g_now_ms;
        CHECK(complete_proactive_frames(&g_ml, &buf, &len) < 0, "missing rest accepted");
        CHECK(g_now_ms - t0 <= 33000, "missing rest took %lu ms", (unsigned long)(g_now_ms - t0));
        free(buf);
    }
}

int main(int argc, char **argv) {
    g_verbose = argc > 1 && strcmp(argv[1], "-v") == 0;
    g_ml.coord_sock = 3;
    test_parse_key32();
    test_fmt_i64();
    test_coord_recv();
    test_noise_recv();
    test_complete_proactive();
    printf("%d checks, %d failed\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
