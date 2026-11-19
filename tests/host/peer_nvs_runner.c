/*
 * Host test for the NVS peer cache (ml_peer_nvs.c), built against a fake NVS
 * by check_coord_robustness.py. The stub headers it writes stand in for
 * tailtiny_internal.h, esp_log.h and nvs.h; the blob store is here.
 *
 * What must hold: a stored table is loaded only when its length matches its
 * entry count exactly and the count fits the table. Anything else (a count
 * larger than the blob or the table, a blob shorter than its header) is
 * dropped rather than read past, and the next save writes a valid table.
 * A stored endpoint count above 2 is clamped to the 2 endpoints stored.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tailtiny_internal.h"
#include "nvs.h"

/* Same layout as ml_peer_nvs.c's (checked by size below) */
typedef struct __attribute__((packed)) {
    uint32_t vpn_ip;
    uint8_t public_key[32];
    uint8_t disco_key[32];
    uint16_t derp_region;
    struct { uint32_t ip; uint16_t port; } __attribute__((packed)) endpoints[2];
    uint8_t endpoint_count;
    char hostname_short[7];
    uint16_t lru_counter;
} entry_t;
_Static_assert(sizeof(entry_t) == 92, "NVS entry layout changed");

/* ---- fake NVS: one blob ---- */
static uint8_t g_blob[200000];
static size_t g_blob_len;
static int g_has_blob, g_writes;

esp_err_t nvs_open(const char *ns, nvs_open_mode_t mode, nvs_handle_t *h) {
    (void)ns; (void)mode;
    *h = 1;
    return ESP_OK;
}
void nvs_close(nvs_handle_t h) { (void)h; }
esp_err_t nvs_commit(nvs_handle_t h) { (void)h; return ESP_OK; }
esp_err_t nvs_erase_all(nvs_handle_t h) { (void)h; g_has_blob = 0; return ESP_OK; }
esp_err_t nvs_get_blob(nvs_handle_t h, const char *key, void *out, size_t *len) {
    (void)h; (void)key;
    if (!g_has_blob) return ESP_ERR_NVS_NOT_FOUND;
    if (!out) { *len = g_blob_len; return ESP_OK; }
    if (*len < g_blob_len) { *len = g_blob_len; return ESP_ERR_NVS_INVALID_LENGTH; }
    memcpy(out, g_blob, g_blob_len);
    *len = g_blob_len;
    return ESP_OK;
}
esp_err_t nvs_set_blob(nvs_handle_t h, const char *key, const void *val, size_t len) {
    (void)h; (void)key;
    memcpy(g_blob, val, len);
    g_blob_len = len;
    g_has_blob = 1;
    g_writes++;
    return ESP_OK;
}

void *ml_psram_calloc(size_t n, size_t size) { return calloc(n, size); }
void tailtiny_ip_to_str(uint32_t ip, char *buf) {
    sprintf(buf, "%u.%u.%u.%u", (unsigned)(ip >> 24), (unsigned)(ip >> 16 & 255),
            (unsigned)(ip >> 8 & 255), (unsigned)(ip & 255));
}

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

/* A stored table: header claiming `count`, followed by `stored` entries */
static void store(unsigned count, unsigned stored, uint8_t ep_count) {
    uint16_t hdr[2] = { (uint16_t)count, 7 };
    memcpy(g_blob, hdr, sizeof(hdr));
    for (unsigned i = 0; i < stored; i++) {
        entry_t e;
        memset(&e, 0, sizeof(e));
        e.vpn_ip = 0x64400001u + i;
        memset(e.public_key, 0x10 + i, 32);
        memset(e.disco_key, 0x80 + i, 32);
        e.derp_region = 1;
        e.endpoints[0].ip = 0xC0A80001u + i;
        e.endpoints[0].port = 41641;
        e.endpoints[1].ip = 0x08080808u;
        e.endpoints[1].port = 1000 + i;
        e.endpoint_count = ep_count;
        memcpy(e.hostname_short, "peer", 5);
        e.lru_counter = (uint16_t)i;
        memcpy(g_blob + sizeof(hdr) + i * sizeof(e), &e, sizeof(e));
    }
    g_blob_len = sizeof(hdr) + stored * sizeof(entry_t);
    g_has_blob = 1;
}

static ml_peer_t g_peers[64];

static int load(void) {
    ml_peer_nvs_deinit();
    CHECK(ml_peer_nvs_init() == ESP_OK, "init");
    memset(g_peers, 0xAB, sizeof(g_peers));
    return ml_peer_nvs_load_all(g_peers, 64);
}

int main(void) {
    /* A valid table loads */
    store(2, 2, 2);
    CHECK(load() == 2, "valid table");
    CHECK(g_peers[1].vpn_ip == 0x64400002u && g_peers[1].endpoint_count == 2 &&
          g_peers[1].endpoints[1].port == 1001 && strcmp(g_peers[1].hostname, "peer") == 0,
          "valid table contents");

    /* No table at all */
    g_has_blob = 0;
    CHECK(load() == 0, "no table");

    /* Count larger than the table: was read past the table's end */
    store(1000, 2, 2);
    CHECK(load() == 0, "count 1000");
    /* Count larger than the entries stored */
    store(3, 2, 2);
    CHECK(load() == 0, "count 3, 2 stored");
    /* Fewer entries claimed than stored (another layout) */
    store(1, 2, 2);
    CHECK(load() == 0, "count 1, 2 stored");
    /* Blob shorter than its header */
    store(0, 0, 0);
    g_blob_len = 2;
    CHECK(load() == 0, "2-byte blob");
    /* Empty but valid */
    store(0, 0, 0);
    CHECK(load() == 0, "empty table");
    /* Larger than the table (NVS refuses to read it) */
    store(CONFIG_ML_NVS_MAX_PEERS + 4, CONFIG_ML_NVS_MAX_PEERS + 4, 2);
    CHECK(load() == 0, "table larger than ML_NVS_MAX_PEERS");
    /* Exactly full */
    store(CONFIG_ML_NVS_MAX_PEERS, CONFIG_ML_NVS_MAX_PEERS, 2);
    CHECK(load() == CONFIG_ML_NVS_MAX_PEERS, "full table");

    /* Endpoint count above the 2 stored: clamped */
    store(1, 1, 200);
    CHECK(load() == 1 && g_peers[0].endpoint_count == 2, "endpoint count %d", g_peers[0].endpoint_count);

    /* After a dropped table, a save writes a valid one-entry table */
    store(1000, 2, 2);
    CHECK(load() == 0, "count 1000 again");
    ml_peer_t p;
    memset(&p, 0, sizeof(p));
    p.vpn_ip = 0x64400099u;
    memset(p.public_key, 0x42, 32);
    strcpy(p.hostname, "fresh");
    g_writes = 0;
    CHECK(ml_peer_nvs_save(&p) == ESP_OK && g_writes == 1, "save after drop");
    CHECK(g_blob_len == 4 + sizeof(entry_t) && ((uint16_t *)g_blob)[0] == 1,
          "saved table: %u bytes, count %u", (unsigned)g_blob_len, (unsigned)((uint16_t *)g_blob)[0]);
    CHECK(load() == 1 && g_peers[0].vpn_ip == 0x64400099u, "saved table reloads");

    /* Remove still works on a loaded table */
    store(2, 2, 2);
    load();
    uint8_t k0[32];
    memset(k0, 0x10, 32);
    CHECK(ml_peer_nvs_remove(k0) == ESP_OK && load() == 1 && g_peers[0].vpn_ip == 0x64400002u, "remove");

    ml_peer_nvs_deinit();
    printf("%d checks, %d failed\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
