/*
 * Host test for the peer updates ml_coord.c makes from a MapResponse.
 * Built and run by check_coord_robustness.py with ESP-IDF's cJSON: it copies
 * parse_peers_from_map_response(), queue_peer_patch() and the key helpers
 * out of ml_coord.c (into coord_peers_extract.c) and ml_peer_update_t out of
 * tailtiny_internal.h. Queued updates are collected here instead of going to
 * the WireGuard task.
 *
 * What must hold:
 *   1. A full "Peers" list ends with a SWEEP only when every record was
 *      queued. A record with a missing, malformed or all-zero Key, or a
 *      malformed DiscoKey, is not queued (it would replace the working peer
 *      with that NodeID) and there is no SWEEP after it (which would remove
 *      that peer as missing).
 *   2. A missing DiscoKey still adds the peer, with a zero DISCO key.
 *   3. PeersRemoved skips a malformed key; NodeIDs and good keys are queued.
 *   4. A PeersChangedPatch with a malformed DiscoKey leaves it zero (the
 *      WireGuard task reads that as unchanged); one named by a malformed
 *      node key is not queued.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

#include "peer_update_type.h"   /* ML_MAX_ENDPOINTS, ml_peer_update_t from tailtiny_internal.h */

typedef struct {
    int peer_update_queue;
} tailtiny_t;

static const char *TAG = "ml_coord";
static int g_verbose;
static void test_log(const char *lvl, const char *fmt, ...) {
    if (!g_verbose) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "  [%s] ", lvl);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}
#define ESP_LOGE(tag, fmt, ...) do { (void)(tag); test_log("E", fmt, ##__VA_ARGS__); } while (0)
#define ESP_LOGW(tag, fmt, ...) do { (void)(tag); test_log("W", fmt, ##__VA_ARGS__); } while (0)
#define ESP_LOGI(tag, fmt, ...) do { (void)(tag); test_log("I", fmt, ##__VA_ARGS__); } while (0)
#define ESP_LOGD(tag, fmt, ...) do { (void)(tag); test_log("D", fmt, ##__VA_ARGS__); } while (0)

#define pdTRUE 1
#define pdMS_TO_TICKS(ms) (ms)
static void *ml_psram_calloc(size_t n, size_t size) { return calloc(n, size); }
static void tailtiny_ip_to_str(uint32_t ip, char *buf) {
    sprintf(buf, "%u.%u.%u.%u", (unsigned)(ip >> 24), (unsigned)(ip >> 16 & 255),
            (unsigned)(ip >> 8 & 255), (unsigned)(ip & 255));
}
static int64_t g_time_hint;
static void wireguard_set_time_hint(int64_t t) { g_time_hint = t; }

/* The queue: updates are kept here */
static ml_peer_update_t *g_q[64];
static int g_qn;
static int ml_wg_queue_send(tailtiny_t *ml, int queue, ml_peer_update_t *const *item, int wait) {
    (void)ml; (void)queue; (void)wait;
    if (g_qn >= 64) return 0;
    g_q[g_qn++] = *item;
    return pdTRUE;
}
static void q_clear(void) {
    for (int i = 0; i < g_qn; i++) free(g_q[i]);
    g_qn = 0;
}

#include "coord_peers_extract.c"

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

static tailtiny_t g_ml;

static void run(const char *json) {
    q_clear();
    cJSON *root = cJSON_Parse(json);
    if (!root) {
        printf("FAIL: test JSON doesn't parse: %s\n", json);
        g_failures++;
        return;
    }
    parse_peers_from_map_response(&g_ml, root);
    cJSON_Delete(root);
}

static int count(int action) {
    int n = 0;
    for (int i = 0; i < g_qn; i++) n += (int)g_q[i]->action == action;
    return n;
}

static bool all(const uint8_t *k, uint8_t v) {
    for (int i = 0; i < 32; i++) if (k[i] != v) return false;
    return true;
}

#define K1 "1111111111111111111111111111111111111111111111111111111111111111"
#define K2 "2222222222222222222222222222222222222222222222222222222222222222"
#define D1 "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
#define Z64 "0000000000000000000000000000000000000000000000000000000000000000"
#define PEER(id, name, key, disco) \
    "{\"ID\":" #id ",\"Name\":\"" name ".\",\"Key\":" key "," disco \
    "\"Addresses\":[\"100.64.0." #id "/32\"],\"HomeDERP\":1}"

int main(int argc, char **argv) {
    g_verbose = argc > 1 && strcmp(argv[1], "-v") == 0;

    /* Good list: both added, then a SWEEP of the same generation */
    run("{\"ControlTime\":\"2026-11-19T12:00:00Z\",\"Peers\":["
        PEER(1, "a", "\"nodekey:" K1 "\"", "\"DiscoKey\":\"discokey:" D1 "\",")
        "," PEER(2, "b", "\"nodekey:" K2 "\"", "\"DiscoKey\":\"discokey:" D1 "\",") "]}");
    CHECK(count(ML_PEER_ADD) == 2 && count(ML_PEER_SWEEP) == 1, "good list: %d adds %d sweeps",
          count(ML_PEER_ADD), count(ML_PEER_SWEEP));
    CHECK(g_qn == 3 && g_q[2]->action == ML_PEER_SWEEP && g_q[2]->sync_gen == g_q[0]->sync_gen &&
          g_q[0]->sync_gen != 0, "sweep last, same generation");
    CHECK(all(g_q[0]->public_key, 0x11) && all(g_q[0]->disco_key, 0xdd) && g_q[0]->node_id == 1 &&
          g_q[0]->vpn_ip == 0x64400001u && strcmp(g_q[0]->hostname, "a") == 0, "peer a fields");
    CHECK(g_time_hint == 1795089600, "ControlTime %ld", (long)g_time_hint);

    /* Bad Key in a full list: that record dropped, and no SWEEP */
    const char *bad_keys[] = {
        "\"nodekey:" "111111111111111111111111111111111111111111111111111111111111111" "\"",   /* 63 */
        "\"nodekey:" K1 "0\"",                                                                    /* 65 */
        "\"nodekey:" "g111111111111111111111111111111111111111111111111111111111111111" "\"",
        "\"nodekey:" Z64 "\"",
        "\"\"",
        "12345",
        "null",
    };
    for (size_t i = 0; i < sizeof(bad_keys) / sizeof(bad_keys[0]); i++) {
        char json[2048];
        snprintf(json, sizeof(json), "{\"Peers\":[%s,{\"ID\":2,\"Name\":\"b.\",\"Key\":%s,"
                 "\"DiscoKey\":\"discokey:" D1 "\",\"Addresses\":[\"100.64.0.2/32\"]}]}",
                 PEER(1, "a", "\"nodekey:" K1 "\"", "\"DiscoKey\":\"discokey:" D1 "\","), bad_keys[i]);
        run(json);
        CHECK(count(ML_PEER_ADD) == 1 && count(ML_PEER_SWEEP) == 0 && all(g_q[0]->public_key, 0x11),
              "bad key %s: %d adds %d sweeps", bad_keys[i], count(ML_PEER_ADD), count(ML_PEER_SWEEP));
    }
    /* No Key member at all */
    run("{\"Peers\":[{\"ID\":2,\"Name\":\"b.\",\"Addresses\":[\"100.64.0.2/32\"]}]}");
    CHECK(g_qn == 0, "missing Key: %d queued", g_qn);

    /* Bad DiscoKey: record dropped, no SWEEP */
    run("{\"Peers\":[" PEER(1, "a", "\"nodekey:" K1 "\"", "\"DiscoKey\":\"discokey:dddd\",") "]}");
    CHECK(g_qn == 0, "bad DiscoKey: %d queued", g_qn);
    /* Missing DiscoKey: added as before, with a zero DISCO key */
    run("{\"Peers\":[" PEER(1, "a", "\"nodekey:" K1 "\"", "") "]}");
    CHECK(count(ML_PEER_ADD) == 1 && count(ML_PEER_SWEEP) == 1 && all(g_q[0]->disco_key, 0),
          "missing DiscoKey");
    /* A zero DiscoKey (a node that never sent one) is a valid key */
    run("{\"Peers\":[" PEER(1, "a", "\"nodekey:" K1 "\"", "\"DiscoKey\":\"discokey:" Z64 "\",") "]}");
    CHECK(count(ML_PEER_ADD) == 1 && count(ML_PEER_SWEEP) == 1, "zero DiscoKey");

    /* Deltas never sweep; a bad record there is dropped too */
    run("{\"PeersChanged\":[" PEER(1, "a", "\"nodekey:" K1 "\"", "") ","
        PEER(2, "b", "\"nodekey:22\"", "") "]}");
    CHECK(count(ML_PEER_ADD) == 1 && count(ML_PEER_SWEEP) == 0, "PeersChanged");

    /* PeersRemoved: NodeIDs and good keys queued, a bad key skipped */
    run("{\"PeersRemoved\":[4955372421395013,\"nodekey:" K2 "\",\"nodekey:2222\",\"" K1 "\"]}");
    CHECK(count(ML_PEER_REMOVE) == 3, "PeersRemoved: %d", count(ML_PEER_REMOVE));
    CHECK(g_qn == 3 && g_q[0]->node_id == 4955372421395013LL && all(g_q[1]->public_key, 0x22) &&
          all(g_q[2]->public_key, 0x11), "PeersRemoved contents");

    /* Patches: a bad DiscoKey stays zero ("unchanged"), a good one is taken */
    run("{\"PeersChangedPatch\":[{\"NodeID\":5,\"DiscoKey\":\"discokey:dd\",\"DERPRegion\":3},"
        "{\"NodeID\":6,\"DiscoKey\":\"discokey:" D1 "\"}]}");
    CHECK(count(ML_PEER_UPDATE_ENDPOINT) == 2, "patches: %d", count(ML_PEER_UPDATE_ENDPOINT));
    CHECK(g_qn == 2 && g_q[0]->node_id == 5 && all(g_q[0]->disco_key, 0) && g_q[0]->derp_region == 3,
          "patch with bad DiscoKey");
    CHECK(g_qn == 2 && g_q[1]->node_id == 6 && all(g_q[1]->disco_key, 0xdd), "patch with good DiscoKey");
    /* The old object form names its peer by node key */
    run("{\"PeersChangedPatch\":{\"nodekey:12\":{\"DERPRegion\":2},\"nodekey:" K1 "\":{\"DERPRegion\":4}}}");
    CHECK(g_qn == 1 && all(g_q[0]->public_key, 0x11) && g_q[0]->derp_region == 4, "object-form patches");

    /* OnlineChange is unaffected */
    run("{\"OnlineChange\":{\"4955372421395013\":true,\"7\":false}}");
    CHECK(g_qn == 2 && g_q[0]->node_id == 4955372421395013LL && g_q[0]->online == 1 &&
          g_q[1]->online == 0, "OnlineChange");

    q_clear();
    printf("%d checks, %d failed\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
