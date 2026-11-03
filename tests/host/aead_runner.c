/* Runner for check_noise_aead.py: one AEAD operation per call, hex in, hex out.
 *
 *   aead_runner noise-seal <key> <counter> <ad> <plaintext>
 *   aead_runner noise-open <key> <counter> <ad> <sealed>
 *   aead_runner wg-seal    <key> <counter> <ad> <plaintext>
 *
 * noise-* go through ml_noise_aead.h (what ml_noise.c uses); wg-seal calls
 * wireguard-lwip's chacha20poly1305_encrypt() directly. <counter> is a 64-bit
 * hex number, "-" stands for empty data. Prints the result in hex, or "REFUSED"
 * when noise-open rejects the message. noise-open with an empty payload passes
 * a NULL output buffer, as ml_noise_read_msg2() does.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ml_noise_aead.h"

static size_t unhex(const char *s, uint8_t **out) {
    size_t n = strcmp(s, "-") == 0 ? 0 : strlen(s) / 2;
    *out = malloc(n + 1);
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        (*out)[i] = (uint8_t)v;
    }
    return n;
}

static void put(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "usage: aead_runner noise-seal|noise-open|wg-seal key counter ad data\n");
        return 2;
    }
    uint8_t *key, *ad, *data;
    if (unhex(argv[2], &key) != 32) {
        fprintf(stderr, "key must be 32 bytes\n");
        return 2;
    }
    uint64_t counter = strtoull(argv[3], NULL, 16);
    size_t ad_len = unhex(argv[4], &ad);
    size_t len = unhex(argv[5], &data);
    const uint8_t *adp = ad_len ? ad : NULL;  /* ml_coord.c passes NULL, 0 */

    if (strcmp(argv[1], "noise-seal") == 0) {
        uint8_t *out = malloc(len + 16);
        if (noise_aead_encrypt(key, counter, adp, ad_len, data, len, out) != 0) return 1;
        put(out, len + 16);
    } else if (strcmp(argv[1], "wg-seal") == 0) {
        uint8_t *out = malloc(len + 16);
        chacha20poly1305_encrypt(out, data, len, adp, ad_len, counter, key);
        put(out, len + 16);
    } else if (strcmp(argv[1], "noise-open") == 0) {
        size_t pt_len = len >= 16 ? len - 16 : 0;
        uint8_t *out = pt_len ? malloc(pt_len) : NULL;
        if (noise_aead_decrypt(key, counter, adp, ad_len, data, len, out) != 0) {
            printf("REFUSED\n");
        } else {
            put(out, pt_len);
        }
    } else {
        fprintf(stderr, "unknown operation %s\n", argv[1]);
        return 2;
    }
    return 0;
}
