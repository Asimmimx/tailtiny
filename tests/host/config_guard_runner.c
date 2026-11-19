/* Runs the config UI's request checks (ml_config_guard.c) and the AT
 * parameter checks (ml_at_validate.c) on the host. Built and run by
 * check_config_guard.py.
 *
 * Each line of stdin is one call; strings are hex so they can hold
 * quotes, CR/LF and bytes >= 0x80 ("-" is the empty string):
 *   param <kind> <hex> <maxlen>    kind: safe apn pin host cred
 *   null <kind>                    the same check with a NULL string
 *   hosthdr <hex> <local ip u32>   ml_config_host_is_local_ip()
 *   auth <hex header> <hex pw>     ml_config_basic_auth_ok()
 *   ctype <hex>                    ml_config_content_type_is_json()
 *   mapped <hex, 16 bytes>         ml_config_ipv4_from_mapped()
 *   zero                           ml_at_secure_zero() clears a buffer
 * and prints one line: 1 or 0 (mapped: "1 <ip u32>" or "0"). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "ml_at_validate.h"
#include "ml_config_guard.h"

/* Decode @p hex into a fresh NUL-terminated buffer of exactly len + 1
 * bytes (so a read past the end is a real overrun under a sanitizer). */
static char *unhex(const char *hex, size_t *len_out)
{
    size_t n = (strcmp(hex, "-") == 0) ? 0 : strlen(hex) / 2;
    char *out = malloc(n + 1);
    if (!out) exit(2);
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) exit(2);
        out[i] = (char)v;
    }
    out[n] = '\0';
    if (len_out) *len_out = n;
    return out;
}

static int kind_of(const char *k, ml_at_param_kind_t *kind)
{
    if (strcmp(k, "apn") == 0) { *kind = ML_AT_PARAM_APN; return 1; }
    if (strcmp(k, "pin") == 0) { *kind = ML_AT_PARAM_PIN; return 1; }
    if (strcmp(k, "host") == 0) { *kind = ML_AT_PARAM_HOSTNAME; return 1; }
    if (strcmp(k, "cred") == 0) { *kind = ML_AT_PARAM_CREDENTIAL; return 1; }
    return 0;
}

int main(void)
{
    char op[16], a[2048], b[2048];
    while (scanf("%15s", op) == 1) {
        if (strcmp(op, "param") == 0 || strcmp(op, "null") == 0) {
            char k[16];
            unsigned long maxlen = 0;
            if (scanf("%15s", k) != 1) return 2;
            char *s = NULL;
            if (op[0] == 'p') {
                if (scanf("%2047s %lu", a, &maxlen) != 2) return 2;
                s = unhex(a, NULL);
            }
            ml_at_param_kind_t kind;
            bool r;
            if (strcmp(k, "safe") == 0) r = ml_at_is_safe_param(s, maxlen);
            else if (kind_of(k, &kind)) r = ml_at_param_valid(kind, s, maxlen);
            else return 2;
            printf("%d\n", r ? 1 : 0);
            free(s);
        } else if (strcmp(op, "hosthdr") == 0) {
            unsigned long ip;
            if (scanf("%2047s %lu", a, &ip) != 2) return 2;
            char *s = unhex(a, NULL);
            printf("%d\n", ml_config_host_is_local_ip(s, (uint32_t)ip) ? 1 : 0);
            free(s);
        } else if (strcmp(op, "auth") == 0) {
            if (scanf("%2047s %2047s", a, b) != 2) return 2;
            char *h = unhex(a, NULL), *pw = unhex(b, NULL);
            printf("%d\n", ml_config_basic_auth_ok(h, pw) ? 1 : 0);
            free(h);
            free(pw);
        } else if (strcmp(op, "ctype") == 0) {
            if (scanf("%2047s", a) != 1) return 2;
            char *s = unhex(a, NULL);
            printf("%d\n", ml_config_content_type_is_json(s) ? 1 : 0);
            free(s);
        } else if (strcmp(op, "mapped") == 0) {
            size_t n;
            if (scanf("%2047s", a) != 1) return 2;
            char *s = unhex(a, &n);
            if (n != 16) return 2;
            uint32_t ip = 0;
            if (ml_config_ipv4_from_mapped((const uint8_t *)s, &ip)) printf("1 %lu\n", (unsigned long)ip);
            else printf("0\n");
            free(s);
        } else if (strcmp(op, "zero") == 0) {
            char buf[32];
            memset(buf, 0x5A, sizeof(buf));
            ml_at_secure_zero(buf, sizeof(buf));
            int clear = 1;
            for (size_t i = 0; i < sizeof(buf); i++) clear &= (buf[i] == 0);
            printf("%d\n", clear);
        } else {
            return 2;
        }
        fflush(stdout);
    }
    return 0;
}
