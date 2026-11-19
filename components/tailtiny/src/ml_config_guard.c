/**
 * @file ml_config_guard.c
 * @brief Request checks for the config web server (ml_config_httpd.c)
 *
 * No ESP-IDF dependencies: tests/host/check_config_guard.py builds it on
 * the PC.
 */

#include "ml_config_guard.h"

#include <stddef.h>
#include <string.h>

/* Longest decoded "user:password" accepted in an Authorization header */
#define AUTH_DECODED_MAX  192

static bool is_digit(char c) { return c >= '0' && c <= '9'; }
static bool is_blank(char c) { return c == ' ' || c == '\t'; }
static char to_lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c; }

/* Case-insensitive prefix test (HTTP scheme and media type names) */
static bool starts_with_ci(const char *s, const char *prefix)
{
    for (; *prefix; s++, prefix++) {
        if (to_lower(*s) != to_lower(*prefix)) return false;
    }
    return true;
}

/* Header values may end in blanks (esp_http_server strips only the
 * leading ones). */
static bool only_blanks(const char *s)
{
    while (is_blank(*s)) s++;
    return *s == '\0';
}

static void wipe(void *buf, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) *p++ = 0;
}

/* ============================================================================
 * Host header
 * ========================================================================== */

bool ml_config_host_is_local_ip(const char *host, uint32_t local_ip)
{
    if (!host || local_ip == 0) return false;

    /* Strict dotted quad: four decimal parts of 1-3 digits, each <= 255,
     * no leading zeros (some parsers read those as octal). Browsers always
     * send an IP host in this form. */
    const char *p = host;
    uint32_t ip = 0;
    for (int part = 0; part < 4; part++) {
        if (!is_digit(*p)) return false;
        if (*p == '0' && is_digit(p[1])) return false;
        unsigned v = 0;
        int n = 0;
        while (is_digit(*p)) {
            if (++n > 3) return false;
            v = v * 10 + (unsigned)(*p - '0');
            p++;
        }
        if (v > 255) return false;
        ip = (ip << 8) | v;
        if (part < 3) {
            if (*p != '.') return false;
            p++;
        }
    }

    /* Optional ":port", 1-5 digits, <= 65535 */
    if (*p == ':') {
        p++;
        unsigned long port = 0;
        int n = 0;
        while (is_digit(*p)) {
            if (++n > 5) return false;
            port = port * 10 + (unsigned long)(*p - '0');
            p++;
        }
        if (n == 0 || port > 65535) return false;
    }

    return only_blanks(p) && ip == local_ip;
}

/* ============================================================================
 * HTTP Basic auth
 * ========================================================================== */

static int b64_value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Standard base64 (RFC 4648 section 4), with or without '=' padding.
 * False on any other character, misplaced padding or a full @p out. */
static bool b64_decode(const char *in, size_t len, uint8_t *out, size_t out_size, size_t *out_len)
{
    size_t pad = 0;
    while (len > 0 && in[len - 1] == '=' && pad < 2) {
        len--;
        pad++;
    }
    if (pad && (len + pad) % 4 != 0) return false;
    if (len % 4 == 1) return false;

    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0;
    for (size_t i = 0; i < len; i++) {
        int v = b64_value(in[i]);
        if (v < 0) return false;            /* also a '=' before the end */
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= out_size) return false;
            out[n++] = (uint8_t)(acc >> bits);
        }
    }
    *out_len = n;
    return true;
}

/* Compare what the client sent (@p a) with the secret (@p b, blen > 0).
 * The time depends only on @p alen, which the client chose, not on the
 * secret or on where the first difference is. */
static bool ct_equal(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
    uint8_t diff = (uint8_t)(alen != blen);
    for (size_t i = 0; i < alen; i++) {
        diff |= (uint8_t)(a[i] ^ b[i % blen]);
    }
    return diff == 0;
}

bool ml_config_basic_auth_ok(const char *authorization, const char *password)
{
    if (!authorization || !password || password[0] == '\0') return false;

    /* "Basic" (any case), blanks, then the base64 token */
    if (!starts_with_ci(authorization, "basic") || !is_blank(authorization[5])) return false;
    const char *tok = authorization + 5;
    while (is_blank(*tok)) tok++;
    size_t tok_len = 0;
    while (tok[tok_len] != '\0' && !is_blank(tok[tok_len])) tok_len++;
    if (tok_len == 0 || !only_blanks(tok + tok_len)) return false;

    uint8_t dec[AUTH_DECODED_MAX];
    size_t dec_len = 0;
    bool ok = false;
    if (b64_decode(tok, tok_len, dec, sizeof(dec), &dec_len)) {
        /* "user:password": the password is everything after the first ':' */
        const uint8_t *colon = memchr(dec, ':', dec_len);
        if (colon) {
            const uint8_t *pw = colon + 1;
            size_t pw_len = dec_len - (size_t)(pw - dec);
            ok = ct_equal(pw, pw_len, (const uint8_t *)password, strlen(password));
        }
    }
    wipe(dec, sizeof(dec));
    return ok;
}

/* ============================================================================
 * Content-Type and addresses
 * ========================================================================== */

bool ml_config_content_type_is_json(const char *content_type)
{
    static const char json[] = "application/json";
    if (!content_type || !starts_with_ci(content_type, json)) return false;
    const char *p = content_type + sizeof(json) - 1;
    while (is_blank(*p)) p++;
    return *p == '\0' || *p == ';';
}

bool ml_config_ipv4_from_mapped(const uint8_t addr[16], uint32_t *ip_out)
{
    static const uint8_t prefix[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    if (memcmp(addr, prefix, sizeof(prefix)) != 0) return false;
    *ip_out = ((uint32_t)addr[12] << 24) | ((uint32_t)addr[13] << 16) |
              ((uint32_t)addr[14] << 8) | (uint32_t)addr[15];
    return true;
}
