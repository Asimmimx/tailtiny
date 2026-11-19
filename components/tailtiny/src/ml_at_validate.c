/**
 * @file ml_at_validate.c
 * @brief Checks for values that go inside modem AT commands
 *
 * No ESP-IDF dependencies: tests/host/check_config_guard.py builds it on
 * the PC. Ported from upstream MicroLink (9fd9991).
 */

#include "ml_at_validate.h"

#include <stdint.h>

/* No <ctype.h>: the result must not depend on the C library's locale or
 * on how it treats bytes >= 0x80. */
static bool is_digit(char c) { return c >= '0' && c <= '9'; }
static bool is_alnum(char c) {
    return is_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
static bool is_print(char c) { return c >= 0x20 && c <= 0x7E; }

/* strlen that stops at limit + 1, so a value without a terminator is never
 * read past limit + 1 bytes and "too long" shows as a result > limit. */
static size_t bounded_len(const char *s, size_t limit)
{
    size_t n = 0;
    while (n <= limit && s[n] != '\0') n++;
    return n;
}

static size_t effective_max(size_t type_max, size_t caller_max)
{
    return (caller_max != 0 && caller_max < type_max) ? caller_max : type_max;
}

/* DNS-style labels: [A-Za-z0-9-], 1 to 63 characters, not starting or
 * ending with '-', separated by single dots, no dot at either end. */
static bool valid_label_list(const char *s, size_t len)
{
    size_t label_len = 0;
    char prev = '.';
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '.') {
            if (label_len == 0 || prev == '-') return false;
            label_len = 0;
        } else if (is_alnum(c) || c == '-') {
            if (label_len == 0 && c == '-') return false;
            if (++label_len > 63) return false;
        } else {
            return false;
        }
        prev = c;
    }
    return label_len > 0 && prev != '-';
}

bool ml_at_is_safe_param(const char *s, size_t maxlen)
{
    if (!s) return false;
    size_t len = bounded_len(s, maxlen);
    if (len > maxlen) return false;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!is_print(c) || c == '"' || c == '\\') return false;
    }
    return true;
}

bool ml_at_param_valid(ml_at_param_kind_t kind, const char *s, size_t maxlen)
{
    if (!s) return false;

    switch (kind) {
    case ML_AT_PARAM_APN: {
        size_t max = effective_max(ML_AT_APN_MAX, maxlen);
        size_t len = bounded_len(s, max);
        if (len > max) return false;
        if (len == 0) return true;      /* empty = the network's default APN */
        return valid_label_list(s, len);
    }
    case ML_AT_PARAM_PIN: {
        size_t max = effective_max(ML_AT_PIN_MAX, maxlen);
        size_t len = bounded_len(s, max);
        if (len < ML_AT_PIN_MIN || len > max) return false;
        for (size_t i = 0; i < len; i++) {
            if (!is_digit(s[i])) return false;
        }
        return true;
    }
    case ML_AT_PARAM_HOSTNAME: {
        size_t max = effective_max(ML_AT_HOSTNAME_MAX, maxlen);
        size_t len = bounded_len(s, max);
        if (len == 0 || len > max) return false;
        return valid_label_list(s, len);
    }
    case ML_AT_PARAM_CREDENTIAL:
        /* ';' and ',' are fine: they sit inside a quoted string that no
         * '"' can ever close early. */
        return ml_at_is_safe_param(s, effective_max(ML_AT_CRED_MAX, maxlen));
    }
    return false;
}

void ml_at_secure_zero(void *buf, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) *p++ = 0;
}
