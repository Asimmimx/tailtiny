/**
 * @file ml_at_validate.h
 * @brief Checks for values that go inside modem AT commands
 *
 * The APN, the PPP user name and password, the SIM PIN and host names are
 * put inside quoted AT command arguments (AT+CGDCONT, AT+CGAUTH, AT+CPIN,
 * AT+CDNSGIP). A '"' would close the argument and a CR/LF would end the
 * command line, so a crafted value (from the config web UI, NVS or the
 * control server's DERP map) could run any AT command on the modem: radio
 * off, SIM lock, SMS, baud rate change. Every such value must pass one of
 * these checks first.
 *
 * Plain C without ESP-IDF, so tests/host/check_config_guard.py runs it on
 * the PC. Ported from upstream MicroLink (9fd9991).
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Longest value each check accepts */
#define ML_AT_APN_MAX        100   /* 3GPP TS 23.003 9.1: APN <= 100 octets */
#define ML_AT_PIN_MIN        4
#define ML_AT_PIN_MAX        8
#define ML_AT_HOSTNAME_MAX   253   /* RFC 1035/1123 */
#define ML_AT_CRED_MAX       64    /* PPP user name / password */

typedef enum {
    ML_AT_PARAM_APN,        /* labels of [A-Za-z0-9-] separated by '.', may be empty */
    ML_AT_PARAM_PIN,        /* 4-8 decimal digits */
    ML_AT_PARAM_HOSTNAME,   /* RFC 1123 host name (or IPv4 literal), not empty */
    ML_AT_PARAM_CREDENTIAL, /* printable ASCII except '"' and '\\', may be empty */
} ml_at_param_kind_t;

/**
 * Baseline check for any string that goes inside a quoted AT argument:
 * not NULL, at most @p maxlen bytes, only printable ASCII (0x20-0x7E), and
 * no '"' or '\\' (some modems read "\XX" inside a string as a hex escape).
 * CR, LF, Ctrl-Z, ESC and bytes >= 0x80 are refused. "" passes.
 */
bool ml_at_is_safe_param(const char *s, size_t maxlen);

/**
 * Type-specific check. @p maxlen limits the length further (pass the
 * destination buffer size minus one), or 0 for the type's own limit.
 */
bool ml_at_param_valid(ml_at_param_kind_t kind, const char *s, size_t maxlen);

static inline bool ml_at_valid_apn(const char *s) {
    return ml_at_param_valid(ML_AT_PARAM_APN, s, 0);
}
static inline bool ml_at_valid_pin(const char *s) {
    return ml_at_param_valid(ML_AT_PARAM_PIN, s, 0);
}
static inline bool ml_at_valid_hostname(const char *s) {
    return ml_at_param_valid(ML_AT_PARAM_HOSTNAME, s, 0);
}
static inline bool ml_at_valid_credential(const char *s) {
    return ml_at_param_valid(ML_AT_PARAM_CREDENTIAL, s, 0);
}

/** Zero a buffer that held a secret (the compiler can't drop the writes). */
void ml_at_secure_zero(void *buf, size_t len);

#ifdef __cplusplus
}
#endif
