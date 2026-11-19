/**
 * @file ml_config_guard.h
 * @brief Request checks for the config web server (ml_config_httpd.c)
 *
 * The parts of the access check that only look at strings and bytes: the
 * Host header, HTTP Basic auth, the Content-Type and IPv4-mapped IPv6
 * addresses. Plain C without ESP-IDF, so tests/host/check_config_guard.py
 * runs them on the PC.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * DNS-rebinding check. True if @p host (a Host header value) is the IPv4
 * address @p local_ip (host byte order) written as a plain dotted quad,
 * optionally followed by ":port". A host name never passes, also not one
 * made of hex digits only ("deadbeef.cafe"), and neither do IPv6 literals:
 * the device's addresses for this server are IPv4 only.
 */
bool ml_config_host_is_local_ip(const char *host, uint32_t local_ip);

/**
 * True if @p authorization (an Authorization header value) is HTTP Basic
 * auth whose password is @p password. The user name is not checked. The
 * comparison takes the same time wherever the first wrong byte is. An
 * empty @p password never matches.
 */
bool ml_config_basic_auth_ok(const char *authorization, const char *password);

/**
 * CSRF check. True if @p content_type is application/json, with or without
 * parameters such as "; charset=utf-8". A cross-site page can only send it
 * after a CORS preflight, which this server never answers.
 */
bool ml_config_content_type_is_json(const char *content_type);

/**
 * True if @p addr (16 bytes, network order) is an IPv4-mapped IPv6 address
 * (::ffff:a.b.c.d); then *ip_out is a.b.c.d in host byte order.
 */
bool ml_config_ipv4_from_mapped(const uint8_t addr[16], uint32_t *ip_out);

#ifdef __cplusplus
}
#endif
