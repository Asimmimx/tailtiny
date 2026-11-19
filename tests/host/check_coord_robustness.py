#!/usr/bin/env python3
"""Checks the control connection's reads, key parsing and the NVS peer cache.

    python tests/host/check_coord_robustness.py [-v]

Needs gcc (or set CC). No ESP-IDF needed.

1. Copies the functions under test out of components/tailtiny/src/ml_coord.c
   (so it tests the code as it is) and builds them into
   tests/host/coord_robustness_runner.c, which feeds them a scripted socket
   and a clock that only moves when the socket "blocks". It checks that a key
   is only taken as exactly 64 hex digits; that a read which has started
   finishes from where it stopped, or fails within 30 s without progress
   (90 s in total) with an errno that isn't EAGAIN; that Noise protocol
   errors set errno; and that an EarlyNoise frame cut off by the first read
   is completed without reading past it.
2. With ESP-IDF's cJSON (from IDF_PATH, C:/esp/esp-idf or ~/esp/esp-idf;
   skipped if none is found), builds tests/host/coord_peers_runner.c from
   parse_peers_from_map_response() and queue_peer_patch(): a peer record
   with a malformed key isn't queued, and a full peer list with one gets no
   stale-peer sweep.
3. Builds tests/host/peer_nvs_runner.c against ml_peer_nvs.c and a fake NVS:
   a stored peer table whose length doesn't match its entry count is dropped,
   not read past.
4. Checks that ml_coord.c and ml_noise.c have no %lld/%llu/%g, which
   newlib-nano's printf (CONFIG_NEWLIB_NANO_FORMAT, default on the ESP32-C2)
   prints as garbage.

Exits 1 and lists each problem otherwise.
"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, '..', '..', 'components', 'tailtiny', 'src')
CC = os.environ.get('CC', 'gcc')
EXE = '.exe' if os.name == 'nt' else ''
CFLAGS = ['-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function']

COORD_FUNCS = ['hex_nibble', 'parse_key32', 'key32_is_zero', 'fmt_i64', 'coord_recv_ex',
               'coord_recv', 'noise_recv_impl', 'complete_proactive_frames']
COORD_DEFINES = ['COORD_RECV_STALL_MS', 'COORD_RECV_TOTAL_MS', 'PROACTIVE_MAX_BYTES']
PEERS_FUNCS = ['hex_nibble', 'parse_key32', 'key32_is_zero', 'fmt_i64', 'parse_rfc3339_utc',
               'queue_peer_patch', 'parse_peers_from_map_response']

NVS_STUBS = {
    'tailtiny_internal.h': '''#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_NOT_FOUND 0x105
#define ESP_ERR_NVS_NOT_FOUND 0x1102
#define ESP_ERR_NVS_INVALID_LENGTH 0x110c
#define CONFIG_ML_NVS_MAX_PEERS 16
#define ML_MAX_ENDPOINTS 8
typedef struct {
    uint32_t vpn_ip;
    uint8_t public_key[32];
    uint8_t disco_key[32];
    char hostname[64];
    bool active;
    bool online;
    struct { uint32_t ip; uint16_t port; bool is_ipv6; } endpoints[ML_MAX_ENDPOINTS];
    int endpoint_count;
    uint16_t derp_region;
    int wg_peer_index;
} ml_peer_t;
void *ml_psram_calloc(size_t n, size_t size);
void tailtiny_ip_to_str(uint32_t ip, char *buf);
esp_err_t ml_peer_nvs_init(void);
void ml_peer_nvs_deinit(void);
esp_err_t ml_peer_nvs_save(const ml_peer_t *peer);
int ml_peer_nvs_load_all(ml_peer_t *peers, int max_peers);
esp_err_t ml_peer_nvs_remove(const uint8_t *public_key);
esp_err_t ml_peer_nvs_clear(void);
''',
    'esp_log.h': '''#pragma once
#include <stdio.h>
#define ML_TEST_LOG(fmt, ...) do { if (getenv("ML_TEST_VERBOSE")) fprintf(stderr, "  " fmt "\\n", ##__VA_ARGS__); } while (0)
#define ESP_LOGE(tag, fmt, ...) do { (void)(tag); ML_TEST_LOG(fmt, ##__VA_ARGS__); } while (0)
#define ESP_LOGW(tag, fmt, ...) do { (void)(tag); ML_TEST_LOG(fmt, ##__VA_ARGS__); } while (0)
#define ESP_LOGI(tag, fmt, ...) do { (void)(tag); ML_TEST_LOG(fmt, ##__VA_ARGS__); } while (0)
#define ESP_LOGD(tag, fmt, ...) do { (void)(tag); ML_TEST_LOG(fmt, ##__VA_ARGS__); } while (0)
''',
    'nvs_flash.h': '#pragma once\n#include "nvs.h"\n',
    'nvs.h': '''#pragma once
#include <stddef.h>
#include <stdint.h>
typedef uint32_t nvs_handle_t;
typedef enum { NVS_READONLY, NVS_READWRITE } nvs_open_mode_t;
esp_err_t nvs_open(const char *ns, nvs_open_mode_t mode, nvs_handle_t *h);
void nvs_close(nvs_handle_t h);
esp_err_t nvs_commit(nvs_handle_t h);
esp_err_t nvs_erase_all(nvs_handle_t h);
esp_err_t nvs_get_blob(nvs_handle_t h, const char *key, void *out, size_t *len);
esp_err_t nvs_set_blob(nvs_handle_t h, const char *key, const void *val, size_t len);
''',
}


def read(path):
    with open(path, encoding='utf-8') as f:
        return f.read()


def skip_literal_or_comment(text, i):
    """If text[i] starts a comment or literal, return the index after it."""
    if text.startswith('/*', i):
        return text.index('*/', i) + 2
    if text.startswith('//', i):
        return text.index('\n', i)
    if text[i] in '"\'':
        q, j = text[i], i + 1
        while text[j] != q:
            j += 2 if text[j] == '\\' else 1
        return j + 1
    return None


def extract_function(text, name):
    m = re.search(r'^static\b[^\n;{}]*\b' + re.escape(name) + r'\s*\(', text, re.M)
    if not m:
        sys.exit(f'{name}() not found in ml_coord.c')
    i = text.index('{', m.end())
    depth = 0
    while True:
        nxt = skip_literal_or_comment(text, i)
        if nxt is not None:
            i = nxt
            continue
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return text[m.start():i + 1]
        i += 1


def extract_define(text, name):
    m = re.search(r'^#define\s+' + name + r'\b.*$', text, re.M)
    if not m:
        sys.exit(f'#define {name} not found in ml_coord.c')
    return m.group(0)


def cjson_dir():
    # CJSON_DIR: a cJSON checkout (the CI clones one); else ESP-IDF's copy
    d = os.environ.get('CJSON_DIR')
    if d and os.path.isfile(os.path.join(d, 'cJSON.c')):
        return d
    roots = [os.environ['IDF_PATH']] if os.environ.get('IDF_PATH') else []
    for root in roots + ['C:/esp/esp-idf', os.path.expanduser('~/esp/esp-idf')]:
        d = os.path.join(root, 'components', 'json', 'cJSON')
        if os.path.isfile(os.path.join(d, 'cJSON.c')):
            return d
    return None


def build_and_run(tmp, exe_name, sources, includes, args, objects=()):
    exe = os.path.join(tmp, exe_name + EXE)
    cmd = [CC] + CFLAGS + [f'-I{d}' for d in includes] + sources + list(objects) + ['-o', exe]
    built = subprocess.run(cmd, capture_output=True, text=True)
    if built.returncode != 0:
        print(built.stdout + built.stderr)
        return [f'{exe_name}: build failed']
    result = subprocess.run([exe] + args, capture_output=True, text=True, timeout=120)
    out = (result.stdout + result.stderr).strip()
    print(f'{exe_name}: ' + out.replace('\n', '\n    '))
    return [] if result.returncode == 0 else [f'{exe_name} failed']


def check_formats():
    """No 64-bit or float conversions in the control-plane logs."""
    problems = []
    for name in ('ml_coord.c', 'ml_noise.c'):
        text = read(os.path.join(SRC, name))
        code = re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)
        for lit in re.findall(r'"(?:[^"\\\n]|\\.)*"', code):
            for conv in re.findall(r'%[-+ #0]*\d*(?:\.\d+)?(ll[diux]|[gGeEfF])', lit):
                problems.append(f'{name}: %{conv} in {lit}')
    return problems


def main():
    verbose = '-v' in sys.argv[1:]
    if verbose:
        os.environ['ML_TEST_VERBOSE'] = '1'
    coord = read(os.path.join(SRC, 'ml_coord.c'))
    problems = check_formats()
    if 'hex_to_bytes' in re.sub(r'/\*.*?\*/', '', coord, flags=re.S):
        problems.append('ml_coord.c still uses hex_to_bytes()')

    with tempfile.TemporaryDirectory() as tmp:
        parts = [extract_define(coord, d) for d in COORD_DEFINES]
        parts += [extract_function(coord, f) for f in COORD_FUNCS]
        with open(os.path.join(tmp, 'coord_extract.c'), 'w', encoding='utf-8') as f:
            f.write('/* Copied from ml_coord.c by check_coord_robustness.py */\n' + '\n\n'.join(parts) + '\n')
        problems += build_and_run(tmp, 'coord_robustness_runner',
                                  [os.path.join(HERE, 'coord_robustness_runner.c')], [tmp],
                                  ['-v'] if verbose else [])

        cj = cjson_dir()
        if not cj:
            print('coord_peers_runner: skipped (no ESP-IDF cJSON; set IDF_PATH)')
        else:
            header = read(os.path.join(SRC, '..', 'include', 'tailtiny_internal.h'))
            m = re.search(r'typedef struct \{\s*enum \{\s*ML_PEER_ADD,.*?\} ml_peer_update_t;', header, re.S)
            if not m:
                sys.exit('ml_peer_update_t not found in tailtiny_internal.h')
            with open(os.path.join(tmp, 'peer_update_type.h'), 'w', encoding='utf-8') as f:
                f.write('#pragma once\n' + extract_define(header, 'ML_MAX_ENDPOINTS') + '\n' + m.group(0) + '\n')
            parts = [extract_function(coord, f) for f in PEERS_FUNCS]
            with open(os.path.join(tmp, 'coord_peers_extract.c'), 'w', encoding='utf-8') as f:
                f.write('/* Copied from ml_coord.c by check_coord_robustness.py */\n' + '\n\n'.join(parts) + '\n')
            # cJSON is third-party: built on its own, without -Werror
            obj = os.path.join(tmp, 'cJSON.o')
            subprocess.run([CC, '-O1', '-w', '-c', os.path.join(cj, 'cJSON.c'), '-o', obj], check=True)
            problems += build_and_run(tmp, 'coord_peers_runner',
                                      [os.path.join(HERE, 'coord_peers_runner.c')], [tmp, cj],
                                      ['-v'] if verbose else [], [obj])

        stubs = os.path.join(tmp, 'stubs')
        os.makedirs(stubs)
        for name, text in NVS_STUBS.items():
            with open(os.path.join(stubs, name), 'w', encoding='utf-8') as f:
                f.write(text)
        problems += build_and_run(tmp, 'peer_nvs_runner',
                                  [os.path.join(HERE, 'peer_nvs_runner.c'),
                                   os.path.join(SRC, 'ml_peer_nvs.c')], [stubs], [])

    for p in problems:
        print('FAIL: ' + p)
    print('OK' if not problems else f'{len(problems)} problem(s)')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
