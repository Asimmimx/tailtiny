#!/usr/bin/env python3
"""Checks WireGuard's receive path: endpoint roaming, replay and short or
foreign plaintexts.

    python tests/host/check_wg_roaming.py [wireguard_lwip/src dir]

Builds tests/host/wg_roaming_runner.c with gcc (or set CC) against the
bundled wireguard-lwip sources and lwIP's headers, and runs it. Two real
wireguardif instances complete a handshake over an in-memory wire; the
runner then checks that a cookie reply or a replayed packet can't move a
peer's endpoint, that roaming still works, and that a plaintext shorter than
an IPv4 header, an inner IPv6 packet, a counter at Reject-After-Messages and a
counter 2^32 behind the newest one are refused. Adapted from MicroLink's
regression test for GHSA-jxrh-hg4w-g4rm (upstream PR #46).

lwIP's headers come from LWIP_INCLUDE_DIR, or ESP-IDF's copy under IDF_PATH
(C:/esp/esp-idf or ~/esp/esp-idf if IDF_PATH isn't set). Pass another
wireguard_lwip/src directory to run the checks against an older copy.

Exits 1 and lists each failed check otherwise.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WG_SRC_DEFAULT = os.path.join(HERE, '..', '..', 'components', 'tailtiny', 'components', 'wireguard_lwip', 'src')
CC = os.environ.get('CC', 'gcc')

STUBS = {
    # Enough of lwIP's configuration for wireguardif.c. IPv6 on, as in
    # ESP-IDF's default build, so ip_addr_t is the dual-stack union.
    'lwipopts.h': ('#define NO_SYS 1\n#define LWIP_IPV4 1\n#define LWIP_IPV6 1\n'
                   '#define LWIP_SOCKET 0\n#define LWIP_NETCONN 0\n#define LWIP_UDP 1\n'
                   '#define LWIP_TCP 0\n#define SYS_LIGHTWEIGHT_PROT 0\n'
                   '#define LWIP_NETIF_STATUS_CALLBACK 0\n#define LWIP_NETIF_LINK_CALLBACK 0\n'),
    'arch/cc.h': ('#include <stdio.h>\n#include <stdlib.h>\n'
                  '#define LWIP_PLATFORM_DIAG(x) do { printf x; } while (0)\n'
                  '#define LWIP_PLATFORM_ASSERT(x) do { fprintf(stderr, "lwIP assert: %s\\n", x); abort(); } while (0)\n'
                  '#ifndef BYTE_ORDER\n#define BYTE_ORDER LITTLE_ENDIAN\n#endif\n#define LWIP_NO_UNISTD_H 0\n'),
    # With NO_SYS, lwIP declares no tcpip_thread API; wireguardif.c hands the
    # link flag to tcpip_thread with tcpip_api_call(). The runner plays that thread.
    'host_shim.h': ('#pragma once\n#include <stdbool.h>\n#include "lwip/err.h"\n'
                    'typedef enum { LWIP_CORE_LOCK_QUERY_HOLDER } sys_thread_core_lock_t;\n'
                    'static inline bool sys_thread_tcpip(sys_thread_core_lock_t t) { (void)t; return true; }\n'
                    'struct tcpip_api_call_data { int dummy; };\n'
                    'typedef err_t (*tcpip_api_call_fn)(struct tcpip_api_call_data *call);\n'
                    'err_t tcpip_api_call(tcpip_api_call_fn fn, struct tcpip_api_call_data *call);\n'),
}

WG_FILES = ['wireguardif.c', 'wireguard.c', 'crypto.c',
            'crypto/refc/blake2s.c', 'crypto/refc/chacha20.c', 'crypto/refc/chacha20poly1305.c',
            'crypto/refc/poly1305-donna.c', 'crypto/refc/x25519.c']


def lwip_include_dir():
    candidates = []
    if os.environ.get('LWIP_INCLUDE_DIR'):
        candidates.append(os.environ['LWIP_INCLUDE_DIR'])
    idf = os.environ.get('IDF_PATH')
    for root in ([idf] if idf else []) + ['C:/esp/esp-idf', os.path.expanduser('~/esp/esp-idf')]:
        candidates.append(os.path.join(root, 'components', 'lwip', 'lwip', 'src', 'include'))
    for c in candidates:
        if os.path.isfile(os.path.join(c, 'lwip', 'pbuf.h')):
            return c
    sys.exit('lwIP headers not found: set LWIP_INCLUDE_DIR or IDF_PATH')


def main():
    wg_src = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else WG_SRC_DEFAULT)
    lwip = lwip_include_dir()
    with tempfile.TemporaryDirectory() as tmp:
        for name, text in STUBS.items():
            path = os.path.join(tmp, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                f.write(text)
        exe = os.path.join(tmp, 'wg_roaming_runner')
        # -Wno-format: the firmware's %ld/%lu for uint32_t is right on the ESP32
        # (unsigned long) and only wrong on a 64-bit host.
        cmd = [CC, '-O1', '-g', '-Wall', '-Wno-unused-parameter', '-Wno-format', '-Wno-sign-compare',
               '-include', os.path.join(tmp, 'host_shim.h'),
               '-I', tmp, '-I', wg_src, '-I', os.path.join(wg_src, 'crypto', 'refc'), '-I', lwip,
               os.path.join(HERE, 'wg_roaming_runner.c')]
        cmd += [os.path.join(wg_src, f) for f in WG_FILES]
        cmd += ['-o', exe]
        subprocess.run(cmd, check=True)
        r = subprocess.run([exe], capture_output=True, text=True)
        # wireguardif.c logs with printf; show only what the runner says
        out = [l for l in (r.stdout + r.stderr).splitlines()
               if l.startswith('FAIL') or 'check(s) failed' in l or 'tests passed' in l]
        print('\n'.join(out) if out else (r.stdout + r.stderr)[-2000:])
        if r.returncode != 0:
            print(f'RESULT: FAIL (exit {r.returncode})')
            return 1
        print('RESULT: OK')
        return 0


if __name__ == '__main__':
    sys.exit(main())
