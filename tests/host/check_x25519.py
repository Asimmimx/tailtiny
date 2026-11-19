#!/usr/bin/env python3
"""Checks both X25519 copies against RFC 7748 and Python's cryptography.

    python tests/host/check_x25519.py

TailTiny carries the same X25519 twice: in wireguard_lwip (WireGuard) and in
components/tailtiny/src (Noise and DISCO). Builds tests/host/x25519_runner.c
with gcc (or set CC) against each, and checks:

- RFC 7748 section 5.2's two test vectors (the second one's u-coordinate has
  bit 255 set, which X25519 must ignore);
- 300 random scalar/u pairs against cryptography's X25519, half of them with
  bit 255 of u set;
- that the caller's u buffer is left unchanged.

Exits 1 and lists each mismatch otherwise.
"""
import os
import secrets
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, '..', '..', 'components', 'tailtiny')
COPIES = {
    'wireguard_lwip': os.path.join(ROOT, 'components', 'wireguard_lwip', 'src', 'crypto', 'refc'),
    'tailtiny/src': os.path.join(ROOT, 'src'),
}
CC = os.environ.get('CC', 'gcc')

RFC_VECTORS = [
    ('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
     'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c',
     'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552'),
    ('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d',
     'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493',
     '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957'),
]


def reference(scalar_hex, u_hex):
    try:
        k = X25519PrivateKey.from_private_bytes(bytes.fromhex(scalar_hex))
        return k.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(u_hex))).hex()
    except ValueError:  # an all-zero result (low-order point): not comparable
        return None


def main():
    cases = [(s, u, out) for s, u, out in RFC_VECTORS]
    for i in range(300):
        u = bytearray(secrets.token_bytes(32))
        if i % 2:
            u[31] |= 0x80
        else:
            u[31] &= 0x7F
        s, uh = secrets.token_bytes(32).hex(), bytes(u).hex()
        ref = reference(s, uh)
        if ref:
            cases.append((s, uh, ref))
    stdin = ''.join(f'{s} {u}\n' for s, u, _ in cases)

    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        for name, src in COPIES.items():
            exe = os.path.join(tmp, 'x25519_' + name.replace('/', '_'))
            subprocess.run([CC, '-O2', '-w', '-I', src, os.path.join(HERE, 'x25519_runner.c'),
                            os.path.join(src, 'x25519.c'), '-o', exe], check=True)
            out = subprocess.run([exe], input=stdin, capture_output=True, text=True, check=True).stdout.split('\n')
            bad = 0
            for (s, u, want), line in zip(cases, out):
                got, state = line.split()
                if got != want or state != 'ok':
                    bad += 1
                    if bad <= 3:
                        problems.append(f'{name}: u={u[:8]}..{u[-2:]} got {got[:16]}.. want {want[:16]}.. ({state})')
            if bad:
                problems.append(f'{name}: {bad}/{len(cases)} wrong')
            print(f'{name}: {len(cases) - bad}/{len(cases)} match (RFC 7748 vectors + cryptography)')
    for p in problems:
        print('PROBLEM:', p)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
