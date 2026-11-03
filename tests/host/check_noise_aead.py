#!/usr/bin/env python3
"""Host tests for the Noise control channel's ChaCha20-Poly1305 (ml_noise_aead.h).

    python tests/host/check_noise_aead.py

Needs gcc (or set CC). Builds a runner from ml_noise_aead.h and wireguard-lwip's
reference ChaCha20-Poly1305, then checks it against known answers:

- RFC 8439 appendix A.5. Its nonce, 000000000102030405060708, starts with 4 zero
  bytes, so both nonce layouts can express it: wireguard-lwip's (counter
  little-endian) with counter 0x0807060504030201, and Tailscale's (counter
  big-endian) through the Noise wrapper with counter 0x0102030405060708.
  RFC 8439's section 2.8.2 vector has a non-zero nonce prefix, so neither can.
- Messages sealed by Python's `cryptography` package (OpenSSL, an independent
  implementation) with Tailscale's nonce for other counters, an empty payload
  (the Noise handshake's) and no associated data (the transport's).
- A changed byte in the body, the tag or the associated data, the wrong counter,
  and a message shorter than a tag are refused.

If `cryptography` is installed, the A.5 vector and the nonce layout are also
re-checked against it; otherwise that part is skipped.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TT = os.path.join(HERE, '..', '..', 'components', 'tailtiny')
WG = os.path.join(TT, 'components', 'wireguard_lwip', 'src')
CC = os.environ.get('CC', 'gcc')
EXE = '.exe' if os.name == 'nt' else ''

# RFC 8439, appendix A.5 ("ChaCha20-Poly1305 AEAD Decryption").
A5_KEY = '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0'
A5_NONCE = '000000000102030405060708'
A5_AAD = 'f33388860000000000004e91'
A5_CT = ('64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18'
         '755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce'
         '98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e'
         '2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e9'
         '9040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04'
         'b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a10'
         '73a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d'
         '6c6f2c29a6ad5cb4022b02709b')
A5_TAG = 'eead9d67890cbb22392336fea1851f38'
A5_PT = ('Internet-Drafts are draft documents valid for a maximum of six months and may '
         'be updated, replaced, or obsoleted by other documents at any time. It is '
         'inappropriate to use Internet-Drafts as reference material or to cite them '
         'other than as /\u201cwork in progress./\u201d').encode('utf-8').hex()
A5_COUNTER_LE = 0x0807060504030201   # wireguard-lwip: 4 zero bytes + counter little-endian
A5_COUNTER_BE = 0x0102030405060708   # Tailscale: 4 zero bytes + counter big-endian

# Sealed with Python's `cryptography` 50.0.2:
#   ChaCha20Poly1305(A5_KEY).encrypt(b"\0" * 4 + counter.to_bytes(8, "big"), MSG, AD)
MSG = b'Tailscale control: MapRequest'.hex()
AD = bytes(range(32)).hex()
SEALED = [  # (counter, associated data, plaintext, sealed)
    (0x0, AD, MSG, '8b1494b341bc3c7d5a754f53ce34e4af7a923222cad17d5813477596ce446a3ea9bc89ec554b27e25f9e303e28'),
    (0x1, AD, MSG, 'e460b453724d12106264584ab752a2c924282a07fc7e8bf5d43a76e40565309e3847b71ddb273b8e79a6b1fab1'),
    (0x100000000, AD, MSG, 'a46180ae6808b3c5b76bba79b7e34f6281662d90279b22db85b11447641c4e571ad31f2ce2b0864dd6bade1d4a'),
    (0xfffffffffffffffe, AD, MSG, 'b23e768bed25a692428aa8024684dc43b6fd61fd42d64999d8580ad540082b0189ef99d3b2bfdb371c02aae584'),
    (0x0, AD, '', 'd40102df9db58bbcc45ae62cf19dbcff'),   # empty payload, as in the handshake
    (0x7, '', MSG, '2cf022fda40bd6e2576507f863a71e97a47f829f7a7bba7e9f113fd1e01e43b368dd26d4c69d94047a364589da'),  # no AD
]

failures = 0
checks = 0


def check(name, ok, detail=''):
    global failures, checks
    checks += 1
    if not ok:
        failures += 1
        print(f'FAIL: {name} {detail}')


def build():
    out = os.path.join(HERE, 'aead_runner' + EXE)
    refc = os.path.join(WG, 'crypto', 'refc')
    srcs = [os.path.join(HERE, 'aead_runner.c'), os.path.join(WG, 'crypto.c')] + [
        os.path.join(refc, f) for f in ('chacha20poly1305.c', 'chacha20.c', 'poly1305-donna.c')]
    subprocess.run([CC, '-O1', '-Wall', '-I', os.path.join(TT, 'src'), '-I', refc, '-I', WG,
                    *srcs, '-o', out], check=True)
    return out


def run(exe, op, key, counter, ad, data):
    r = subprocess.run([exe, op, key, f'{counter:x}', ad or '-', data or '-'],
                       check=True, capture_output=True, text=True)
    return r.stdout.strip()


def flip(hexstr, i):
    b = bytearray.fromhex(hexstr)
    b[i] ^= 0x01
    return b.hex()


def main():
    exe = build()
    key = A5_KEY
    a5_sealed = A5_CT + A5_TAG

    check('wireguard-lwip matches RFC 8439 A.5',
          run(exe, 'wg-seal', key, A5_COUNTER_LE, A5_AAD, A5_PT) == a5_sealed)
    check('Noise seal matches A.5 with the counter big-endian',
          run(exe, 'noise-seal', key, A5_COUNTER_BE, A5_AAD, A5_PT) == a5_sealed)
    check('Noise open matches A.5 with the counter big-endian',
          run(exe, 'noise-open', key, A5_COUNTER_BE, A5_AAD, a5_sealed) == A5_PT)
    check('Noise open refuses A.5 with the counter little-endian',
          run(exe, 'noise-open', key, A5_COUNTER_LE, A5_AAD, a5_sealed) == 'REFUSED')

    for counter, ad, pt, sealed in SEALED:
        name = f'counter {counter:#x}, {len(pt) // 2} bytes, {len(ad) // 2} bytes AD'
        check(f'seal {name}', run(exe, 'noise-seal', key, counter, ad, pt) == sealed)
        check(f'open {name}', run(exe, 'noise-open', key, counter, ad, sealed) == pt)
        check(f'wrong counter refused, {name}',
              run(exe, 'noise-open', key, counter ^ 1, ad, sealed) == 'REFUSED')
        for i in sorted({0, len(sealed) // 2 - 17, len(sealed) // 2 - 16, len(sealed) // 2 - 1}):
            if i >= 0:
                check(f'byte {i} changed refused, {name}',
                      run(exe, 'noise-open', key, counter, ad, flip(sealed, i)) == 'REFUSED')
        if ad:
            check(f'changed AD refused, {name}',
                  run(exe, 'noise-open', key, counter, flip(ad, 0), sealed) == 'REFUSED')

    check('A.5 with a byte of its tag changed is refused',
          run(exe, 'noise-open', key, A5_COUNTER_BE, A5_AAD, flip(a5_sealed, len(a5_sealed) // 2 - 1)) == 'REFUSED')
    check('message shorter than a tag is refused',
          run(exe, 'noise-open', key, 0, AD, SEALED[4][3][:30]) == 'REFUSED')
    check('empty message is refused', run(exe, 'noise-open', key, 0, AD, '') == 'REFUSED')

    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    except ImportError:
        print('cryptography not installed: skipped the cross-check against it')
    else:
        c = ChaCha20Poly1305(bytes.fromhex(key))
        check('cryptography agrees with A.5',
              c.encrypt(bytes.fromhex(A5_NONCE), bytes.fromhex(A5_PT), bytes.fromhex(A5_AAD)).hex() == a5_sealed)
        check('A.5 nonce is Tailscale layout for 0x0102030405060708',
              bytes(4) + A5_COUNTER_BE.to_bytes(8, 'big') == bytes.fromhex(A5_NONCE))
        for counter, ad, pt, sealed in SEALED:
            nonce = bytes(4) + counter.to_bytes(8, 'big')
            check(f'cryptography agrees with the counter {counter:#x} vector',
                  c.encrypt(nonce, bytes.fromhex(pt), bytes.fromhex(ad) or None).hex() == sealed)

    os.remove(exe)
    print(f'{checks - failures}/{checks} checks passed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
