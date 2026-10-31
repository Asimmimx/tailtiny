#!/usr/bin/env python3
"""Checks the locking rule in wireguard_lwip/src/wireguardif.c.

    python tests/host/check_wg_locking.py

TailTiny runs wireguard-lwip's timers and incoming packets on its WireGuard task
(ml_wg_mgr.c) while lwIP's thread encrypts outgoing packets, so the keypairs,
counters, handshake state and peer table are only touched under the device's
WG_LOCK. And nothing that sends or enters lwIP runs under it: the UDP send waits
for lwIP's thread (ml_tcpip_run), which may itself be waiting for the lock.

Reads the source; needs only Python. Exits 1 and lists each problem otherwise.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, '..', '..', 'components', 'tailtiny', 'components', 'wireguard_lwip', 'src', 'wireguardif.c')

# Must be called with the lock held.
STATE_CALLS = (
    'wireguard_encrypt_packet', 'wireguard_decrypt_packet', 'keypair_destroy', 'keypair_update',
    'wireguard_start_session', 'wireguard_create_handshake_initiation',
    'wireguard_create_handshake_response', 'wireguard_process_handshake_response',
    'wireguard_process_initiation_message', 'wireguard_process_cookie_message',
    'wireguardif_initiate_handshake', 'wireguardif_lookup_peer', 'peer_lookup_by_allowed_ip',
    'peer_lookup_by_receiver', 'peer_lookup_by_handshake', 'peer_lookup_by_pubkey', 'peer_alloc',
    'wireguardif_seal_locked', 'wireguardif_process_data_message_locked',
    'wireguardif_make_handshake_response_locked',
)
# Must be called without it.
UNLOCKED_CALLS = (
    'wireguardif_endpoint_output', 'wireguardif_device_output', 'wireguardif_send_sealed',
    'wireguardif_send_keepalive', 'wireguardif_output_to_peer', 'wireguard_start_handshake',
    'wg_netif_set_link', 'tcpip_api_call', 'udp_sendto', 'derp_output_fn', 'udp_output_fn',
)
# Helpers that only ever run with the lock already held, besides the *_locked functions.
LOCKED_HELPERS = ('wireguardif_initiate_handshake', 'wireguardif_lookup_peer')
# Entry points that must be found, so a parsing slip can't pass silently.
MUST_SEE = ('wireguardif_output', 'wireguardif_network_rx', 'wireguardif_run_timers',
            'wireguard_start_handshake', 'wireguardif_connect_derp')


def code_lines(path):
    with open(path, encoding='utf-8') as f:
        for number, line in enumerate(f, start=1):
            line = line.split('//', 1)[0]
            yield number, re.sub(r'/\*.*?\*/', '', line)


def functions(path):
    """(name, lines) for each function. A function's brace may be on its definition line or
    the next; any other top-level brace that opens neither a type nor an initializer is an
    error, so a layout change can't drop a function from the check."""
    name, pending, depth, body = None, None, 0, []
    for number, code in code_lines(path):
        if depth == 0:
            definition = re.match(r'^(?:static\s+)?[\w\s\*]+?\b(\w+)\s*\([^;]*$', code)
            if definition and '{' in code:
                name, body, pending = definition.group(1), [], None
            elif definition:
                pending = definition.group(1)
            elif pending and '{' in code:  # the brace after a signature that spans lines
                name, body, pending = pending, [], None
            elif '{' in code and not re.match(r'\s*#|\s*(?:static\s+|const\s+)*(?:struct|union|enum)\b|.*=\s*\{', code):
                raise SystemExit(f'{os.path.basename(path)}:{number}: a top-level brace the check can\'t place')
        if name:
            body.append((number, code))
        depth += code.count('{') - code.count('}')
        if name and depth == 0 and body:
            yield name, body
            name = None


def check(path):
    state = re.compile(r'\b(' + '|'.join(STATE_CALLS) + r')\s*\(')
    unlocked = re.compile(r'(\b(' + '|'.join(UNLOCKED_CALLS) + r')\s*\(|->input\s*\()')
    problems, seen = [], set()
    for name, body in functions(path):
        seen.add(name)
        held = name.endswith('_locked') or name in LOCKED_HELPERS
        for number, code in body[1:]:
            if re.search(r'\bWG_LOCK\s*\(', code):
                if held:
                    problems.append(f'line {number}: {name} locks while holding the lock')
                held = True
            found = state.search(code)
            if found and not held:
                problems.append(f'line {number}: {name} calls {found.group(1)} without the lock')
            if unlocked.search(code) and held:
                problems.append(f'line {number}: {name} sends or enters lwIP under the lock')
            if re.search(r'\bWG_UNLOCK\s*\(', code):
                held = False
    missing = [f for f in MUST_SEE if f not in seen]
    if missing:
        problems.append('functions not found: ' + ', '.join(missing))
    return problems


def self_test():
    """The parser must see a function whose brace is on its own line."""
    import tempfile
    with tempfile.NamedTemporaryFile('w', suffix='.c', delete=False, encoding='utf-8') as f:
        f.write('static void wireguardif_process_response_message(struct wireguard_device *device)\n'
                '{\n\twireguard_start_session(peer, true);\n}\n')
    try:
        names = [name for name, _ in functions(f.name)]
        assert names == ['wireguardif_process_response_message'], names
        assert check(f.name)[0].endswith('calls wireguard_start_session without the lock'), check(f.name)
    finally:
        os.unlink(f.name)


if __name__ == '__main__':
    self_test()
    problems = check(sys.argv[1] if len(sys.argv) > 1 else SRC)
    for p in problems:
        print('wireguardif.c', p)
    print('OK: WireGuard state only under WG_LOCK, no sends under it' if not problems
          else f'{len(problems)} problem(s)')
    sys.exit(1 if problems else 0)
