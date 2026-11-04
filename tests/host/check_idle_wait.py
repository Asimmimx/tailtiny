#!/usr/bin/env python3
"""Checks the DERP and WireGuard tasks' idle waits.

    python tests/host/check_idle_wait.py

1. Builds tests/host/idle_wait_runner.c with gcc (or set CC) and runs it:
   ml_idle_wait() against a real socket pair and eventfd. Linux only, since
   eventfd is; skipped elsewhere.
2. Reads the source for the wiring the runner can't see: every send to a
   queue the WireGuard or DERP task waits on goes through a helper that wakes
   that task, and neither task goes back to a short polling delay.

Exits 1 and lists each problem otherwise.
"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
COMP = os.path.join(HERE, '..', '..', 'components', 'tailtiny')
SRC = os.path.join(COMP, 'src')
CC = os.environ.get('CC', 'gcc')

WAKE_QUEUES = ('wg_rx_queue', 'disco_rx_queue', 'peer_update_queue', 'derp_tx_queue')


def code(path):
    with open(path, encoding='utf-8') as f:
        text = f.read()
    return re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)


def run_runner():
    if not sys.platform.startswith('linux'):
        print('runner: skipped (eventfd is Linux only)')
        return []
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, 'idle_wait_runner')
        subprocess.run([CC, '-O1', '-Wall', '-Wextra', '-Werror', '-pthread', '-I', SRC,
                        os.path.join(HERE, 'idle_wait_runner.c'), '-o', exe], check=True)
        result = subprocess.run([exe], capture_output=True, text=True, timeout=30)
    print('runner: ' + result.stdout.strip().replace('\n', '\n        '))
    return [] if result.returncode == 0 else ['idle_wait_runner failed']


def check_wiring():
    problems = []
    files = sorted(f for f in os.listdir(SRC) if f.endswith('.c'))
    if len(files) < 10:
        problems.append('expected the tailtiny sources in ' + SRC)
    raw = re.compile(r'\bxQueueSend(?:ToFront|ToBack)?\s*\(\s*ml->(' + '|'.join(WAKE_QUEUES) + r')\b')
    for name in files:
        for match in raw.finditer(code(os.path.join(SRC, name))):
            problems.append(f'{name}: raw xQueueSend to {match.group(1)} (use ml_wg_queue_send / ml_derp_queue_item)')

    header = code(os.path.join(COMP, 'include', 'tailtiny_internal.h'))
    derp = code(os.path.join(SRC, 'ml_derp.c'))
    wg = code(os.path.join(SRC, 'ml_wg_mgr.c'))
    zerocopy = code(os.path.join(SRC, 'ml_zerocopy.c'))
    lifecycle = code(os.path.join(SRC, 'tailtiny.c'))
    expect = [
        (header, 'if (sent == pdTRUE) ml_wg_wake(ml);', 'ml_wg_queue_send wakes the WireGuard task'),
        (header, 'if (sent == pdTRUE) ml_derp_wake(ml);', 'ml_derp_queue_item wakes the DERP task'),
        (derp, 'ml_wg_queue_send(ml, target,', 'relayed WireGuard/DISCO packets wake the WireGuard task'),
        (zerocopy, 'ml_wg_wake(ml);', 'the zero-copy DISCO ring wakes the WireGuard task'),
        (wg, 'ulTaskNotifyTake(pdTRUE, ML_DELAY_TICKS(100))', 'the WireGuard task waits for a notification'),
        (derp, 'uxQueueMessagesWaiting(ml->derp_tx_queue)', 'the DERP wait is skipped while TX is queued'),
        (derp, 'mbedtls_ssl_check_pending(&ml->derp.ssl)', 'the DERP wait is skipped while TLS holds data'),
        (derp, 'ml_idle_wait(fd, ml->derp_wake_fd, timeout_ms)', 'the DERP task waits on socket and eventfd'),
        (lifecycle, 'ml->derp_wake_fd = -1', 'the eventfd starts closed'),
        (lifecycle, 'close(ml->derp_wake_fd)', 'destroy closes the eventfd'),
    ]
    for text, needle, what in expect:
        if needle not in text:
            problems.append(f'missing: {what} ({needle})')
    if derp.count('derp_wait_work(ml, 100)') != 2:
        problems.append('the DERP task should wait in derp_wait_work() when connected and when not')
    if re.search(r'xQueueReceive\(\s*ml->wg_rx_queue\s*,[^;]*pdMS_TO_TICKS\(\s*10\s*\)', wg):
        problems.append('ml_wg_mgr.c polls wg_rx_queue every 10 ms again')
    for fn in ('tailtiny_rebind', 'tailtiny_stop'):
        body = re.search(fn + r'\s*\([^)]*\)\s*\{(.*?)\n\}', lifecycle, re.S)
        if not body or 'ml_derp_wake(ml);' not in body.group(1):
            problems.append(f'{fn}() should wake the DERP task')
    print(f'wiring: {len(problems)} problems')
    return problems


def main():
    problems = run_runner() + check_wiring()
    for p in problems:
        print('FAIL ' + p)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
