#!/usr/bin/env python3
"""Checks the WireGuard handshake timestamp (wireguard_tai64n_now()).

    python tests/host/check_tai64n.py

A WireGuard peer drops a handshake initiation whose TAI64N timestamp isn't
newer than the last one it accepted from us. Builds tests/host/tai64n_runner.c
with gcc (or set CC) against wireguard-platform-esp32.c and stub ESP-IDF and
FreeRTOS headers, and checks that:

- with the clock set, the timestamp is the wall time (TAI64N label + offset);
- a later boot's first timestamp is newer than the previous boot's last one,
  though uptime starts again at 0 (the bug: it used uptime);
- without a set clock it falls back to uptime, as before;
- within a boot it never goes backwards: not when the wall clock steps back,
  and not when the clock gets set after uptime timestamps.

Exits 1 and lists each problem otherwise.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WG_SRC = os.path.join(HERE, '..', '..', 'components', 'tailtiny', 'components', 'wireguard_lwip', 'src')
CC = os.environ.get('CC', 'gcc')
TAI_LABEL = 0x400000000000000A  # TAI64 label for 1970-01-01 00:00:10 TAI

STUBS = {
    'esp_random.h': '#include <stddef.h>\nstatic inline void esp_fill_random(void *b, size_t n) { (void)b; (void)n; }\n',
    'esp_timer.h': '#include <stdint.h>\nint64_t esp_timer_get_time(void);\n',
    'lwip/sys.h': '#include <stdint.h>\nstatic inline uint32_t sys_now(void) { return 0; }\n',
    'freertos/FreeRTOS.h': '#define portMAX_DELAY 0xffffffffu\n',
    'freertos/semphr.h': ('typedef void *SemaphoreHandle_t;\n'
                          'static inline SemaphoreHandle_t xSemaphoreCreateMutex(void) { return 0; }\n'
                          'static inline int xSemaphoreTake(SemaphoreHandle_t s, unsigned t) { (void)s; (void)t; return 1; }\n'
                          'static inline int xSemaphoreGive(SemaphoreHandle_t s) { (void)s; return 1; }\n'
                          'static inline void vSemaphoreDelete(SemaphoreHandle_t s) { (void)s; }\n'),
}

WALL = 1_794_000_000  # a set clock (2026)


def build(tmp):
    for name, text in STUBS.items():
        path = os.path.join(tmp, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(text)
    exe = os.path.join(tmp, 'tai64n_runner')
    subprocess.run([CC, '-O1', '-Wall', '-Wextra', '-Wno-unused-parameter', '-Dgettimeofday=fake_gettimeofday',
                    '-I', tmp, '-I', WG_SRC, os.path.join(HERE, 'tai64n_runner.c'), '-o', exe], check=True)
    return exe


def boot(exe, samples):
    """One boot: a fresh process, so the timestamp's state starts empty. samples are
    (wall s, wall us, uptime us); returns each timestamp as (seconds, ns)."""
    stdin = ''.join(f'{s} {us} {up}\n' for s, us, up in samples)
    out = subprocess.run([exe], input=stdin, capture_output=True, text=True, check=True, timeout=30).stdout
    lines = [h for h in out.split('\n') if len(h) == 24 and all(c in '0123456789abcdef' for c in h)]
    return [(int(h[:16], 16), int(h[16:], 16)) for h in lines]


def check(exe):
    problems = []

    def expect(cond, what):
        if not cond:
            problems.append(what)

    first = boot(exe, [(WALL, 250_000, 60_000_000)])
    expect(first == [(TAI_LABEL + WALL, 250_000_000)], f'a set clock gives the wall time: got {first}')

    # A device that ran an hour, rebooted, and handshakes 8 s into the new boot.
    last_before = boot(exe, [(WALL + 3600, 0, 3600_000_000)])[-1]
    first_after = boot(exe, [(WALL + 3610, 0, 8_000_000)])[0]
    expect(first_after > last_before, f'after a reboot the first timestamp is newer: {first_after} vs {last_before}')

    unset = boot(exe, [(5, 0, 7_500_000)])
    expect(unset == [(TAI_LABEL + 7, 500_000_000)], f'an unset clock falls back to uptime: got {unset}')

    stepped = boot(exe, [(WALL + 10, 0, 1_000_000), (WALL + 8, 0, 2_000_000), (WALL + 8, 0, 3_000_000)])
    expect(stepped[0] < stepped[1] < stepped[2], f'the wall clock stepping back still moves forward: {stepped}')

    set_later = boot(exe, [(5, 0, 7_000_000), (WALL, 0, 9_000_000)])
    expect(set_later[0] < set_later[1], f'the clock getting set moves forward: {set_later}')

    same = boot(exe, [(WALL, 0, 1), (WALL, 0, 2)])
    expect(same[0] < same[1], f'two timestamps in the same microsecond still differ: {same}')

    # No SNTP or RTC: the control server's ControlTime (wireguard_set_time_hint)
    hinted = boot(exe, [(-1, WALL, 5_000_000), (5, 0, 7_000_000)])
    expect(hinted == [(TAI_LABEL + WALL + 2, 0)], f'an unset clock follows the time hint: got {hinted}')
    last_before = boot(exe, [(-1, WALL, 3_000_000), (5, 0, 3600_000_000)])[-1]
    first_after = boot(exe, [(-1, WALL + 3610, 6_000_000), (5, 0, 8_000_000)])[0]
    expect(first_after > last_before,
           f'with the hint and no clock, a reboot still moves forward: {first_after} vs {last_before}')

    print(f'tai64n: {8 - len(problems)}/8 checks passed')
    return problems


def main():
    with tempfile.TemporaryDirectory() as tmp:
        problems = check(build(tmp))
    for p in problems:
        print('FAIL ' + p)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
