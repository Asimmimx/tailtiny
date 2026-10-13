#!/usr/bin/env python3
"""Reset an ESP32 and print its serial log for a while (non-interactive).

Unlike `idf.py monitor`, this exits on its own, so AI assistants and scripts
can use it. Exit code 0 once the device reports a Tailscale VPN IP, 1 if it
doesn't within the time limit.

    python tools/serial_log.py COM5            # Windows
    python tools/serial_log.py /dev/ttyACM0 90 # Linux, 90 seconds
"""
import re
import sys
import time

try:
    import serial
except ImportError:
    sys.exit("pyserial missing: run this from the ESP-IDF environment (or pip install pyserial)")

ANSI = re.compile(r'\x1b\[[0-9;]*m')


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    port = sys.argv[1]
    seconds = int(sys.argv[2]) if len(sys.argv) > 2 else 60

    s = serial.Serial(port, 115200, timeout=0.5)
    s.dtr = False            # reset into the app (not the bootloader)
    s.rts = True
    time.sleep(0.1)
    s.rts = False

    vpn_ip = None
    end = time.time() + seconds
    while time.time() < end:
        line = ANSI.sub('', s.readline().decode('utf-8', 'replace')).rstrip()
        if not line:
            continue
        print(line, flush=True)
        # the app's line, printed once TailTiny reports CONNECTED
        m = re.search(r'Connected! VPN IP: (100\.\d+\.\d+\.\d+)', line)
        if m and not vpn_ip:
            vpn_ip = m.group(1)
            end = min(end, time.time() + 5)     # a few more lines, then stop

    print()
    if vpn_ip:
        print(f"RESULT: connected, VPN IP {vpn_ip}")
        return 0
    print("RESULT: no VPN IP yet (see the Troubleshooting table in AGENTS.md)")
    return 1


if __name__ == '__main__':
    sys.exit(main())
