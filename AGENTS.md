# AGENTS.md: setting up TailTiny with an AI assistant

This file is for AI coding assistants (Claude Code, Codex, Cursor, Copilot, and others). It describes the exact steps for putting TailTiny on a user's ESP32 board. Follow it from top to bottom. Every command below has been run on real hardware.

**Goal:** the user's ESP32 joins their Tailscale network and replies to a UDP echo over it.

---

## Rules

- **Never print, log, or commit the user's WiFi password or Tailscale auth key.** Write them only into `examples/basic_connect/sdkconfig.credentials`. That file is git-ignored. Don't read it back to the user.
- **Don't run `idf.py erase-flash` unless the user asks.** It deletes the device's Tailscale identity, and re-joining then needs a new auth key.
- An auth key with *Reusable* off works **once**. If the device has already joined with it, don't reuse it on another board.
- `idf.py monitor` is interactive and won't return. To read logs, use the serial snippet in step 7.
- Ask the user only for what you can't detect: WiFi name, WiFi password, and auth key. Detect the chip and the serial port yourself.

---

## Step 1. Check ESP-IDF (v5.3 or newer)

ESP-IDF commands only work in a shell where ESP-IDF's export script has been run:

| OS | Activate ESP-IDF in the current shell |
|---|---|
| Windows (PowerShell) | `& $env:IDF_PATH\export.ps1` (or the "ESP-IDF PowerShell" shortcut) |
| Linux / macOS | `. $IDF_PATH/export.sh` |

Then check:

```bash
python $IDF_PATH/tools/idf.py --version     # expect: ESP-IDF v5.3 or newer
```

On Windows, use `python $env:IDF_PATH\tools\idf.py --version`. Plain `idf.py --version` there reports the launcher's own version (e.g. `v1.0.3`), not ESP-IDF's.

If ESP-IDF is missing, install it. This takes 10–20 minutes and about 2 GB:

```bash
# Linux / macOS
git clone -b v5.3.2 --recursive --depth 1 --shallow-submodules https://github.com/espressif/esp-idf.git ~/esp/esp-idf
~/esp/esp-idf/install.sh esp32c3     # use the user's chip, or "all"
. ~/esp/esp-idf/export.sh
```

```powershell
# Windows (PowerShell)
git clone -b v5.3.2 --recursive --depth 1 --shallow-submodules https://github.com/espressif/esp-idf.git C:\esp\esp-idf
C:\esp\esp-idf\install.bat esp32c3   # use the user's chip, or "all"
$env:IDF_PATH = 'C:\esp\esp-idf'; & C:\esp\esp-idf\export.ps1
```

## Step 2. Find the serial port

| OS | Command | Looks like |
|---|---|---|
| Windows | `Get-CimInstance Win32_PnPEntity \| Where-Object Name -match 'COM\d' \| Select Name` | `USB-Enhanced-SERIAL CH343 (COM5)`, `USB JTAG/serial debug unit (COM7)`, `Silicon Labs CP210x (COM3)` |
| Linux | `ls /dev/ttyUSB* /dev/ttyACM*` | `/dev/ttyACM0` |
| macOS | `ls /dev/cu.usb*` | `/dev/cu.usbmodem1101` |

Ignore `COM1` on Windows; it's a built-in port. If there's no port, the board isn't connected or the cable is charge-only.

## Step 3. Identify the chip

```bash
python -m esptool --port <PORT> chip_id
```

Look for the line `Chip is ESP32-C3 (...)`. The target name for later steps is that chip in lower case without the dash: `esp32c3`, `esp32s3`, `esp32`, `esp32c6`, `esp32s2`.

Then check that the chip is supported:

| Chip | What to do |
|---|---|
| ESP32-C3 | Supported, tested on hardware. Continue |
| ESP32-S3, ESP32, ESP32-C6 | Should work. Continue, and tell the user it hasn't been hardware-tested with this fork |
| ESP32-S2 | Continue only if the board has PSRAM (log line `Found ... PSRAM`). Otherwise RAM is too tight |
| ESP32-C2 | Warn that it is very likely too small: TailTiny needs ~185 KB free after WiFi, a C2 has ~95 KB (~169 KB with deep tuning). Continue only if the user wants to try |
| ESP32-C5, ESP32-C61 | Need ESP-IDF 5.5+. Not tested yet |
| ESP32-H2, ESP32-P4 | **Stop.** No built-in WiFi. Tell the user they need a different board |

## Step 4. Get the code

```bash
git clone https://github.com/Asimmimx/tailtiny.git
cd tailtiny/examples/basic_connect
```

If the user already has a clone, `git pull` it. Old upstream copies fail on Windows with `Failed to resolve component 'wireguard_lwip'`.

## Step 5. Credentials

Ask the user for:

1. **WiFi name and password.** 2.4 GHz only; no ESP32 except the C5 supports 5 GHz.
2. **Tailscale auth key.** Send them to <https://login.tailscale.com/admin/settings/keys> → **Generate auth key**, with **Reusable off**, **Ephemeral off**, and **Pre-approved on** if shown. The key starts with `tskey-auth-`.

Create `sdkconfig.credentials` next to `sdkconfig.credentials.example` with exactly these lines:

```ini
CONFIG_ML_WIFI_SSID="<wifi name>"
CONFIG_ML_WIFI_PASSWORD="<wifi password>"
CONFIG_ML_TAILSCALE_AUTH_KEY="<tskey-auth-...>"
CONFIG_ML_DEVICE_NAME="<short-name, optional, e.g. esp32-livingroom>"
```

If a value contains `"` or `\`, escape it as `\"` or `\\`.

These settings are copied into `sdkconfig` only on the **first** build. If you change them later, delete `sdkconfig` and build again.

## Step 6. Build and flash

```bash
idf.py set-target <chip>          # e.g. esp32c3; this also creates sdkconfig
idf.py -p <PORT> flash            # builds, then flashes (first build: 2–5 min)
```

- `set-target` resets the build. Run it once per board, not before every flash.
- If flashing fails with "Failed to connect", hold **BOOT**, tap **RESET**, release BOOT, and retry.

## Step 7. Verify

From the repository root, reset the board and read its log. The script exits by itself (unlike `idf.py monitor`):

```bash
python tools/serial_log.py <PORT>
```

It ends with `RESULT: connected, VPN IP 100.x.y.z` (exit code 0) once these lines appear, usually within 20 s:

```
main: WiFi connected to <ssid>, IP: 192.168.x.y
main: TailTiny state: CONNECTED
main: Connected! VPN IP: 100.x.y.z
```

If it ends with `RESULT: no VPN IP yet`, match the log against the Troubleshooting table below.

Then, from any machine on the user's tailnet (often the one you're running on), test the tunnel:

```bash
python tools/udp_echo.py 100.x.y.z
```

Expect `RESULT: reply from 100.x.y.z: ECHO: hello`. The script retries for 30 s, because the first tunnel after boot takes about 15 s. If this machine isn't on the tailnet, ask the user to run it from one that is, or to `ping 100.x.y.z`.

Finally, tell the user to open <https://login.tailscale.com/admin/machines>, find the device, and choose **"…" → Disable key expiry**. Otherwise it drops off after 180 days.

## Troubleshooting (match the log)

| Log shows | Cause | Fix |
|---|---|---|
| `Device is waiting for approval` | Device approval is on for the tailnet and the key was not pre-approved | Approve it at <https://login.tailscale.com/admin/machines>, or use a pre-approved key next time |
| `DERP connect attempt N failed, retrying in ...` repeating | Outbound HTTPS (443) to Tailscale's relays is blocked or the internet is down | Check the network; it keeps retrying by itself (2 s up to 60 s) |
| `WiFi disconnected, reason=201` repeating | WiFi name not found | Check the SSID, and that the network is 2.4 GHz |
| `reason=15` or `reason=204` repeating | Wrong WiFi password | Fix the password, delete `sdkconfig`, rebuild |
| `reason=2` / `205` once, then `WiFi connected` | Normal first-attempt retry | Nothing to do |
| `Registration needs a login` or `Registration rejected by the control server`, or `Registering...` then `MapRequest failed, will retry` forever | Auth key invalid, expired or already used | Get a new key, put it in `sdkconfig.credentials`, delete `sdkconfig`, rebuild. If the device joined before with another key, the user may need `erase-flash` (ask first) |
| `Out of memory for MapResponse` or `Incomplete MapResponse` | Not enough RAM (big tailnet or small chip) | Use a board with PSRAM, or raise `CONFIG_ML_H2_BUFFER_SIZE_KB` if PSRAM is present |
| `Failed to resolve component 'wireguard_lwip'` | Old upstream checkout | Use this repository (step 4) |
| `idf.py: command not found` | ESP-IDF not activated in this shell | Step 1 |
| Build OK, flash: `Failed to connect to ESP32` | Board not in download mode or port busy | Close other serial monitors; BOOT+RESET (step 6) |

## Adding TailTiny to an existing project

1. Copy `examples/basic_connect/sdkconfig.defaults` (and `sdkconfig.defaults.esp32s3` if they use an S3) into the project.
2. In the project's top-level `CMakeLists.txt`, before `include($ENV{IDF_PATH}/tools/cmake/project.cmake)`, add:
   ```cmake
   set(EXTRA_COMPONENT_DIRS "<path>/tailtiny/components/tailtiny")
   ```
3. Add `tailtiny` to the `REQUIRES` of the component that uses it.
4. Use `examples/basic_connect/main/main.c` as the template: WiFi first, then `tailtiny_init()`, `tailtiny_start()`, and wait for `tailtiny_is_connected()`. API details are in `docs/REFERENCE.md`.

## Repository map

| Path | What |
|---|---|
| `components/tailtiny/` | The library. Add this one folder to your project |
| `components/tailtiny/components/wireguard_lwip/` | WireGuard. Pulled in automatically via `idf_component.yml` |
| `examples/basic_connect/` | Minimal app: join the tailnet, UDP echo on port 9000 |
| `docs/REFERENCE.md` | Full API, configuration options, cellular, troubleshooting |
| `docs/compat/compat.json` | Chip support data behind `docs/compatibility.svg` |
