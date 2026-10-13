# TailTiny: Tailscale for ESP32

Put an ESP32 on your [Tailscale](https://tailscale.com) network. Once it's on your tailnet, any of your devices can reach it from anywhere: phone, laptop, server. You don't need port forwarding or a public IP.

> TailTiny is a maintained fork of [MicroLink](https://github.com/CamM2325/microlink) (renamed in v3.0.0), which has had no commits since March 2026.
> It adds bug fixes, plus easier setup and ESP32-C3 support. Every fix was tested on real hardware ([what changed](#what-this-fork-fixes)).

---

## Which ESP32 works?

<img src="docs/compatibility.svg" alt="ESP32 compatibility chart: ESP32-C3 tested; ESP32-S3, ESP32 and ESP32-C6 should work; ESP32-S2 and C2 have too little RAM without PSRAM; ESP32-C5/C61 need a newer ESP-IDF; ESP32-H2 and P4 are not supported" width="760">

<details>
<summary>Same table as text</summary>

| Chip | Status | Notes |
|---|---|---|
| ESP32-C3 | ✅ Tested on hardware | Tested with this fork: no PSRAM, single core |
| ESP32-S3 | 🟡 Should work | The original author's main board. PSRAM recommended |
| ESP32 | 🟡 Should work | Tested by the original author (no PSRAM) |
| ESP32-C6 | 🟡 Should work | Builds. Single core like the C3, with more RAM |
| ESP32-S2 | 🟠 Low RAM | Builds. RAM use not measured on an S2 yet; use a board with PSRAM (most S2 boards have it) |
| ESP32-C2 | 🟠 Low RAM | Builds. TailTiny needs about 185 KB free after WiFi connects to keep reconnecting reliably (about 156 KB just to join once). A C2 has about 95 KB by default, and about 169 KB with Espressif's deepest RAM tuning on ESP-IDF 5.5 ([Espressif](https://developer.espressif.com/blog/2025/11/esp32c2-ram-optimization/)), so it is still short |
| ESP32-C5 / C61 | ❔ Unknown | WiFi support needs ESP-IDF 5.5+. Not built yet |
| ESP32-H2 | ❌ No | No WiFi (Thread/Zigbee/BLE only) |
| ESP32-P4 | ❌ No | No built-in WiFi |

"Should work" means it builds with ESP-IDF v5.3.2 using this fork, but hasn't been run on hardware with this fork yet. The RAM numbers come from an ESP32-C3 with part of its memory held back to mimic a smaller chip ([details](CHANGELOG.md)). If you try one, please [open an issue](https://github.com/Asimmimx/tailtiny/issues) with the result.

</details>

---

## Set it up with an AI assistant

Working with Claude Code, Codex, Cursor or Copilot? Open this repository and say:

> *Set up TailTiny on my ESP32 board.*

The assistant reads [`AGENTS.md`](AGENTS.md). It detects your chip and serial port, asks you only for your WiFi details and Tailscale key, then builds, flashes and checks the connection.

---

## Quick start (about 15 minutes)

**You need:** an ESP32 board from the table above, a USB cable, and a free Tailscale account.

### 1. Install ESP-IDF

Follow Espressif's installer for your OS (v5.3 or newer):
[Windows](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/windows-setup.html) ·
[Linux / macOS](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/linux-macos-setup.html)

Run the commands below in the **ESP-IDF terminal** that the installer sets up.

### 2. Download TailTiny

```bash
git clone https://github.com/Asimmimx/tailtiny.git
cd tailtiny/examples/basic_connect
```

### 3. Get a Tailscale auth key

Open **[Tailscale admin → Settings → Keys](https://login.tailscale.com/admin/settings/keys)** and click **Generate auth key**:

- **Reusable**: off
- **Ephemeral**: **off** (otherwise the device disappears when it powers off)
- **Pre-approved**: on (if you see the option)

Copy the key. It starts with `tskey-auth-`.

### 4. Add your WiFi and key

Copy the template:

```bash
cp sdkconfig.credentials.example sdkconfig.credentials
```

Open `sdkconfig.credentials` in any text editor and fill in the three lines:

```ini
CONFIG_ML_WIFI_SSID="your-wifi-name"
CONFIG_ML_WIFI_PASSWORD="your-wifi-password"
CONFIG_ML_TAILSCALE_AUTH_KEY="tskey-auth-..."
```

`sdkconfig.credentials` is git-ignored, so your secrets stay local.

### 5. Build and flash

Replace `esp32c3` with your chip and `COM5` with your board's port (`/dev/ttyUSB0` on Linux, `/dev/cu.usbserial-*` on macOS):

```bash
idf.py set-target esp32c3
idf.py -p COM5 flash monitor
```

After about 15 seconds you should see:

```
TailTiny state: CONNECTED
Connected! VPN IP: 100.x.y.z
```

The device now shows up in your [Tailscale machines list](https://login.tailscale.com/admin/machines). Click **"…" → Disable key expiry** there, or it will drop off the network after 180 days.

### 6. Try it

From any computer on your tailnet:

```bash
ping 100.x.y.z
echo "hello" | nc -u 100.x.y.z 9000      # the example echoes it back
```

---

## Use it in your own project

1. Copy [`examples/basic_connect/sdkconfig.defaults`](examples/basic_connect/sdkconfig.defaults) into your project. It enables the crypto and network options TailTiny needs.
2. Add one line to your project's top-level `CMakeLists.txt`, before `include(...project.cmake)`:

   ```cmake
   set(EXTRA_COMPONENT_DIRS "path/to/tailtiny/components/tailtiny")
   ```

3. Start TailTiny once WiFi is connected:

   ```c
   #include "tailtiny.h"

   tailtiny_config_t cfg = {
       .auth_key    = "tskey-auth-...",
       .device_name = "my-esp32",
       .enable_derp = true, .enable_stun = true, .enable_disco = true,
   };
   tailtiny_t *ml = tailtiny_init(&cfg);
   tailtiny_start(ml);

   /* once tailtiny_is_connected(ml) is true: */
   tailtiny_udp_socket_t *sock = tailtiny_udp_create(ml, 9000);
   tailtiny_udp_send(sock, tailtiny_parse_ip("100.64.0.5"), 9000, "hi", 2);
   ```

[`examples/basic_connect/main/main.c`](examples/basic_connect/main/main.c) is a complete, working program. The full API is in the [reference](docs/REFERENCE.md#api-reference).

---

## What this fork fixes

Compared with upstream v2.1.0 (latest release: [v3.0.1](https://github.com/Asimmimx/tailtiny/releases/tag/v3.0.1)). Every item was checked on real hardware; the numbers are from an ESP32-C3 without PSRAM:

- **Runs on ESP32-C3/C6 and boards without PSRAM.** Upstream reboot-looped on single-core chips and ran out of memory without PSRAM.
- **No more crash** when a packet arrives while a socket is opening ([#17](https://github.com/CamM2325/microlink/issues/17)).
- **Much less RAM to join a tailnet.** The lowest point was 9.7 KB free; now it's 84–93 KB.
- **No packet loss under load.** 50 msg/s used to lose 71% of packets with 784 ms latency; 100 msg/s now loses none, at 19 ms.
- **Closest DERP relay instead of Dallas** ([#19](https://github.com/CamM2325/microlink/issues/19)). From Turkey, relay latency dropped from 168 ms to about 60 ms.
- **No more "offline" in the admin console while the device thinks it's connected.** A dead control connection is now noticed (GOAWAY, RST_STREAM, no keepalive for 120 s) and re-opened ([#40](https://github.com/CamM2325/microlink/pull/40)).
- **Stable direct path on your LAN.** It used to flip between a peer's LAN and public address every couple of minutes, re-handshaking each time.
- **Registration errors are logged** with the server's reason instead of an endless `MapRequest failed` ([#23](https://github.com/CamM2325/microlink/pull/23)). The rejection itself wasn't reproduced on hardware.
- **Quieter background traffic:** no flood of `DISCO PONG unmatched` warnings, and endpoints go to the control server only when they change.
- **DERP keeps reconnecting and no longer leaks memory** ([#37](https://github.com/CamM2325/microlink/pull/37)).
- **Correct peer online status** ([#24](https://github.com/CamM2325/microlink/pull/24)), plus fixes for [#34](https://github.com/CamM2325/microlink/issues/34), [#36](https://github.com/CamM2325/microlink/issues/36) and [#39](https://github.com/CamM2325/microlink/pull/39).
- **Easier setup:** one component folder, Windows builds, any chip, and a credentials file that actually gets read.

Full list with before/after measurements, behaviour changes and what's still open: **[CHANGELOG.md](CHANGELOG.md)**.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Device never shows up in Tailscale | The log says why (`Registration needs a login` / `rejected`). Usually the auth key is wrong or already used. Make a new one, and erase the old identity with `idf.py -p PORT erase-flash` |
| Changed `sdkconfig.credentials` but nothing changed | Delete the `sdkconfig` file and build again. Settings are only copied in on the first build |
| First message right after boot gets no reply | Normal. The first tunnel takes about 15 s to set up |
| `Failed to resolve component 'wireguard_lwip'` | You're on the old upstream repo. Use this fork |
| `DERP connect attempt N failed, retrying in ...` | Outbound HTTPS (port 443) is blocked or the internet is down. It keeps retrying by itself |

More in the [full reference](docs/REFERENCE.md#troubleshooting).

---

## More documentation

- [Full reference](docs/REFERENCE.md): features, memory, API, every config option, cellular (4G), headscale
- [Architecture](docs/ARCHITECTURE.md) · [Large tailnets](docs/LARGE_TAILNET.md) · [Testing guide](TESTING_GUIDE.md)

## Credits & license

TailTiny is based on MicroLink, created by **Cameron Malone** ([CamM2325](https://github.com/CamM2325)). This fork keeps his work and adds fixes on top. MIT License, see [LICENSE](LICENSE).
