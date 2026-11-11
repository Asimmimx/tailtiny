# Changelog

## v3.2.0 (2026-11-11)

Fixes for open upstream issues and for bugs fixed in other MicroLink forks: one-way tunnels to peers behind CGNAT ([upstream #18](https://github.com/CamM2325/microlink/issues/18), [#41](https://github.com/CamM2325/microlink/issues/41)), peers the control server removes, endless WireGuard handshake retries, and a `tailtiny_stop()` that could leave tasks running into freed memory. Fixes found in [Csontikka](https://github.com/Csontikka/microlink), [fugo101](https://github.com/fugo101/microlink), [antmanler](https://github.com/antmanler/microlink), [jetkvm](https://github.com/jetkvm/microlink), [cplewes](https://github.com/cplewes/microlink) and [djorr5](https://github.com/djorr5/microlink) were checked against this code and written for it here. Also the idle-power and peer-update work [tozes](https://github.com/tozes) contributed in [#13](https://github.com/Asimmimx/tailtiny/pull/13) to [#17](https://github.com/Asimmimx/tailtiny/pull/17).

### Behaviour changes to know about

- **WireGuard goes over DERP until DISCO confirms a direct path.** On a LAN that takes about a second; until then a peer's first packets are relayed. Peers behind CGNAT, which could only get one-way traffic before, now work over DERP.
- **A handshake that nobody answers is retried for 90 s, then dropped** until there's traffic for that peer again (`[WG_PERIODIC] Handshake to key=... unanswered for 90 s, giving up until there is traffic`). It used to be retried every 5 s forever.
- **Peers the control server removes are removed**, also from the NVS peer cache (`Peer removed: <name> (<ip>, not in the peer list)`).
- **`tailtiny_stop()` returns once every task has exited**, usually in about 100 ms (it always took 3 s), and waits at most 20 s. If a task is still running then, it logs an error and `tailtiny_destroy()` leaks the instance rather than free it under that task.
- **TailTiny no longer answers a CallMeMaybe with one.**

### Fixes

- **WireGuard: a handshake after a reboot is no longer dropped.** The handshake initiation's timestamp (TAI64N) was the time since boot. A WireGuard peer drops an initiation whose timestamp isn't newer than the last one it accepted from that key (replay protection; wireguard-go logs `handshake replay`), and after a reboot the time since boot starts again near 0. So every initiation TailTiny sent after a reboot was dropped, and a session only came up once the peer started a handshake itself, or had forgotten the old timestamp. `wireguard_tai64n_now()` now uses the wall clock once it is set (an RTC, SNTP or the application, from 2020 on), and the time since boot only until then. It never goes backwards within a boot, also when SNTP steps the clock back. `tests/host/check_tai64n.py` checks it.

- **A control-server update no longer resets peers that haven't changed.** Every long-poll MapResponse lists all peers again. For each one already known, `add_peer()` reset its direct path, re-added it to wireguard-lwip, sent a CallMeMaybe and a forced DISCO probe, and rewrote the whole NVS peer table. With a dozen peers that was about a second of the WireGuard task's time right after connecting, and a flash write per peer, which stalls both cores. Live traffic waited (on an ESP32-S3, TCP to a peer retransmitted during it) and direct paths fell back to DERP until DISCO found them again. A peer whose VPN address, DISCO key, home DERP region and endpoints are unchanged, and that is already in wireguard-lwip, now only takes its online state and hostname, and still gets a CallMeMaybe. `ml_peer_nvs_save()` skips the flash write when the entry is unchanged, unless an earlier write failed. And a peer whose VPN address changes is removed from wireguard-lwip and added again, so its allowed IP follows (wireguardif_add_peer() kept the old one).

- **WireGuard goes only to a DISCO-confirmed address, or over DERP** ([upstream #18](https://github.com/CamM2325/microlink/issues/18), [#41](https://github.com/CamM2325/microlink/issues/41)). A new peer's WireGuard endpoint was its first netmap endpoint, an address nobody had checked, and wireguardif sends to any endpoint it has. For a peer behind carrier-grade NAT, or a phone that had left the WiFi whose address it advertised, every reply went there while the peer's packets came in over DERP: a one-way tunnel. The endpoint now stays empty (DERP) until a direct DISCO PONG sets it, as in Tailscale's magicsock; the netmap endpoints are still the DISCO probe targets. A peer that reaches us over DERP while DISCO trusts no direct path to it gets its replies over DERP too (`<peer> reached us over DERP: ...`), the endpoint is also forgotten when a direct path's trust expires without a session, and `ml_wg_mgr_trigger_handshake()` only tries the direct address while DISCO trusts it.

- **Peers the control server removes are removed.** `PeersRemoved` holds NodeIDs (numbers), and `PeersChangedPatch` is an array of changes that name their peer by `NodeID`; both were read as nodekey strings, so nothing from them was ever applied: a deleted node kept its peer slot (8 without PSRAM) and its DISCO probes, and a peer's new endpoints, home DERP region, DISCO key (a restarted client) and online state only arrived with the next full netmap. `OnlineChange` wasn't read either. All three are now applied by NodeID. A full `Peers` list now also drops peers it doesn't name, from the peer table and from the NVS cache (which preloaded them on every boot), and a node that comes back under a new node key replaces its old one instead of leaving a second WireGuard peer with the same /32.

- **WireGuard handshake retries stop after 90 s, and outgoing traffic starts one.** A peer with no session was sent an initiation every 5 s for as long as it stayed `active`, also when it was offline or had dropped us: two X25519 operations each, and the chip was never idle long enough to sleep. Retries now stop after 90 s (wireguard-go's `RekeyAttemptTime`). In turn, a packet for a peer with no session asks for a handshake, as in wireguard-go; it was dropped (`ERR_CONN`) without one, and only the endless retries had hidden that.

- **WireGuard: a session that stopped answering is re-handshaken after 15 s.** When data goes out and nothing authenticated comes back for 15 s (wireguard-go's new-handshake timer), a new handshake starts. A peer that restarted or moved was sent data on its dead session until the rekey, up to two minutes later.

- **WireGuard: the replay check comes before the endpoint update.** A packet that decrypted moved the peer's endpoint to its source and refreshed the timers before the replay window was checked (and keepalives weren't checked at all), so anyone who captured one of a peer's packets could resend it from their own address and redirect our packets for that peer. The handshake-initiation rate limit subtracted the wrong way round and never limited anything.

- **The handshake timestamp follows the control server's clock while the system clock isn't set.** Without SNTP or an RTC (`basic_connect` has neither), the timestamp was still the time since boot, so a peer still dropped our initiations after a reboot. The MapResponse's `ControlTime` now sets it (for WireGuard only; the system clock is left alone).

- **A peer reachable on two addresses no longer gets a handshake every 3 s.** WireGuard's endpoint follows where the peer's packets come from, and each heartbeat PONG on the DISCO path forced a new handshake when that was the other address (LAN and a NAT hairpin, say). A PONG now switches the session only for a new DISCO path, or one still on DERP.

- **`tailtiny_stop()` waits for the tasks to exit, and frees what they held.** It slept a fixed 3 s, and a task still in a reconnect backoff (up to 16 s), the wait for DERP (15 s), a DERP region probe or a TLS handshake then ran on into queues and an instance that `tailtiny_destroy()` had freed. `ml_net_switch` stops and destroys TailTiny when a rebind fails, a transport doesn't come up or the VPN doesn't connect in time, and so does an application that restarts TailTiny. Each task now clears its bit as it exits and stop waits up to 20 s for all of them (if one is still running, destroy leaks the instance instead of freeing it under it). The WireGuard device with its keys (about 15 KB) and the DERP TLS session and socket are freed, and `tailtiny_start()` after a stop works (the shutdown bit was never cleared, so every new task exited at once).

- **DERP: a dead relay connection is noticed.** One that died without a FIN or RST (a NAT that forgot it, a router reboot) looked connected forever while we had nothing to send, so peers that reach us over DERP couldn't. The relay sends a keepalive every 60 s; after 150 s with nothing received, TailTiny reconnects. A frame header split across two TLS records no longer drops the connection.

- **Smaller fixes.** DISCO no longer derives its box key with an X25519 for every packet ([upstream #31](https://github.com/CamM2325/microlink/pull/31); 30-40 ms each on an ESP32-S3), the key per peer is kept. A CallMeMaybe is no longer answered with one: Tailscale never does, and two TailTiny devices kept one going back and forth. The direct one-shot handshake is tried again when DISCO finds a new path. The Noise handshake's reply is read into a buffer of at least 512 bytes and must be 48 bytes long (1 or 2 body bytes after the HTTP 101 overflowed it). The MapResponse JSON is found after its 4-byte length prefix, not at the first `{`, which a length byte could be.

### New options

- **`CONFIG_ML_TASK_DERP_CORE`: the core for the DERP task** (0 or 1, default 0, so nothing changes unless set). The DERP relay's TLS handshake took about 3 s of CPU on an ESP32-S3, at priority 5 on core 0, and a lower-priority task there can't run during it: in one product whose UI loop runs on core 0 at priority 1, the screen froze for 2.6 to 2.9 s at every DERP connect. With the option set to 1 the longest stall around the connect was 257 ms, and the handshake took 3.0 to 3.8 s in the background. This moves the contention to core 1, where lower-priority tasks wait instead. Single-core targets always use core 0.

### Power

- **Follow-ups to the coord and net_io waits.** A STUN socket the coord task creates wakes net_io, so its first reply isn't held for up to 1 s until net_io's `select()` times out. The WireGuard task's wait is rounded up to whole ticks: rounded down, it often woke a tick before its job was due and then waited again. The init warning for missing eventfds names both tasks when both lack one.

- **The coord and net_io tasks wait for work too, and no task wakes every 100 ms.** With the DERP and WireGuard tasks waiting since 3.1.0, the coord task still checked the control connection for 50 ms and then slept 50 ms, and the net_io task's `select()` timed out every 50 ms: about 30 wake-ups a second between them, so the chip seldom stayed idle long enough to sleep. The coord task's long-poll now waits in one `select()` on the control connection and an eventfd, which STUN replies, commands, a DERP region change and `tailtiny_stop()` write. The net_io task's `select()` includes its own eventfd, which `tailtiny_rebind()` and `tailtiny_stop()` write. Both wait up to 1 s, enough for the H2 PING every 5 s and the STUN retries every 2 s. The DERP task waits up to 1 s while connected (still 100 ms while reconnecting), and the WireGuard task until its next timer is due (every 400 ms, unchanged, since that's where a handshake an outgoing packet asks for is sent) instead of every 100 ms. On an ESP32-S3 idle on the tailnet, time in light sleep went from about 13% to about 33%. Each task falls back to its old polling on its own if its eventfd can't be created, with `CONFIG_VFS_SUPPORT_SELECT` off, and on a cellular AT socket. `tests/host/check_idle_wait.py` checks the new wiring.

### How it was checked

- All five examples build with ESP-IDF v5.3.2 with no warnings (`basic_connect` for esp32c3 and esp32s3, also with `CONFIG_ML_TASK_DERP_CORE=1` and with `CONFIG_VFS_SUPPORT_SELECT=n`; the others for esp32s3). The library is about 5 KB larger.
- Host tests pass: `run_tests.py`, `check_wg_locking.py`, `check_noise_aead.py`, `check_idle_wait.py` and `check_tai64n.py`, which now also checks the ControlTime fallback.
- On an ESP32-C3 without PSRAM, v3.1.0 plus #13-#17 against this release with the same test firmware: three boots each with device-started traffic (149 of 150 packets arrived in every boot of both), 10 minutes idle with light sleep (69.5% asleep before, 75.3% now), echo after idle and after a rebind (30 of 30 in both), and `tailtiny_stop()`: 3018 ms before, 115 ms now, with all tasks gone.
- Upstream #18 on the same board, with a test patch that drops all direct UDP both ways (so only DERP works) and the PC sending first: before, 0 of 40 echoes came back (the PC re-handshook 8 times, every reply went to the dropped direct path); now 40 of 40, through DERP.
- Not run on hardware: removals and patches from the control server, the 90 s retry limit, the 15 s re-handshake and the DERP receive timeout need a node deleted from the tailnet, a peer going away or a dead relay connection.

## v3.1.0 (2026-11-07)

Security fixes for WireGuard and DERP, ESP-IDF 6 support, and automatic light sleep while the tailnet is idle. All of it was contributed by [tozes](https://github.com/tozes) in [#2](https://github.com/Asimmimx/tailtiny/pull/2), [#4](https://github.com/Asimmimx/tailtiny/pull/4) and [#6](https://github.com/Asimmimx/tailtiny/pull/6) to [#12](https://github.com/Asimmimx/tailtiny/pull/12).

### Behaviour changes to know about

- **The DERP relay's certificate is now verified** (`CONFIG_ML_DERP_VERIFY_CERT`, on by default). A self-hosted DERP server with a private certificate is refused (`DERP certificate for <host> not accepted: ...`) until you add its CA to the bundle or turn the option off. It adds about 70 KB of flash with the default full bundle, or 21 KB with `CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_CMN`.
- **TailTiny registers ESP-IDF's eventfd VFS** in `tailtiny_init()` (default config) when `CONFIG_VFS_SUPPORT_SELECT` is on. If your application registers it itself with its own config, do that before `tailtiny_init()`: afterwards, `esp_vfs_eventfd_register()` returns `ESP_ERR_INVALID_STATE`. TailTiny reuses a VFS that's already registered.
- **ESP-IDF 5.0 to 5.2 are refused by the component manifest.** They never built (`esp_driver_tsens` needs 5.3).
- `basic_connect` is about 4 KB larger for the light-sleep change (eventfd VFS and `select()`).

### Fixes

- **WireGuard: the timer task and lwIP's thread no longer share keypairs without a lock.** Since the timers moved off lwIP's thread (`wireguardif_periodic()` on the WireGuard manager task), keepalives, handshakes, key expiry and incoming packets ran on that task while lwIP's thread encrypted outgoing data, with nothing between them. A keepalive and a data packet could take the same sending counter (the same ChaCha20-Poly1305 nonce under the same key), and a key could be wiped while a packet was being encrypted with it ([#1](https://github.com/Asimmimx/tailtiny/issues/1)). Each WireGuard device now has a mutex (`wireguard-platform.h`), held for everything that reads or changes keypairs, counters, handshake state and the peer table. Sends happen after it's released, to a copy of the peer's endpoint, because the UDP send waits for lwIP's thread (`ml_tcpip_run()`), which may be waiting for the lock. `tests/host/check_wg_locking.py` checks that rule in `wireguardif.c`; on v3.0.2's file it finds 35 unlocked calls.
- **DERP: the relay's TLS certificate is verified.** The DERP connection used `MBEDTLS_SSL_VERIFY_NONE`, so anyone on the network path could pose as the relay. WireGuard still protected what it carried, but a fake relay could silently drop or delay it. The certificate is now checked against ESP-IDF's certificate bundle and the relay's host name (new `CONFIG_ML_DERP_VERIFY_CERT`, on by default; it needs `MBEDTLS_CERTIFICATE_BUNDLE`, also on by default). Tailscale's relays chain to ISRG Root X1, which the bundle has, from ESP-IDF v5.3.2 on. It links ESP-IDF's certificate bundle: about +70 KB of flash with the default full bundle, +21 KB with `CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_CMN`. Turn it off for a self-hosted DERP server with a private certificate. A refused certificate is logged with the reason.
- **`idf_component.yml` asks for ESP-IDF 5.3 or newer.** It said 5.0, but TailTiny requires `esp_driver_tsens`, which ESP-IDF added in 5.3, so on 5.0 to 5.2 the build stopped at `Failed to resolve component 'esp_driver_tsens'`. The README already says 5.3 or newer.

### ESP-IDF 6

- **cJSON comes from the component registry on ESP-IDF 6.** ESP-IDF 6 no longer ships cJSON as the `json` component, so CMake stopped at `Failed to resolve component 'json'`. On ESP-IDF 6 and later, `idf_component.yml` now pulls `espressif/cjson` and TailTiny requires `espressif__cjson`. ESP-IDF 5 keeps its built-in `json`.
- **TailTiny requires the UART and GPIO driver components.** `ml_at_socket.c` and `ml_cellular.c` include `driver/uart.h` and `driver/gpio.h`, which came through `driver` until ESP-IDF 6 split them out. TailTiny now requires `esp_driver_uart` and `esp_driver_gpio`, which exist from ESP-IDF 5.3 on.
- **Builds with GCC 15.** GCC 15, which ESP-IDF 6 uses, rejects a byte array initialised from a string of exactly its length unless the array is marked `nonstring`, and ESP-IDF builds with `-Werror`. WireGuard's protocol names in `wireguard.c` (`CONSTRUCTION`, `IDENTIFIER`, `LABEL_MAC1`, `LABEL_COOKIE`) and Salsa20's constant in `nacl_box.c` are such arrays on purpose, and are now marked `__attribute__((nonstring))` (GCC 8 and later).
- **DERP's TLS works with Mbed TLS 4.** Mbed TLS 4, which ESP-IDF 6 ships, draws TLS randomness from PSA, made its entropy and CTR-DRBG modules private and removed `mbedtls_ssl_conf_rng()`. The DERP connection's entropy and CTR-DRBG contexts, their seeding and freeing, and the `mbedtls_ssl_conf_rng()` call are now compiled only with Mbed TLS 3 (`MBEDTLS_VERSION_MAJOR < 4`). ESP-IDF 6 initialises PSA at startup. Certificate verification (`CONFIG_ML_DERP_VERIFY_CERT`) is unchanged.
- **The Noise control channel uses wireguard-lwip's ChaCha20-Poly1305.** Mbed TLS 4, which ESP-IDF 6 ships, made its ChaCha20-Poly1305 API private. `ml_noise.c` now uses the reference implementation that the bundled wireguard-lwip already uses for WireGuard, through `noise_aead_encrypt()`/`noise_aead_decrypt()` in the new `src/ml_noise_aead.h`, on every ESP-IDF version. Tailscale's nonce is 4 zero bytes and then the counter big-endian, while wireguard-lwip writes its counter little-endian into the same 8 bytes, so the wrapper passes the counter byte-swapped. `tests/host/check_noise_aead.py` checks it against RFC 8439's appendix A.5 vector in both byte orders, against messages sealed by Python's `cryptography` for other counters, an empty payload and no associated data, and that a changed byte, associated data, counter or a cut-short message is refused.

### Power

- **The DERP and WireGuard tasks sleep until there's work.** The DERP task polled TLS and then yielded for one tick, and the WireGuard task woke every 10 ms to check its RX queue. With `CONFIG_FREERTOS_HZ=100` the chip needs a few idle ticks in a row before automatic light sleep (`CONFIG_FREERTOS_USE_TICKLESS_IDLE`) can engage, so with TailTiny running it almost never did. The DERP task now waits in one `select()` on the relay socket and an eventfd that's written whenever TX or a control request is queued, so outgoing relay packets still go out at once. It skips the wait while TX is queued or Mbed TLS holds decrypted data. The WireGuard task waits for a task notification that every producer for its queues sends. Both waits are capped at 100 ms for timers, reconnects and shutdown. An AT modem socket (cellular) can't be waited on with `select()`, so the DERP task keeps polling it, and it also polls when `CONFIG_VFS_SUPPORT_SELECT` is off or no eventfd can be created (a warning, not an init failure). `tests/host/check_idle_wait.py` runs the wait against a real socket and eventfd and checks the wiring.

All five examples build with ESP-IDF v5.3.2 with no warnings.

## v3.0.2 (2026-10-13)

### Fixes

- **Config web server: no out-of-bounds read on a damaged peer allowlist.** When an allowlist saved by an old version was loaded, the peer count stored in it was not checked against the size of the saved data. A damaged or cut-short entry in NVS made the copy read past the end of the buffer. The count is now limited to the entries actually stored; if it doesn't fit, the list is dropped. The old limit check also did nothing when `CONFIG_ML_CONFIG_MAX_ALLOWED_PEERS` was 255 or more (512 in the S3 examples).
- **`cellular_connect` builds without warnings in both UDP and TCP mode.**

All five examples build with ESP-IDF v5.3.2 with no warnings.

## v3.0.1 (2026-10-13)

Completes the v3.0.0 notes and finishes the rename. No change to how the library works.

### Log output changed in v3.0.0 (missing from its notes)

| Before | After |
|---|---|
| Log tag `microlink` | `tailtiny` |
| `MicroLink v2 initialized (max_peers=N)` | `TailTiny initialized (max_peers=N)` |
| Config web page title "MicroLink" | "TailTiny" |
| Example logs: "MicroLink state", "Failed to initialize MicroLink", ... | "TailTiny state", "Failed to initialize TailTiny", ... |

If you call `esp_log_level_set("microlink", ...)`, or a script or test rig looks for `microlink` or `MicroLink v2 initialized` in the serial output, change it to `tailtiny` / `TailTiny initialized`.

### Examples

All examples now build as `tailtiny_<name>` (for example `build/tailtiny_failover_connect.bin`). v3.0.0 had renamed only `basic_connect` and `cellular_connect`; `cellular_heartbeat`, `failover_connect` and `rebind_test` follow now.

### Code comments

- The NVS namespace `"microlink"` now has a comment explaining why it must not be renamed (devices would lose their Tailscale identity).
- Source references point again to the upstream MicroLink v1 files they came from.

## v3.0.0 (2026-10-13)

MicroLink is now **TailTiny**. Only the name changed; the code does the same as v2.3.1.

### Updating an existing project

| Before | After |
|---|---|
| `components/microlink/` | `components/tailtiny/` |
| `REQUIRES microlink` | `REQUIRES tailtiny` |
| `#include "microlink.h"` | `#include "tailtiny.h"` |
| `#include "microlink_internal.h"` | `#include "tailtiny_internal.h"` |
| `microlink_*` functions and types (`microlink_init()`, `microlink_t`, ...) | `tailtiny_*` (`tailtiny_init()`, `tailtiny_t`, ...) |
| menuconfig: "MicroLink V2 Configuration" | "TailTiny Configuration" |
| github.com/Asimmimx/microlink | github.com/Asimmimx/tailtiny (the old link redirects) |

Unchanged: the `CONFIG_ML_*` options and `ml_*` names, so `sdkconfig` and `sdkconfig.credentials` files keep working. The keys are still stored in the NVS namespace `"microlink"`, so a device updated from v2.x keeps its Tailscale identity and doesn't need a new auth key.

## v2.3.1 (2026-10-09)

A RAM re-measurement for the ESP32-C2 entry of the compatibility chart. It found two low-RAM problems, fixed here, and a wrong number in v2.2.0.

### How much RAM MicroLink needs

Measured on the ESP32-C3 by holding RAM from boot to mimic a smaller chip, with a test build that forces a control reconnect 60 s in (as when the server closes the connection):

| Free after WiFi connects | Joins | Re-joins after a reconnect |
|---|---|---|
| 226 KB (C3 as is) | Yes | Yes |
| 185 KB | Yes | Yes (lowest free 25 KB) |
| 164 KB | Yes | No: the peer list no longer fits in one block |
| 156 KB | Yes | No |
| 143 KB | Joins, then loses the control connection (v2.2.0 too) | No |

So a board needs about **185 KB free after WiFi** to stay on the tailnet over time. The ESP32-C2 has about 95 KB by default and about 169 KB with Espressif's deepest RAM tuning, so it stays "Low RAM". The v2.2.0 note "still joins with only 185 KB free at boot" (about 143 KB after WiFi) was wrong: it joined, but lost the control connection right after.

### Fixes

| Problem | Before | After |
|---|---|---|
| Re-registering with little RAM | The RegisterResponse (~600 bytes) was read into 16 KB + 8 KB buffers; with ~143 KB after WiFi every re-registration failed | 6 KB + 4 KB; re-registration passes at that level |
| Long-poll message when RAM is tight | The 22 KB full netmap sent first on each long-poll was taken even with little RAM left | Skipped when it would leave less than 48 KB (keepalives and small updates are always taken). Normal boards still parse it |
| Running out of memory reading a control message | No log, and `errno` could still hold an old EAGAIN, so the half-read stream was treated as "no data" | Logged with the frame size and free heap, and the connection is reopened |
| Build warnings | 9 (unused functions and variables) | 0 |

`Out of memory for MapResponse` now also shows the free heap and the largest free block.

## v2.3.0 (2026-10-09)

Checked on an ESP32-C3 without PSRAM (ESP-IDF v5.3.2) on a 6-device tailnet, with a Windows peer and an Android peer on the same LAN.

### Fixes

| Problem | Before | After |
|---|---|---|
| Device sometimes shown offline in the admin console while its log said `CONNECTED` ([#40](https://github.com/CamM2325/microlink/pull/40)) | The control watchdog was reset by our own 5 s HTTP/2 PINGs, which keep succeeding on a dead long-poll, so it never fired. Server GOAWAY, RST_STREAM and END_STREAM on the long-poll, and a closed socket (`recv()` = 0 read as "no data"), went unnoticed | Watchdog only counts data on the long-poll stream (the server sends a keepalive about once a minute). GOAWAY, RST_STREAM, END_STREAM and a closed socket reconnect at once. A test build that ignored the long-poll reconnected 120 s later, in 7 s, and was never shown offline |
| Long-poll updates larger than one Noise message (~4 KB) | Split HTTP/2 frames were dropped, and their remaining bytes were read as frame headers. The full netmap sent at the start of every long-poll was never parsed | HTTP/2 frames and MapResponses are reassembled across Noise messages. The long-poll copy of the DERPMap is skipped (it is loaded on every connect), so the lowest free heap after joining stays 62–66 KB |
| Registration errors were silent ([#23](https://github.com/CamM2325/microlink/pull/23)) | A rejected or used-up auth key only showed as `MapRequest failed, will retry` forever | The server's reason is logged: `Registration rejected by the control server: ...`, `Registration needs a login: ...` (invalid, expired or already-used key), or a warning when the device waits for approval. Not reproduced on hardware: it would need the device's identity erased |
| Direct path flipping between a peer's LAN and public address | A peer on the same LAN answers on both (the router hairpins the public one). Whichever PONG came first won, so the path flipped every ~2 min and each flip forced a new WireGuard handshake: 14 flips in 8 min | A trusted direct path is kept; it is left only for a LAN path or once it stops answering. 0 flips in 10 min, settled on the LAN path |
| `DISCO PONG unmatched` warnings | One ping goes out on several paths with the same txid, and the peer answers each. Only the first PONG matched; the rest were logged as warnings, dozens per minute | Extra PONGs are recognised as duplicates (DEBUG). A direct PONG that arrives after a DERP one now still sets up the direct path. 0 warnings in 10 min |
| Endpoint update every 23 s | Each STUN re-probe sent a new MapRequest to the control server, even when nothing had changed | Sent only after a change, or every 10 minutes: 2 in 10 min |

### Behaviour changes to know about

- **Logs**: `STUN probe sent`, `STUN mapped`, `MapRequest includes N endpoint(s)` and repeated `WG endpoint stored (no session)` lines are now DEBUG.
- `ml_coord` logs `Control plane watchdog timeout: no long-poll data for 120s` when it reconnects for that reason. `ctrl_watchdog_ms` keeps its default of 120000; don't set it below about 70000, since the server's keepalive comes about once a minute.

### Still open

- Unvalidated endpoints for peers behind CGNAT ([#18](https://github.com/CamM2325/microlink/issues/18)) and stale endpoints for peers reached through DERP ([#41](https://github.com/CamM2325/microlink/issues/41)). Testing these needs a phone on mobile data.

### Removed

- The Cortex-M0 assembly X25519 and the sample platform file in `wireguard_lwip`. They were never built and can't run on an ESP32.

## v2.2.0: maintained fork (2026-10-05)

First release of [Asimmimx/microlink](https://github.com/Asimmimx/microlink), a maintained fork of [CamM2325/microlink](https://github.com/CamM2325/microlink) v2.1.0.

Every fix below was checked on real hardware (ESP32-C3 without PSRAM, ESP-IDF v5.3.2), usually by reproducing the bug first and then measuring before and after. Each one is a separate commit. Upstream pull requests were not merged; where one existed, the bug was reproduced here and the fix written and tested independently.

### Fixes

| Problem | Before | After |
|---|---|---|
| Single-core chips (C3, C6) | Reboot loop on start (task pinned to Core 1) | Connects normally |
| Boards without PSRAM | `MapRequest failed` forever (out of memory) | Peer list loads |
| Crash when a packet arrived while a socket was opening ([#17](https://github.com/CamM2325/microlink/issues/17)) | Load access fault in `udp_input`, reboot | lwIP is only touched from its own thread. Checked with `CONFIG_LWIP_CHECK_THREAD_SAFETY` |
| Peak RAM while joining a tailnet | Free RAM dipped to 9.7 KB on a C3 | Lowest point 84–93 KB; still joins with only 185 KB free at boot (corrected in v2.3.1: at that level the control connection is lost right after joining) |
| Long-poll allocated 64 KB per message | Control connection lost when RAM was tight | Stays connected |
| FreeRTOS at 100 Hz, the ESP-IDF default ([#36](https://github.com/CamM2325/microlink/issues/36)) | Watchdog every 5 s; app task never ran | No watchdog trips |
| Packet loss under load (as in PRs [#30](https://github.com/CamM2325/microlink/pull/30), [#32](https://github.com/CamM2325/microlink/pull/32), [#38](https://github.com/CamM2325/microlink/pull/38)) | Per-packet INFO logs throttled the tunnel: 50 msg/s gave 71% loss and 784 ms | 100 msg/s: 0% loss, 19 ms |
| DERP relay fixed to Dallas ([#19](https://github.com/CamM2325/microlink/issues/19)) | Relay latency from Turkey: 168 ms | Closest region measured and remembered: about 60 ms |
| Failed DERP connects ([#37](https://github.com/CamM2325/microlink/pull/37)) | ~10 KB leaked per attempt; gave up after 3 attempts | No leak; retries with 2–60 s backoff |
| Peer online status ([#24](https://github.com/CamM2325/microlink/pull/24)) | Every peer reported online | Matches `tailscale status` |
| UDP RX task priority ([#39](https://github.com/CamM2325/microlink/pull/39)) | Same as ESP-IDF's reserved Bluetooth controller priority | 12, below the system tasks; same throughput |
| Tunnel MTU ([#34](https://github.com/CamM2325/microlink/issues/34)) | 1420 (plain WireGuard) | 1280 (Tailscale) |
| Web config panel on the original ESP32 | Build error (no temperature sensor) | Builds |

### Setup

- One component folder. The `wireguard_lwip` symlink that broke every Windows build is replaced by `idf_component.yml`.
- `sdkconfig.credentials` is actually read now (it was documented but ignored).
- `basic_connect` builds for any chip with `idf.py set-target <chip>`. Buffer sizes follow PSRAM automatically.
- `AGENTS.md` lets an AI assistant set the project up end to end. Two helper scripts support it: `tools/serial_log.py` and `tools/udp_echo.py`.

### Behaviour changes to know about

- **PreferredDERP**: the device now reports the region it measured as closest, not region 9. It is stored in NVS under the key `derp_pref`.
- **`microlink_peer_info_t.online`** now means "online according to the control plane". Before, it meant "has a slot in the local peer table".
- **Logs**: per-packet and per-tick lines (`UDP RX`, `WG RX/TX`, `DISCO ...`, `DERP status`, `HEARTBEAT`) are now DEBUG. Set the `ml_*` tags to DEBUG to see them again.
- **Defaults without PSRAM**: `ML_H2_BUFFER_SIZE_KB` 80 (a cap, not a reservation), `ML_JSON_BUFFER_SIZE_KB` 64 (no longer used for the initial MapResponse), `ML_MAX_PEERS` 8.

### Still open

- Unvalidated endpoints for peers behind CGNAT ([#18](https://github.com/CamM2325/microlink/issues/18)) and stale endpoints for peers reached through DERP ([#41](https://github.com/CamM2325/microlink/issues/41)). Testing these needs a phone on mobile data.
- Registration errors are silent ([#23](https://github.com/CamM2325/microlink/pull/23)). Fixed in v2.3.0.
- RST_STREAM/GOAWAY on the long-poll are not handled ([#40](https://github.com/CamM2325/microlink/pull/40)). Fixed in v2.3.0.
