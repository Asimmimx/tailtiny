/**
 * @file ml_net_switch.h
 * @brief TailTiny Network Switching — WiFi Primary + Cellular Fallback
 *
 * Manages automatic failover between WiFi and cellular connectivity.
 * WiFi is the primary transport; when it fails, switches to cellular.
 * Periodically checks if WiFi has recovered and fails back.
 *
 * Architecture:
 *   - Full stop/start cycle on transport switch (tailtiny_stop → switch → tailtiny_start)
 *   - Health check timer detects connectivity loss
 *   - Failback timer periodically checks if WiFi has recovered
 *   - All Tailscale operations work unchanged on either transport
 */

#pragma once

#include "esp_err.h"
#include "tailtiny.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Types
 * ========================================================================== */

typedef enum {
    ML_NET_WIFI = 0,
    ML_NET_CELLULAR,
} ml_net_type_t;

typedef enum {
    ML_NET_SW_IDLE = 0,             /* Not started */
    ML_NET_SW_WIFI_CONNECTING,      /* Connecting to WiFi */
    ML_NET_SW_WIFI_VPN_UP,          /* WiFi + Tailscale connected */
    ML_NET_SW_SWITCHING_TO_CELL,    /* Transitioning to cellular */
    ML_NET_SW_CELL_CONNECTING,      /* Initializing cellular modem */
    ML_NET_SW_CELL_VPN_UP,          /* Cellular + Tailscale connected */
    ML_NET_SW_SWITCHING_TO_WIFI,    /* Trying WiFi failback */
    ML_NET_SW_ERROR,                /* Fatal error */
} ml_net_switch_state_t;

typedef struct {
    /* WiFi credentials */
    const char *wifi_ssid;
    const char *wifi_password;

    /* Cellular settings */
    const char *sim_pin;
    const char *apn;

    /* Tailscale */
    const char *tailscale_auth_key;
    const char *device_name;

    /* Timing (0 = use the default; the _ms defaults come from Kconfig
     * "Network Switching", CONFIG_ML_NET_SWITCH_*_MS) */
    uint32_t wifi_timeout_ms;           /* WiFi connect timeout (default: 30000) */
    uint32_t health_check_interval_ms;  /* Health check period (default: 30000) */
    uint32_t health_fail_count;         /* Failures before switch (default: 3) */
    uint32_t failback_check_ms;         /* WiFi recovery check (default: 120000; set
                                           CONFIG_ML_NET_SWITCH_FAILBACK_MS=0 to disable) */

    /* Callbacks (all optional) */
    void (*on_connected)(ml_net_type_t type, void *user_data);
    void (*on_disconnected)(void *user_data);
    void (*on_switching)(ml_net_type_t from, ml_net_type_t to, void *user_data);
    void *user_data;
} ml_net_switch_config_t;

/* ============================================================================
 * API
 * ========================================================================== */

/**
 * Initialize network switching module.
 * Copies config internally. Does NOT start connecting.
 *
 * @param config  Configuration (strings are copied)
 * @return ESP_OK on success
 */
esp_err_t ml_net_switch_init(const ml_net_switch_config_t *config);

/**
 * Deinitialize and free resources.
 * Calls ml_net_switch_stop(); if the switch task hasn't exited, nothing is
 * freed (an error is logged) and deinit can be called again later.
 */
void ml_net_switch_deinit(void);

/**
 * Start the connection sequence: WiFi first, then cellular fallback.
 * Non-blocking. Monitor state via callbacks or ml_net_switch_get_state().
 *
 * @return ESP_OK on success
 */
esp_err_t ml_net_switch_start(void);

/**
 * Stop all connections and halt the state machine.
 *
 * Tells the switch task to stop and waits for it to stop and destroy
 * TailTiny, stop the active transport and exit. No on_* callback is called
 * for this: close sockets made on the handle before calling it.
 * Must not be called from an on_* callback.
 *
 * @return ESP_OK once the task has exited,
 *         ESP_ERR_TIMEOUT if it was still busy after 5 minutes (powering up
 *         the modem, say); call again to keep waiting,
 *         ESP_ERR_INVALID_STATE if called from the switch task (a callback)
 */
esp_err_t ml_net_switch_stop(void);

/**
 * Get the currently active transport type.
 *
 * @return ML_NET_WIFI or ML_NET_CELLULAR
 */
ml_net_type_t ml_net_switch_get_active(void);

/**
 * Get the current state machine state.
 */
ml_net_switch_state_t ml_net_switch_get_state(void);

/**
 * Get the current tailtiny_t handle.
 * Returns NULL if not connected.
 *
 * The switch destroys the handle and creates a new one when it restarts the
 * VPN (connect timeout, failed rebind, retry after both transports failed),
 * so don't keep it, or sockets made on it, across a switch. Before it
 * destroys a handle that on_connected announced, it calls on_switching or
 * on_disconnected (ml_net_switch_stop() excepted): close the sockets there
 * (tailtiny_udp_close()) and make them again once connected.
 * examples/failover_connect shows the pattern.
 */
tailtiny_t *ml_net_switch_get_handle(void);

/* ml_net_switch_get_udp_socket() was declared here but never implemented
 * (calling it failed to link); it's gone. */

/**
 * Convert state to string for logging.
 */
const char *ml_net_switch_state_str(ml_net_switch_state_t state);

#ifdef __cplusplus
}
#endif
