/**
 * @file ml_net_switch.c
 * @brief TailTiny Network Switching — WiFi Primary + Cellular Fallback
 *
 * Full stop/start cycle approach:
 *   1. Try WiFi first (with timeout)
 *   2. If WiFi fails → tear down WiFi, init cellular, start TailTiny over cellular
 *   3. Periodic health check → if VPN drops, trigger switch
 *   4. When on cellular, periodically check if WiFi has recovered → failback
 *
 * The switch task owns the TailTiny handle and the transports: it creates,
 * stops and destroys them, also when ml_net_switch_stop() is called, which
 * waits for it.
 */

#include "sdkconfig.h"

#ifdef CONFIG_ML_ENABLE_NET_SWITCH

#include "ml_net_switch.h"
#include "ml_cellular.h"
#include "ml_at_socket.h"
#include "ml_config_httpd.h"
#include "tailtiny.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/timers.h"
#include <string.h>

static const char *TAG = "ml_net_sw";

/* ============================================================================
 * Internal State
 * ========================================================================== */

#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT       BIT1
#define NET_SW_STACK_SIZE   6144
#define WIFI_DISCONNECT_DEBOUNCE_MS  5000  /* Wait 5s before declaring WiFi dead */

/* Defaults for the ml_net_switch_config_t timing fields left at 0: Kconfig
 * "Network Switching" (CONFIG_ML_NET_SWITCH_*), which was never read. The
 * fallbacks are the Kconfig defaults. The WiFi timeout and the health-check
 * period can't be 0 (Kconfig has no range): 0 there means the old default. */
#ifndef CONFIG_ML_NET_SWITCH_WIFI_TIMEOUT_MS
#define CONFIG_ML_NET_SWITCH_WIFI_TIMEOUT_MS    30000
#endif
#ifndef CONFIG_ML_NET_SWITCH_HEALTH_INTERVAL_MS
#define CONFIG_ML_NET_SWITCH_HEALTH_INTERVAL_MS 30000
#endif
#ifndef CONFIG_ML_NET_SWITCH_FAILBACK_MS
#define CONFIG_ML_NET_SWITCH_FAILBACK_MS        120000
#endif
#define NET_SW_DEFAULT_WIFI_TIMEOUT_MS \
    (CONFIG_ML_NET_SWITCH_WIFI_TIMEOUT_MS > 0 ? CONFIG_ML_NET_SWITCH_WIFI_TIMEOUT_MS : 30000)
#define NET_SW_DEFAULT_HEALTH_INTERVAL_MS \
    (CONFIG_ML_NET_SWITCH_HEALTH_INTERVAL_MS > 0 ? CONFIG_ML_NET_SWITCH_HEALTH_INTERVAL_MS : 30000)
#define NET_SW_DEFAULT_FAILBACK_MS \
    (CONFIG_ML_NET_SWITCH_FAILBACK_MS > 0 ? CONFIG_ML_NET_SWITCH_FAILBACK_MS : 0)  /* 0 = no failback */

/* Backoff between full attempts after WiFi and cellular both failed */
#define NET_SW_RETRY_MIN_MS     30000
#define NET_SW_RETRY_MAX_MS     300000

/* How long ml_net_switch_stop() waits for the task to tear down and exit.
 * The task may be in a modem power-up or network registration that can't
 * be cut short, and then in tailtiny_stop()'s own wait. */
#define NET_SW_STOP_TIMEOUT_MS  300000

typedef struct {
    /* Config (copied) */
    char wifi_ssid[64];
    char wifi_password[64];
    char sim_pin[16];
    char apn[64];
    char ppp_user[32];
    char ppp_pass[32];
    char tailscale_auth_key[128];
    char device_name[64];

    uint32_t wifi_timeout_ms;
    uint32_t health_check_interval_ms;
    uint32_t health_fail_count;
    uint32_t failback_check_ms;

    /* Callbacks */
    void (*on_connected)(ml_net_type_t type, void *user_data);
    void (*on_disconnected)(void *user_data);
    void (*on_switching)(ml_net_type_t from, ml_net_type_t to, void *user_data);
    void *user_data;

    /* State */
    ml_net_switch_state_t state;
    ml_net_type_t active_transport;
    tailtiny_t *ml;             /* written only by the switch task, under s_ml_lock */
    bool initialized;
    volatile bool running;      /* cleared by ml_net_switch_stop(); the task polls it */

    /* WiFi */
    EventGroupHandle_t wifi_events;
    int wifi_retry_count;

    /* Health monitoring */
    TimerHandle_t health_timer;
    uint32_t health_fail_counter;

    /* Failback */
    TimerHandle_t failback_timer;

    /* WiFi disconnect debounce */
    TimerHandle_t wifi_debounce_timer;
    bool wifi_disconnect_pending;

    /* Task */
    TaskHandle_t task_handle;
} ml_net_switch_ctx_t;

static ml_net_switch_ctx_t s_ctx = {0};

/* The default WiFi STA netif and the WiFi/IP event handlers are process-wide
 * and outlive a deinit. In s_ctx, deinit's memset forgot them, and an init
 * after it created a second STA netif and registered the handlers again. */
static esp_netif_t *s_wifi_netif;

/* Guards s_ctx.ml: the health timer and ml_net_switch_get_handle() read it
 * while the switch task may be replacing it. Static: no allocation, and it
 * survives deinit/init. */
static SemaphoreHandle_t s_ml_lock;
static StaticSemaphore_t s_ml_lock_buf;

/* NS_TASK_EXITED is set while no switch task exists: the task sets it as
 * the last thing it does, start clears it before creating one, and stop waits
 * for it without clearing it. Sticky, unlike a semaphore given once: a give
 * left over from a stop that timed out could end a later stop before the new
 * task had exited, and of two concurrent stops only one got it. */
#define NS_TASK_EXITED BIT0
static EventGroupHandle_t s_task_events;
static StaticEventGroup_t s_task_events_buf;

/* Notifies of the task in flight (timer callbacks, stop), under s_task_lock.
 * The task clears its handle and waits for them before deleting itself, so
 * a notify that read the handle just before can't reach a deleted task.
 * Same scheme as ml_wg_notify(). */
static portMUX_TYPE s_task_lock = portMUX_INITIALIZER_UNLOCKED;
static int s_notifiers;

static void sw_notify_task(void)
{
    taskENTER_CRITICAL(&s_task_lock);
    TaskHandle_t task = s_ctx.task_handle;
    if (task) s_notifiers++;
    taskEXIT_CRITICAL(&s_task_lock);
    if (!task) return;
    xTaskNotifyGive(task);
    taskENTER_CRITICAL(&s_task_lock);
    s_notifiers--;
    taskEXIT_CRITICAL(&s_task_lock);
}

/* Sleep that ends early once ml_net_switch_stop() was called. Returns
 * whether the switch is still running. Leaves task notifications alone. */
static bool sw_sleep(uint32_t ms)
{
    while (ms > 0 && s_ctx.running) {
        uint32_t slice = ms > 250 ? 250 : ms;
        vTaskDelay(pdMS_TO_TICKS(slice));
        ms -= slice;
    }
    return s_ctx.running;
}

/* ============================================================================
 * WiFi Management
 * ========================================================================== */

/* Called 5s after WiFi disconnect if it hasn't reconnected */
static void wifi_debounce_cb(TimerHandle_t timer)
{
    if (!s_ctx.wifi_disconnect_pending) return;
    s_ctx.wifi_disconnect_pending = false;

    /* Only trigger switch if we're on WiFi with VPN up */
    if (s_ctx.active_transport != ML_NET_WIFI) return;
    if (s_ctx.state != ML_NET_SW_WIFI_VPN_UP) return;

    ESP_LOGW(TAG, "WiFi down for %dms — triggering switch to cellular",
             WIFI_DISCONNECT_DEBOUNCE_MS);
    s_ctx.state = ML_NET_SW_SWITCHING_TO_CELL;
    sw_notify_task();
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT) {
        if (event_id == WIFI_EVENT_STA_START) {
            esp_wifi_connect();
        } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
            if (s_ctx.wifi_retry_count < 5) {
                s_ctx.wifi_retry_count++;
                ESP_LOGI(TAG, "WiFi disconnected, retry %d/5", s_ctx.wifi_retry_count);
                esp_wifi_connect();

                /* Start debounce timer on first disconnect while VPN is up */
                if (s_ctx.wifi_retry_count == 1 &&
                    s_ctx.state == ML_NET_SW_WIFI_VPN_UP &&
                    s_ctx.wifi_debounce_timer) {
                    s_ctx.wifi_disconnect_pending = true;
                    xTimerReset(s_ctx.wifi_debounce_timer, 0);
                }
            } else {
                xEventGroupSetBits(s_ctx.wifi_events, WIFI_FAIL_BIT);
            }
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "WiFi connected, IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_ctx.wifi_retry_count = 0;

        /* Cancel debounce — WiFi recovered */
        if (s_ctx.wifi_disconnect_pending) {
            s_ctx.wifi_disconnect_pending = false;
            if (s_ctx.wifi_debounce_timer) {
                xTimerStop(s_ctx.wifi_debounce_timer, 0);
            }
            ESP_LOGI(TAG, "WiFi recovered within debounce window");
        }

        xEventGroupSetBits(s_ctx.wifi_events, WIFI_CONNECTED_BIT);
    }
}

static esp_err_t wifi_start(void)
{
    ESP_LOGI(TAG, "Starting WiFi (%s)...", s_ctx.wifi_ssid);

    s_ctx.wifi_retry_count = 0;
    xEventGroupClearBits(s_ctx.wifi_events, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);

    if (!s_wifi_netif) {
        s_wifi_netif = esp_netif_create_default_wifi_sta();
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        ESP_ERROR_CHECK(esp_wifi_init(&cfg));
        ESP_ERROR_CHECK(esp_event_handler_instance_register(
            WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL, NULL));
        ESP_ERROR_CHECK(esp_event_handler_instance_register(
            IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL, NULL));
    }

    wifi_config_t wifi_config = {0};
    strncpy((char *)wifi_config.sta.ssid, s_ctx.wifi_ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, s_ctx.wifi_password, sizeof(wifi_config.sta.password) - 1);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    /* Wait for connection, in slices so that a stop is noticed */
    EventBits_t bits = 0;
    for (uint32_t waited = 0; waited < s_ctx.wifi_timeout_ms && s_ctx.running; waited += 250) {
        bits = xEventGroupWaitBits(s_ctx.wifi_events,
                                   WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                   pdFALSE, pdFALSE, pdMS_TO_TICKS(250));
        if (bits & (WIFI_CONNECTED_BIT | WIFI_FAIL_BIT)) break;
    }

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "WiFi connected");
        return ESP_OK;
    }
    if (!s_ctx.running) return ESP_ERR_INVALID_STATE;  /* stop requested */

    ESP_LOGW(TAG, "WiFi connection failed (timeout=%lums)", (unsigned long)s_ctx.wifi_timeout_ms);
    return ESP_ERR_TIMEOUT;
}

static void wifi_stop(void)
{
    ESP_LOGI(TAG, "Stopping WiFi...");
    esp_wifi_disconnect();
    esp_wifi_stop();
}

/* ============================================================================
 * Cellular Management
 * ========================================================================== */

static esp_err_t cellular_start(void)
{
    ESP_LOGI(TAG, "Starting cellular modem...");

    ml_cellular_config_t cell_config = {
        .tx_pin = CONFIG_ML_CELLULAR_TX_PIN,
        .rx_pin = CONFIG_ML_CELLULAR_RX_PIN,
        .baud_rate = 115200,
        .apn = s_ctx.apn[0] ? s_ctx.apn : NULL,
        .sim_pin = s_ctx.sim_pin[0] ? s_ctx.sim_pin : NULL,
    };

    /* Apply APN: NVS (web UI) > config struct > Kconfig */
    static char nvs_apn[32] = "";
    if (ml_config_get_nvs_apn(nvs_apn, sizeof(nvs_apn))) {
        cell_config.apn = nvs_apn;
    }

    /* Apply PPP credentials: NVS (web UI) > Kconfig */
    char nvs_ppp_user[32] = "", nvs_ppp_pass[32] = "";
    if (ml_config_get_nvs_ppp(nvs_ppp_user, sizeof(nvs_ppp_user),
                               nvs_ppp_pass, sizeof(nvs_ppp_pass))) {
        cell_config.ppp_user = nvs_ppp_user;
        cell_config.ppp_pass = nvs_ppp_pass;
    } else {
        const char *ppp_u = CONFIG_ML_CELLULAR_PPP_USER;
        if (ppp_u && ppp_u[0]) cell_config.ppp_user = ppp_u;
        const char *ppp_p = CONFIG_ML_CELLULAR_PPP_PASS;
        if (ppp_p && ppp_p[0]) cell_config.ppp_pass = ppp_p;
    }

    esp_err_t err = ml_cellular_init(&cell_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Cellular init failed: %s", esp_err_to_name(err));
        return err;
    }

    err = ml_cellular_connect();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Cellular data connection failed: %s", esp_err_to_name(err));
        ml_cellular_deinit();
        return err;
    }

    ml_cellular_data_mode_t mode = ml_cellular_get_data_mode();
    ESP_LOGI(TAG, "Cellular connected via %s",
             mode == ML_DATA_MODE_PPP ? "PPP" : "AT socket bridge");
    return ESP_OK;
}

static void cellular_stop(void)
{
    ESP_LOGI(TAG, "Stopping cellular...");
    ml_cellular_data_stop();
    ml_cellular_deinit();
}

/* ============================================================================
 * TailTiny VPN Management
 * ========================================================================== */

/* Unpublish the handle, then stop and destroy it. Only the switch task calls
 * this, so a handle can't be stopped and destroyed twice. */
static void vpn_stop(void)
{
    xSemaphoreTake(s_ml_lock, portMAX_DELAY);
    tailtiny_t *ml = s_ctx.ml;
    s_ctx.ml = NULL;
    xSemaphoreGive(s_ml_lock);

    if (ml) {
        tailtiny_stop(ml);
        tailtiny_destroy(ml);
    }
}

static esp_err_t vpn_start(void)
{
    const char *name = s_ctx.device_name[0] ? s_ctx.device_name : NULL;

    /* For cellular, prefer IMEI-based name */
    if (s_ctx.active_transport == ML_NET_CELLULAR && !name) {
        name = tailtiny_imei_device_name();
    }
    if (!name) {
        name = tailtiny_default_device_name();
    }

    tailtiny_config_t ml_config = {
        .auth_key = s_ctx.tailscale_auth_key,
        .device_name = name,
        .enable_derp = true,
        .enable_stun = (s_ctx.active_transport == ML_NET_WIFI),
        .enable_disco = true,
        .max_peers = CONFIG_ML_MAX_PEERS,
    };

    tailtiny_t *ml = tailtiny_init(&ml_config);
    if (!ml) {
        ESP_LOGE(TAG, "tailtiny_init failed");
        return ESP_FAIL;
    }
    xSemaphoreTake(s_ml_lock, portMAX_DELAY);
    s_ctx.ml = ml;
    xSemaphoreGive(s_ml_lock);

    esp_err_t err = tailtiny_start(ml);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tailtiny_start failed: %s", esp_err_to_name(err));
        vpn_stop();
        return err;
    }

    /* Wait for connection — large tailnets (200+ peers) over cellular can take
     * 3-4 minutes to download the full MapResponse via AT socket bridge.
     * Use 180s for cellular, 60s for WiFi. */
    int timeout_ticks = (s_ctx.active_transport == ML_NET_WIFI) ? 120 : 360;
    int timeout_secs = timeout_ticks / 2;
    for (int i = 0; i < timeout_ticks; i++) {
        if (!s_ctx.running) {
            ESP_LOGI(TAG, "Stop requested while waiting for the VPN");
            vpn_stop();
            return ESP_ERR_INVALID_STATE;
        }
        if (tailtiny_is_connected(ml)) {
            uint32_t ip = tailtiny_get_vpn_ip(ml);
            char ip_str[16];
            tailtiny_ip_to_str(ip, ip_str);
            ESP_LOGI(TAG, "VPN connected via %s (IP: %s)",
                     s_ctx.active_transport == ML_NET_WIFI ? "WiFi" : "Cellular",
                     ip_str);
            return ESP_OK;
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    ESP_LOGW(TAG, "VPN connection timeout (%ds)", timeout_secs);
    vpn_stop();
    return ESP_ERR_TIMEOUT;
}

/* ============================================================================
 * Health Check Timer
 * ========================================================================== */

static void health_timer_cb(TimerHandle_t timer)
{
    if (!s_ctx.running) return;

    /* On the timer task: never block. If the switch task holds the lock it
     * is replacing the handle; skip this round. Read without the lock, the
     * handle could be destroyed in between. */
    if (!s_ml_lock || xSemaphoreTake(s_ml_lock, 0) != pdTRUE) return;
    bool have_ml = s_ctx.ml != NULL;
    bool connected = have_ml && tailtiny_is_connected(s_ctx.ml);
    xSemaphoreGive(s_ml_lock);
    if (!have_ml) return;

    if (!connected) {
        s_ctx.health_fail_counter++;
        ESP_LOGW(TAG, "Health check failed (%lu/%lu)",
                 (unsigned long)s_ctx.health_fail_counter,
                 (unsigned long)s_ctx.health_fail_count);

        if (s_ctx.health_fail_counter >= s_ctx.health_fail_count) {
            ESP_LOGE(TAG, "Health check threshold reached — triggering network switch");
            s_ctx.health_fail_counter = 0;

            if (s_ctx.active_transport == ML_NET_WIFI) {
                s_ctx.state = ML_NET_SW_SWITCHING_TO_CELL;
            } else {
                s_ctx.state = ML_NET_SW_SWITCHING_TO_WIFI;
            }

            /* Wake the task */
            sw_notify_task();
        }
    } else {
        s_ctx.health_fail_counter = 0;
    }
}

/* ============================================================================
 * Failback Timer (check if WiFi recovered while on cellular)
 * ========================================================================== */

static void failback_timer_cb(TimerHandle_t timer)
{
    if (!s_ctx.running) return;
    if (s_ctx.active_transport != ML_NET_CELLULAR) return;

    /* Don't attempt failback if no WiFi credentials configured */
    if (s_ctx.wifi_ssid[0] == '\0') return;

    ESP_LOGI(TAG, "Failback check: attempting WiFi reconnection...");
    s_ctx.state = ML_NET_SW_SWITCHING_TO_WIFI;

    sw_notify_task();
}

/* ============================================================================
 * Main State Machine Task
 * ========================================================================== */

/* Bring the VPN up over WiFi. On failure WiFi is stopped again. */
static bool try_wifi(void)
{
    s_ctx.state = ML_NET_SW_WIFI_CONNECTING;
    s_ctx.active_transport = ML_NET_WIFI;

    if (wifi_start() == ESP_OK && s_ctx.running && vpn_start() == ESP_OK) {
        s_ctx.state = ML_NET_SW_WIFI_VPN_UP;
        if (s_ctx.on_connected) {
            s_ctx.on_connected(ML_NET_WIFI, s_ctx.user_data);
        }
        /* Start health check timer */
        xTimerStart(s_ctx.health_timer, 0);
        return true;
    }

    /* WiFi failed — try cellular */
    if (s_ctx.running) {
        ESP_LOGW(TAG, "WiFi path failed, falling back to cellular");
    }
    wifi_stop();
    return false;
}

/* Bring the VPN up over cellular. On failure the modem may still be up: the
 * caller stops it before the next attempt. */
static bool try_cellular(void)
{
    /* The failback timer would turn the state into SWITCHING_TO_WIFI while
     * this attempt runs */
    xTimerStop(s_ctx.health_timer, 0);
    if (s_ctx.failback_timer) xTimerStop(s_ctx.failback_timer, 0);

    s_ctx.state = ML_NET_SW_CELL_CONNECTING;
    s_ctx.active_transport = ML_NET_CELLULAR;

    if (s_ctx.on_switching) {
        s_ctx.on_switching(ML_NET_WIFI, ML_NET_CELLULAR, s_ctx.user_data);
    }

    if (cellular_start() == ESP_OK && s_ctx.running && vpn_start() == ESP_OK) {
        s_ctx.state = ML_NET_SW_CELL_VPN_UP;
        if (s_ctx.on_connected) {
            s_ctx.on_connected(ML_NET_CELLULAR, s_ctx.user_data);
        }
        /* Start health check + failback timers */
        xTimerStart(s_ctx.health_timer, 0);
        if (s_ctx.failback_check_ms > 0 && s_ctx.failback_timer) {
            xTimerStart(s_ctx.failback_timer, 0);
        }
        return true;
    }
    return false;
}

typedef enum {
    SW_LOOP_STOPPED,        /* ml_net_switch_stop() was called */
    SW_LOOP_RETRY_CELL,     /* the VPN couldn't be moved: start again on cellular */
} sw_loop_result_t;

/* Runs while the VPN is up: reacts to the health, failback and debounce
 * timers. */
static sw_loop_result_t state_loop(void)
{
    while (s_ctx.running) {
        /* Wait for notification from health/failback timer */
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(5000));

        if (!s_ctx.running) break;

        switch (s_ctx.state) {
            case ML_NET_SW_SWITCHING_TO_CELL: {
                ESP_LOGI(TAG, "Switching WiFi → Cellular");
                xTimerStop(s_ctx.health_timer, 0);

                if (s_ctx.on_switching) {
                    s_ctx.on_switching(ML_NET_WIFI, ML_NET_CELLULAR, s_ctx.user_data);
                }

                /* Start cellular while WiFi VPN is still running */
                s_ctx.state = ML_NET_SW_CELL_CONNECTING;
                esp_err_t cell_err = cellular_start();
                if (!s_ctx.running) break;  /* stop: the task's teardown takes it from here */
                if (cell_err == ESP_OK) {
                    /* Cellular is up — rebind sockets instead of full restart */
                    wifi_stop();
                    s_ctx.active_transport = ML_NET_CELLULAR;
                    esp_err_t rb_err = tailtiny_rebind(s_ctx.ml);
                    if (rb_err == ESP_OK) {
                        ESP_LOGI(TAG, "Rebind to cellular complete");
                        s_ctx.state = ML_NET_SW_CELL_VPN_UP;
                        if (s_ctx.on_connected) {
                            s_ctx.on_connected(ML_NET_CELLULAR, s_ctx.user_data);
                        }
                        xTimerStart(s_ctx.health_timer, 0);
                        if (s_ctx.failback_check_ms > 0 && s_ctx.failback_timer) {
                            xTimerStart(s_ctx.failback_timer, 0);
                        }
                    } else {
                        ESP_LOGE(TAG, "Rebind failed (%s), full restart",
                                 esp_err_to_name(rb_err));
                        vpn_stop();
                        wifi_stop();
                        /* The modem is up: the retry initialises it again
                         * (it failed on "Already initialized" before) */
                        cellular_stop();
                        return SW_LOOP_RETRY_CELL;
                    }
                } else {
                    /* Cellular failed — full restart path */
                    ESP_LOGE(TAG, "Cellular start failed, full restart");
                    if (s_ctx.on_disconnected) {
                        s_ctx.on_disconnected(s_ctx.user_data);
                    }
                    vpn_stop();
                    wifi_stop();
                    return SW_LOOP_RETRY_CELL;
                }
                break;
            }

            case ML_NET_SW_SWITCHING_TO_WIFI: {
                ESP_LOGI(TAG, "Attempting failback: Cellular → WiFi");
                xTimerStop(s_ctx.health_timer, 0);
                if (s_ctx.failback_timer) {
                    xTimerStop(s_ctx.failback_timer, 0);
                }

                /* Try WiFi without tearing down cellular yet */
                s_ctx.state = ML_NET_SW_WIFI_CONNECTING;

                esp_err_t wifi_err = wifi_start();
                if (!s_ctx.running) break;  /* stop: the task's teardown takes it from here */
                if (wifi_err == ESP_OK) {
                    /* WiFi is back — rebind sockets to WiFi interface */
                    ESP_LOGI(TAG, "WiFi recovered! Rebinding to WiFi");

                    if (s_ctx.on_switching) {
                        s_ctx.on_switching(ML_NET_CELLULAR, ML_NET_WIFI, s_ctx.user_data);
                    }

                    /* Tear down cellular transport first so ml_at_socket_is_ready()
                     * returns false and ml_* wrappers route to BSD sockets */
                    cellular_stop();
                    s_ctx.active_transport = ML_NET_WIFI;

                    esp_err_t rb_err = tailtiny_rebind(s_ctx.ml);
                    if (rb_err == ESP_OK) {
                        ESP_LOGI(TAG, "Rebind to WiFi complete");
                        s_ctx.state = ML_NET_SW_WIFI_VPN_UP;
                        if (s_ctx.on_connected) {
                            s_ctx.on_connected(ML_NET_WIFI, s_ctx.user_data);
                        }
                        xTimerStart(s_ctx.health_timer, 0);
                    } else {
                        /* Rebind failed — try full restart on cellular */
                        ESP_LOGW(TAG, "Rebind to WiFi failed (%s), reverting to cellular",
                                 esp_err_to_name(rb_err));
                        wifi_stop();
                        vpn_stop();
                        return SW_LOOP_RETRY_CELL;
                    }
                } else {
                    /* WiFi still down, stay on cellular */
                    ESP_LOGI(TAG, "WiFi still unavailable, staying on cellular");
                    wifi_stop();
                    s_ctx.state = ML_NET_SW_CELL_VPN_UP;
                    xTimerStart(s_ctx.health_timer, 0);
                    if (s_ctx.failback_check_ms > 0 && s_ctx.failback_timer) {
                        xTimerStart(s_ctx.failback_timer, 0);
                    }
                }
                break;
            }

            default:
                break;
        }
    }
    return SW_LOOP_STOPPED;
}

static void net_switch_task(void *arg)
{
    ESP_LOGI(TAG, "Network switch task started");

    /* Step 1: Try WiFi (skip if no SSID configured) */
    bool has_wifi = (s_ctx.wifi_ssid[0] != '\0');
    bool cellular_only_next = false;
    uint32_t retry_ms = NET_SW_RETRY_MIN_MS;

    /* Every failure comes back here. After WiFi and cellular had both failed
     * once, the task slept 30 s and went into the state loop with no VPN and
     * no timer running, in a state the loop doesn't handle: offline until a
     * reboot. Now it starts over, WiFi then cellular, with a backoff. */
    while (s_ctx.running) {
        bool up = false;

        if (!has_wifi) {
            ESP_LOGI(TAG, "No WiFi SSID configured, going straight to cellular");
        } else if (!cellular_only_next) {
            up = try_wifi();
        }
        cellular_only_next = false;

        if (!up && s_ctx.running) {
            up = try_cellular();
        }

        if (up) {
            retry_ms = NET_SW_RETRY_MIN_MS;
            if (state_loop() == SW_LOOP_RETRY_CELL) {
                cellular_only_next = true;
            }
            continue;
        }

        if (!s_ctx.running) break;

        /* Both failed */
        ESP_LOGE(TAG, "Both WiFi and cellular failed! Retrying in %lus",
                 (unsigned long)(retry_ms / 1000));
        s_ctx.state = ML_NET_SW_ERROR;
        if (s_ctx.on_disconnected) {
            s_ctx.on_disconnected(s_ctx.user_data);
        }

        sw_sleep(retry_ms);
        retry_ms = (retry_ms * 2 > NET_SW_RETRY_MAX_MS) ? NET_SW_RETRY_MAX_MS : retry_ms * 2;
        cellular_stop();
    }

    /* Teardown, here: this task owns the handle and the transports.
     * TailTiny first, so its tasks have exited before their transport goes. */
    ESP_LOGI(TAG, "Network switch task stopping");
    xTimerStop(s_ctx.health_timer, 0);
    if (s_ctx.failback_timer) xTimerStop(s_ctx.failback_timer, 0);
    vpn_stop();
    if (has_wifi) wifi_stop();
    cellular_stop();
    s_ctx.state = ML_NET_SW_IDLE;

    ESP_LOGI(TAG, "Network switch task exiting");
    taskENTER_CRITICAL(&s_task_lock);
    s_ctx.task_handle = NULL;
    taskEXIT_CRITICAL(&s_task_lock);
    for (;;) {
        taskENTER_CRITICAL(&s_task_lock);
        int busy = s_notifiers;
        taskEXIT_CRITICAL(&s_task_lock);
        if (!busy) break;
        vTaskDelay(1);
    }
    xEventGroupSetBits(s_task_events, NS_TASK_EXITED);
    vTaskDelete(NULL);
}

/* ============================================================================
 * Public API
 * ========================================================================== */

esp_err_t ml_net_switch_init(const ml_net_switch_config_t *config)
{
    if (s_ctx.initialized) return ESP_ERR_INVALID_STATE;
    if (!config || !config->tailscale_auth_key) return ESP_ERR_INVALID_ARG;

    memset(&s_ctx, 0, sizeof(s_ctx));

    if (!s_ml_lock) s_ml_lock = xSemaphoreCreateMutexStatic(&s_ml_lock_buf);
    if (!s_task_events) {
        s_task_events = xEventGroupCreateStatic(&s_task_events_buf);
        xEventGroupSetBits(s_task_events, NS_TASK_EXITED);   /* no task yet */
    }

    /* Copy strings */
    if (config->wifi_ssid) strncpy(s_ctx.wifi_ssid, config->wifi_ssid, sizeof(s_ctx.wifi_ssid) - 1);
    if (config->wifi_password) strncpy(s_ctx.wifi_password, config->wifi_password, sizeof(s_ctx.wifi_password) - 1);
    if (config->sim_pin) strncpy(s_ctx.sim_pin, config->sim_pin, sizeof(s_ctx.sim_pin) - 1);
    if (config->apn) strncpy(s_ctx.apn, config->apn, sizeof(s_ctx.apn) - 1);
    strncpy(s_ctx.tailscale_auth_key, config->tailscale_auth_key, sizeof(s_ctx.tailscale_auth_key) - 1);
    if (config->device_name) strncpy(s_ctx.device_name, config->device_name, sizeof(s_ctx.device_name) - 1);

    /* Timing defaults (Kconfig "Network Switching" for the _ms fields) */
    s_ctx.wifi_timeout_ms = config->wifi_timeout_ms ? config->wifi_timeout_ms
                                                    : NET_SW_DEFAULT_WIFI_TIMEOUT_MS;
    s_ctx.health_check_interval_ms = config->health_check_interval_ms ? config->health_check_interval_ms
                                                                      : NET_SW_DEFAULT_HEALTH_INTERVAL_MS;
    s_ctx.health_fail_count = config->health_fail_count ? config->health_fail_count : 3;
    s_ctx.failback_check_ms = config->failback_check_ms ? config->failback_check_ms
                                                        : NET_SW_DEFAULT_FAILBACK_MS;

    /* Callbacks */
    s_ctx.on_connected = config->on_connected;
    s_ctx.on_disconnected = config->on_disconnected;
    s_ctx.on_switching = config->on_switching;
    s_ctx.user_data = config->user_data;

    /* Create event group for WiFi */
    s_ctx.wifi_events = xEventGroupCreate();
    if (!s_ctx.wifi_events) return ESP_ERR_NO_MEM;

    /* Create health check timer */
    s_ctx.health_timer = xTimerCreate("net_health",
                                       pdMS_TO_TICKS(s_ctx.health_check_interval_ms),
                                       pdTRUE, NULL, health_timer_cb);
    if (!s_ctx.health_timer) return ESP_ERR_NO_MEM;

    /* Create failback timer */
    if (s_ctx.failback_check_ms > 0) {
        s_ctx.failback_timer = xTimerCreate("net_failback",
                                             pdMS_TO_TICKS(s_ctx.failback_check_ms),
                                             pdTRUE, NULL, failback_timer_cb);
    }

    /* Create WiFi disconnect debounce timer (one-shot) */
    s_ctx.wifi_debounce_timer = xTimerCreate("wifi_debounce",
                                              pdMS_TO_TICKS(WIFI_DISCONNECT_DEBOUNCE_MS),
                                              pdFALSE, NULL, wifi_debounce_cb);

    s_ctx.state = ML_NET_SW_IDLE;
    s_ctx.initialized = true;

    ESP_LOGI(TAG, "Net switch initialized (wifi_timeout=%lums, health=%lums, failback=%lums)",
             (unsigned long)s_ctx.wifi_timeout_ms,
             (unsigned long)s_ctx.health_check_interval_ms,
             (unsigned long)s_ctx.failback_check_ms);

    return ESP_OK;
}

void ml_net_switch_deinit(void)
{
    if (!s_ctx.initialized) return;

    if (ml_net_switch_stop() != ESP_OK) {
        /* The task still runs and uses the timers, the event group and
         * s_ctx: freeing them now would pull them out from under it. */
        ESP_LOGE(TAG, "Deinit skipped: the network switch task hasn't exited");
        return;
    }

    if (s_ctx.health_timer) {
        xTimerDelete(s_ctx.health_timer, portMAX_DELAY);
    }
    if (s_ctx.failback_timer) {
        xTimerDelete(s_ctx.failback_timer, portMAX_DELAY);
    }
    if (s_ctx.wifi_debounce_timer) {
        xTimerDelete(s_ctx.wifi_debounce_timer, portMAX_DELAY);
    }
    if (s_ctx.wifi_events) {
        vEventGroupDelete(s_ctx.wifi_events);
    }

    memset(&s_ctx, 0, sizeof(s_ctx));
}

esp_err_t ml_net_switch_start(void)
{
    if (!s_ctx.initialized) return ESP_ERR_INVALID_STATE;
    if (s_ctx.running || s_ctx.task_handle) return ESP_ERR_INVALID_STATE;
    /* Also not while the last task is still on its way out (after a stop
     * that timed out): call ml_net_switch_stop() again first */
    if (!(xEventGroupGetBits(s_task_events) & NS_TASK_EXITED)) return ESP_ERR_INVALID_STATE;

    xEventGroupClearBits(s_task_events, NS_TASK_EXITED);
    s_ctx.running = true;

    BaseType_t ret = xTaskCreate(net_switch_task, "net_sw",
                                  NET_SW_STACK_SIZE, NULL, 5, &s_ctx.task_handle);
    if (ret != pdPASS) {
        s_ctx.running = false;
        s_ctx.task_handle = NULL;
        xEventGroupSetBits(s_task_events, NS_TASK_EXITED);
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

esp_err_t ml_net_switch_stop(void)
{
    if (!s_ctx.running && !s_ctx.task_handle &&
        (!s_task_events || (xEventGroupGetBits(s_task_events) & NS_TASK_EXITED))) {
        return ESP_OK;
    }

    if (s_ctx.task_handle && xTaskGetCurrentTaskHandle() == s_ctx.task_handle) {
        /* From an on_* callback: the task can't wait for itself */
        ESP_LOGE(TAG, "ml_net_switch_stop() called from the switch task (a callback?)");
        return ESP_ERR_INVALID_STATE;
    }

    s_ctx.running = false;

    /* Stop timers */
    if (s_ctx.health_timer) xTimerStop(s_ctx.health_timer, portMAX_DELAY);
    if (s_ctx.failback_timer) xTimerStop(s_ctx.failback_timer, portMAX_DELAY);
    if (s_ctx.wifi_debounce_timer) xTimerStop(s_ctx.wifi_debounce_timer, portMAX_DELAY);
    s_ctx.wifi_disconnect_pending = false;

    /* The task tears down TailTiny and the transports itself on its way out:
     * wake it and wait. This waited a fixed 500 ms and then ran vpn_stop()
     * here, while the task could still be in vpn_start() (which waits up to
     * 180 s), cellular_start() or wifi_start(): both then stopped and
     * destroyed the same handle, or the task used it after it was freed. */
    sw_notify_task();
    EventBits_t bits = xEventGroupWaitBits(s_task_events, NS_TASK_EXITED, pdFALSE, pdTRUE,
                                           pdMS_TO_TICKS(NET_SW_STOP_TIMEOUT_MS));
    if (!(bits & NS_TASK_EXITED)) {
        ESP_LOGE(TAG, "Network switch task didn't exit within %ds; call ml_net_switch_stop() again",
                 NET_SW_STOP_TIMEOUT_MS / 1000);
        return ESP_ERR_TIMEOUT;
    }

    s_ctx.state = ML_NET_SW_IDLE;
    return ESP_OK;
}

ml_net_type_t ml_net_switch_get_active(void)
{
    return s_ctx.active_transport;
}

ml_net_switch_state_t ml_net_switch_get_state(void)
{
    return s_ctx.state;
}

tailtiny_t *ml_net_switch_get_handle(void)
{
    if (!s_ml_lock) return NULL;
    xSemaphoreTake(s_ml_lock, portMAX_DELAY);
    tailtiny_t *ml = s_ctx.ml;
    xSemaphoreGive(s_ml_lock);
    return ml;
}

const char *ml_net_switch_state_str(ml_net_switch_state_t state)
{
    switch (state) {
        case ML_NET_SW_IDLE:              return "IDLE";
        case ML_NET_SW_WIFI_CONNECTING:   return "WIFI_CONNECTING";
        case ML_NET_SW_WIFI_VPN_UP:       return "WIFI_VPN_UP";
        case ML_NET_SW_SWITCHING_TO_CELL: return "SWITCHING_TO_CELL";
        case ML_NET_SW_CELL_CONNECTING:   return "CELL_CONNECTING";
        case ML_NET_SW_CELL_VPN_UP:       return "CELL_VPN_UP";
        case ML_NET_SW_SWITCHING_TO_WIFI: return "SWITCHING_TO_WIFI";
        case ML_NET_SW_ERROR:             return "ERROR";
        default:                          return "UNKNOWN";
    }
}

#endif /* CONFIG_ML_ENABLE_NET_SWITCH */
