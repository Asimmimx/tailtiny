/* Runs wireguard_tai64n_now() from wireguard-platform-esp32.c on the host,
 * with ESP-IDF and FreeRTOS replaced by the stubs check_tai64n.py writes.
 * Built and run by check_tai64n.py. Each line of stdin sets the clocks and
 * takes one timestamp:  <wall seconds> <wall microseconds> <uptime microseconds>
 * and prints it as 24 hex digits (TAI64N: 8 bytes seconds, 4 bytes ns). */
#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>

static long long fake_wall_s, fake_wall_us, fake_uptime_us;

int64_t esp_timer_get_time(void) { return fake_uptime_us; }

int fake_gettimeofday(struct timeval *tv, void *tz) {
    (void)tz;
    tv->tv_sec = (time_t)fake_wall_s;
    tv->tv_usec = (long)fake_wall_us;  /* suseconds_t is missing on MinGW */
    return 0;
}

#include "wireguard-platform-esp32.c"

int main(void) {
    while (scanf("%lld %lld %lld", &fake_wall_s, &fake_wall_us, &fake_uptime_us) == 3) {
        if (fake_wall_s < 0) {
            /* "-1 <unix s> <uptime us>": the control server's time arrives */
            wireguard_set_time_hint(fake_wall_us);
            continue;
        }
        uint8_t out[12];
        wireguard_tai64n_now(out);
        for (int i = 0; i < 12; i++) printf("%02x", out[i]);
        printf("\n");
    }
    return 0;
}
