idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES tailtiny nvs_flash esp_wifi esp_netif esp_event
)
