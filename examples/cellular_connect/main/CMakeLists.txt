idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES tailtiny nvs_flash esp_netif esp_event driver
)
