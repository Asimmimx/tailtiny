cmake_minimum_required(VERSION 3.16)

# Add tailtiny component path
set(EXTRA_COMPONENT_DIRS
    "../../components"
)

# Your WiFi and Tailscale settings: copy sdkconfig.credentials.example to
# sdkconfig.credentials and fill it in. It is applied on top of the defaults.
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.credentials")
    set(SDKCONFIG_DEFAULTS "sdkconfig.defaults;sdkconfig.credentials")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(tailtiny_basic_connect)
