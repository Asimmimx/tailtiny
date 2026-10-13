cmake_minimum_required(VERSION 3.16)

# Add tailtiny component path
set(EXTRA_COMPONENT_DIRS
    "../../components"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(tailtiny_cellular_heartbeat)
