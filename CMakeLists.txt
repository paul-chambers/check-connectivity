cmake_minimum_required(VERSION 3.26)
project(multiwand C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS_DEBUG "-ggdb3 -DDEBUG")

# find_program( SETCAP_PROGRAM setTargetCaps REQUIRED )

include_directories( . )
include_directories( SYSTEM /usr/include/libnl3 )

add_executable( multiwand
                multiwand.c
                multiwand.h)

target_link_libraries( multiwand nl-3 nl-route-3 )
add_custom_command(
        TARGET multiwand
        POST_BUILD
        COMMAND setTargetCaps "$<TARGET_FILE:multiwand>"
        VERBATIM
)

add_executable(setTargetCaps setTargetCaps.c)

target_link_libraries( setTargetCaps cap )
