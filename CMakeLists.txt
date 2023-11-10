cmake_minimum_required(VERSION 3.26)
project(multiwand C)

set(CMAKE_C_STANDARD 11)

include_directories( . )
include_directories( SYSTEM /usr/include/libnl3 )

add_executable( multiwand
                multiwand.c
                multiwand.h)

target_link_libraries( multiwand nl-3 nl-route-3 )
