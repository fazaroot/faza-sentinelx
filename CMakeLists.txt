cmake_minimum_required(VERSION 3.10)
project(sentinel_firewall CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(NFQUEUE REQUIRED libnetfilter_queue)

add_executable(sentinel-firewall src/main.cpp)

target_include_directories(sentinel-firewall PRIVATE ${NFQUEUE_INCLUDE_DIRS})
target_link_libraries(sentinel-firewall PRIVATE ${NFQUEUE_LIBRARIES} pthread)
target_compile_options(sentinel-firewall PRIVATE ${NFQUEUE_CFLAGS_OTHER} -Wall -O2)
