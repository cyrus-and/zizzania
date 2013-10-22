# CMake setup
cmake_minimum_required(VERSION 2.8)
find_package(PkgConfig)

# common
add_definitions(-std=gnu99 -Wall -pedantic)
include_directories(lib/)

# executable
add_executable(zizzania-bin bin/zizzania.c)
set_target_properties(zizzania-bin PROPERTIES OUTPUT_NAME zizzania)

# library
file(GLOB LIBRARY_SRC lib/*.c)
add_library(zizzania STATIC ${LIBRARY_SRC})
target_link_libraries(zizzania-bin zizzania)

# build modes
set(CMAKE_C_FLAGS "-O3 -Os")
set(CMAKE_C_FLAGS_DEBUG "-g -DDEBUG")

# glib
pkg_check_modules(GLIB2 REQUIRED glib-2.0)
if(GLIB2_FOUND)
  add_definitions(${GLIB2_CFLAGS})
  target_link_libraries(zizzania-bin ${GLIB2_LIBRARIES})
else()
  message(FATAL_ERROR "glib not found")
endif()

# pcap
find_program(PCAP_CONFIG pcap-config)
if(PCAP_CONFIG)
  exec_program(${PCAP_CONFIG} ARGS --cflags OUTPUT_VARIABLE PCAP_CFLAGS)
  exec_program(${PCAP_CONFIG} ARGS --libs OUTPUT_VARIABLE PCAP_LIBRARIES)
  add_definitions(${PCAP_CFLAGS})
  target_link_libraries(zizzania-bin ${PCAP_LIBRARIES})
else()
  message(FATAL_ERROR "libpcap not found")
endif()

# pthread
find_package(Threads)
target_link_libraries(zizzania-bin ${CMAKE_THREAD_LIBS_INIT})

# [un]install
install(PROGRAMS ${PROJECT_BINARY_DIR}/zizzania DESTINATION bin)
add_custom_target(uninstall xargs rm < install_manifest.txt)
