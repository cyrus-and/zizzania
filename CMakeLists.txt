# CMake setup
cmake_minimum_required(VERSION 2.8)
find_package(PkgConfig)

# sources
file(GLOB SRC *.c)
add_executable(zizzania ${SRC})
add_definitions(-std=gnu99 -Wall -pedantic)

# build modes
set(CMAKE_C_FLAGS "-O3 -Os")
set(CMAKE_C_FLAGS_DEBUG "-g -DDEBUG")
set(CMAKE_C_FLAGS_VDEBUG "-g -DDEBUG -DVDEBUG")

# glib
pkg_check_modules(GLIB2 REQUIRED glib-2.0)
if(GLIB2_FOUND)
  add_definitions(${GLIB2_CFLAGS})
  target_link_libraries(zizzania ${GLIB2_LIBRARIES})
else()
  message(FATAL_ERROR "glib not found")
endif()

# pcap
find_program(PCAP_CONFIG pcap-config)
if(PCAP_CONFIG)
  exec_program(${PCAP_CONFIG} ARGS --cflags OUTPUT_VARIABLE PCAP_CFLAGS)
  exec_program(${PCAP_CONFIG} ARGS --libs OUTPUT_VARIABLE PCAP_LIBRARIES)
  add_definitions(${PCAP_CFLAGS})
  target_link_libraries(zizzania ${PCAP_LIBRARIES})
else()
  message(FATAL_ERROR "libpcap not found")
endif()

# [un]install
install(PROGRAMS ${PROJECT_BINARY_DIR}/zizzania DESTINATION bin)
add_custom_target(uninstall xargs rm < install_manifest.txt)
