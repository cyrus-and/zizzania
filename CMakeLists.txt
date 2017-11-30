cmake_minimum_required(VERSION 3.2 FATAL_ERROR)
project(zizzania LANGUAGES C)

include(ExternalProject)

# uthash
set(UTHASH_INCLUDES "${CMAKE_BINARY_DIR}/uthash-prefix/src/uthash/include/")
ExternalProject_Add(uthash
  URL https://github.com/troydhanson/uthash/archive/v2.0.2.tar.gz
  URL_HASH MD5=d08632a58674274c9cd87e2930f5696a
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND "")

# pcap
find_program(PCAP_CONFIG pcap-config)
if(PCAP_CONFIG)
  exec_program(${PCAP_CONFIG} ARGS --cflags OUTPUT_VARIABLE PCAP_CFLAGS)
  exec_program(${PCAP_CONFIG} ARGS --libs OUTPUT_VARIABLE PCAP_LIBS)
else()
  message(FATAL_ERROR "libpcap not found")
endif()

# add program source
add_subdirectory(src)

# un/install
install(PROGRAMS ${CMAKE_BINARY_DIR}/src/zizzania DESTINATION bin)
add_custom_target(uninstall xargs rm < install_manifest.txt)
