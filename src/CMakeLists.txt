# executable source files
add_executable(zizzania
  bsss.c
  clients.c
  dispatcher.c
  dissector.c
  handler.c
  handshake.c
  ieee802.c
  iface.c
  killer.c
  main.c
  members.c
  options.c
  terminal.c
  util.c)

# build types
set(CMAKE_C_FLAGS_RELEASE "-O3 -Os")
set(CMAKE_C_FLAGS_DEBUG "-g3 -DDEBUG")

# compilation flags
set(COMMON_FLAGS "-Wall")
set_target_properties(zizzania PROPERTIES
  COMPILE_FLAGS "${COMMON_FLAGS} ${PCAP_CFLAGS}")

# headers
target_include_directories(zizzania
  PRIVATE "${UTHASH_INCLUDES}")

# libraries
target_link_libraries(zizzania ${PCAP_LIBS} pthread)
