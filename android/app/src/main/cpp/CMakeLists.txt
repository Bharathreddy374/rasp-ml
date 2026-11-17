cmake_minimum_required(VERSION 3.22.1)
project(trustprobe C)

add_library(trustprobe SHARED trustprobe.c)

# No FORTIFY wrappers: taking &open must give the GOT entry, not an inline fortify shim.
target_compile_options(trustprobe PRIVATE -O2 -fvisibility=hidden -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -Wall)
target_link_libraries(trustprobe dl log)
