cmake_minimum_required(VERSION 3.9)

project(pam_drv)

set(STAGING_DIR /home/qqq/Documents/openwrt/staging_dir)
set(CMAKE_C_COMPILER   /home/qqq/Documents/openwrt/staging_dir/toolchain-mipsel_24kc_gcc-7.3.0_glibc/bin/mipsel-openwrt-linux-gcc)
set(CMAKE_CXX_COMPILER /home/qqq/Documents/openwrt/staging_dir/toolchain-mipsel_24kc_gcc-7.3.0_glibc/bin/mipsel-openwrt-linux-g++)

set(CMAKE_CXX_STANDARD 11)

file(GLOB SOURCES /home/qqq/Documents/mgw_pam/c_src/*.cpp)
file(GLOB HEADERS /home/qqq/Documents/mgw_pam/c_src/*.h)

include_directories(/usr/local/lib/erlang/usr/include/)
add_library(pam_drv SHARED main.cpp CLocalProto.cpp CBaseProto.cpp CRadProto.cpp CTacPlusProto.cpp)
target_link_libraries(pam_drv /home/qqq/Documents/slics_drv/c_src/libei.a /home/qqq/Documents/openwrt/staging_dir/target-mipsel_24kc_glibc/lib/libpam.a)