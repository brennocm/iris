cmake_minimum_required(VERSION 3.22.1)
project(iris C)

add_library(iris SHARED iris.c)

target_compile_options(iris PRIVATE
    -Wall -Wextra -Werror
    -fstack-protector-strong
    -fvisibility=hidden)

# 16 KB page alignment is required for apps targeting Android 15+ on 16 KB devices;
# NDK r27 does not do it by default.
target_link_options(iris PRIVATE
    -Wl,-z,relro -Wl,-z,now
    -Wl,-z,max-page-size=16384)
