cmake_minimum_required(VERSION 3.26)
project(network_raw_socket C)

set(CMAKE_C_STANDARD 11)

add_executable(network_raw_socket main.c
        log/logQueue.h
)
