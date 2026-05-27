cmake_minimum_required(VERSION 3.10)
project(vulnerable_server)

set(CMAKE_CXX_STANDARD 11)

add_executable(vulnerable_server server.cpp)

target_compile_options(vulnerable_server PRIVATE -Wall -Wextra)

install(TARGETS vulnerable_server DESTINATION bin)
