cmake_minimum_required(VERSION 3.13)
project(SHA1 VERSION 1.0.0)

add_library(SHA1 ${CMAKE_CURRENT_SOURCE_DIR}/src/sha1.c)
target_include_directories(SHA1 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(SHA1_EXE main.c)

target_link_libraries(SHA1_EXE SHA1)

