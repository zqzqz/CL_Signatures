cmake_minimum_required(VERSION 3.19)
project(cl_signatures C)

set(CMAKE_C_STANDARD 99)

include_directories(${CORE_LIB_PATH})

add_library(schemeC schemeC.c)
target_link_libraries(schemeC utils)