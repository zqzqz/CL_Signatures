cmake_minimum_required(VERSION 3.19)
project(cl_signatures C)

set(CMAKE_C_STANDARD 99)
set(CORE_LIB_PATH ${CMAKE_CURRENT_SOURCE_DIR}/core/c)

include_directories(${CORE_LIB_PATH})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(signatures/schemeA)
add_subdirectory(signatures/schemeB)
add_subdirectory(signatures/schemeC)
add_subdirectory(signatures/schemeD)

add_subdirectory(commitment_schemes/PoK_message)
add_subdirectory(commitment_schemes/PoK_signature)

add_subdirectory(sign_commitment)

add_subdirectory(utils)


add_executable(test_cl_signatures test_cl_signatures.c)
target_link_libraries(test_cl_signatures
        utils
        schemeA
        schemeB
        schemeC
        schemeD
        ${CORE_LIB_PATH}/core.a)

add_executable(test_zkPoK test_anonymous_credentials.c)
target_link_libraries(test_zkPoK
        PoK_message
        PoK_signature
        sign_commitment
        schemeD
        utils
        ${CORE_LIB_PATH}/core.a)

add_executable(test_VRF test_VRF.c)
target_link_libraries(test_VRF
        PoK_message
        PoK_signature
        sign_commitment
        schemeD
        utils
        ${CORE_LIB_PATH}/core.a)

# Create a merged library
add_library(CLSigLib STATIC
        $<TARGET_OBJECTS:PoK_message>
        $<TARGET_OBJECTS:PoK_signature>
        $<TARGET_OBJECTS:sign_commitment>
        $<TARGET_OBJECTS:utils>
        $<TARGET_OBJECTS:schemeA>
        $<TARGET_OBJECTS:schemeB>
        $<TARGET_OBJECTS:schemeC>
        $<TARGET_OBJECTS:schemeD>)

target_link_libraries(CLSigLib ${CORE_LIB_PATH}/core.a)