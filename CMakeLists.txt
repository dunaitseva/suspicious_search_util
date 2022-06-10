cmake_minimum_required(VERSION 3.20)
project(SuspiciousSearchUtil)

set(CMAKE_CXX_STANDARD 17)

set(PROJECT_DIR project)
set(SOURCE_DIR ${PROJECT_DIR}/src)
set(INCLUDE_DIR ${PROJECT_DIR}/include)


set(EXE_TARGET_NAME ${PROJECT_NAME})



add_executable(
        ${EXE_TARGET_NAME}
        ${PROJECT_DIR}/main.cpp
)
target_include_directories(${EXE_TARGET_NAME} PUBLIC ${INCLUDE_DIR})
