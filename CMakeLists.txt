cmake_minimum_required(VERSION 3.20)
project(SuspiciousSearchUtil)

set(CMAKE_CXX_STANDARD 20)

#set(CMAKE_CXX_COMPILER "C:\\Program Files\\LLVM\\bin\\clang++.exe")
#set(CMAKE_C_COMPILER "C:\\Program Files\\LLVM\\bin\\clang.exe")

set(PROJECT_DIR project)
set(SOURCE_DIR ${PROJECT_DIR}/src)
set(INCLUDE_DIR ${PROJECT_DIR}/include)

set(LIB_NAME SuspiciousSearchUtilLib)
add_library(
        ${LIB_NAME}
        ${SOURCE_DIR}/SuspiciousEntryStorage.cpp
        ${SOURCE_DIR}/Analyzer.cpp
        ${SOURCE_DIR}/Match.cpp
        ${SOURCE_DIR}/DirectoryReport.cpp
)
target_include_directories(${LIB_NAME} PUBLIC ${INCLUDE_DIR})

set(EXE_TARGET_NAME ${PROJECT_NAME})
add_executable(
        ${EXE_TARGET_NAME}
        ${PROJECT_DIR}/main.cpp
)
target_include_directories(${EXE_TARGET_NAME} PUBLIC ${INCLUDE_DIR})
target_link_libraries(${EXE_TARGET_NAME} PUBLIC ${LIB_NAME})

option(TEST "Enable tests build" OFF)
if (TEST)
    message(STATUS "Testing enabled")

    include(FetchContent)
    FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/archive/609281088cfefc76f9d0ce82e1ff6c30cc3591e5.zip
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    enable_testing()
    include(GoogleTest)

    set(TEST_DIR tests)
    set(test_file_suffix Tests)
    set(test_file_ext cpp)

    file(GLOB TestsSrc "${TEST_DIR}/*${test_file_suffix}.${test_file_ext}")
    foreach (file ${TestsSrc})
        message("Testing file ${file} found")
        get_filename_component(target_test ${file} NAME_WE)

        add_executable(${target_test} ${file})
        target_include_directories(${target_test} PUBLIC ${INCLUDE_DIR})
        target_link_libraries(${target_test} PUBLIC gtest_main)
        target_link_libraries(${target_test} PUBLIC ${LIB_NAME})
        gtest_discover_tests(${target_test})

        message(STATUS "Target ${target_test} tests created")
    endforeach ()
endif ()
