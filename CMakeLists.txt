cmake_minimum_required(VERSION 3.16)
project(log_analyzer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Sources are globbed so that adding a file never requires editing this list.
file(GLOB_RECURSE LIB_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/*.cpp)
file(GLOB_RECURSE TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/tests/*.cpp)

find_package(Threads REQUIRED)

add_library(loganalyzer_lib STATIC ${LIB_SOURCES})
target_include_directories(loganalyzer_lib PUBLIC ${CMAKE_SOURCE_DIR}/include)
# The HTTP server (serve command) runs on its own thread and, on Windows, uses Winsock.
target_link_libraries(loganalyzer_lib PUBLIC Threads::Threads)
if(WIN32)
  target_link_libraries(loganalyzer_lib PUBLIC ws2_32)
endif()

add_executable(loganalyzer app/main.cpp)
target_link_libraries(loganalyzer PRIVATE loganalyzer_lib)

add_executable(loganalyzer_tests ${TEST_SOURCES})
target_include_directories(loganalyzer_tests PRIVATE ${CMAKE_SOURCE_DIR}/tests)
target_link_libraries(loganalyzer_tests PRIVATE loganalyzer_lib)

# cmake -DLOGANALYZER_SANITIZE=ON builds everything with AddressSanitizer and
# UndefinedBehaviorSanitizer (GCC / Clang; on MSVC use tools/quick.ps1 -Asan instead).
option(LOGANALYZER_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer (GCC/Clang)" OFF)

foreach(tgt loganalyzer_lib loganalyzer loganalyzer_tests)
  if(MSVC)
    # C4127 fires on the do { } while (0) idiom inside the test macros.
    target_compile_options(${tgt} PRIVATE /W4 /wd4127 /utf-8)
    target_compile_definitions(${tgt} PRIVATE _CRT_SECURE_NO_WARNINGS)
  else()
    target_compile_options(${tgt} PRIVATE -Wall -Wextra -Wpedantic)
    if(LOGANALYZER_SANITIZE)
      target_compile_options(${tgt} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer -g)
      target_link_options(${tgt} PRIVATE -fsanitize=address,undefined)
    endif()
  endif()
endforeach()

enable_testing()
add_test(NAME all_tests COMMAND loganalyzer_tests)
