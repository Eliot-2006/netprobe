cmake_minimum_required(VERSION 3.25)
project(netprobe VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(NETPROBE_BUILD_TESTS "Build unit and integration tests" ON)
option(NETPROBE_BUILD_BENCH "Build Google Benchmark suites and synth_pcap" OFF)
option(NETPROBE_BUILD_FUZZ "Build libFuzzer targets (Clang only)" OFF)
option(NETPROBE_WERROR "Treat warnings as errors" OFF)
option(NETPROBE_HARDENING "Enable standard-library assertions / hardening" OFF)
set(NETPROBE_SANITIZE "" CACHE STRING "Sanitizers: '', 'address,undefined', or 'thread'")

# Upstream (e.g. Homebrew) Clang on macOS ships headers for its own libc++; link that libc++
# instead of the system one. Apple Clang 15's sanitizer runtimes do not start on newer macOS.
if(APPLE AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  get_filename_component(_llvm_root "${CMAKE_CXX_COMPILER}" DIRECTORY)
  get_filename_component(_llvm_root "${_llvm_root}" DIRECTORY)
  if(EXISTS "${_llvm_root}/lib/c++")
    add_link_options(-L${_llvm_root}/lib/c++ -Wl,-rpath,${_llvm_root}/lib/c++)
  endif()
endif()

# ---- shared compile settings for project targets (not third-party) ----
add_library(netprobe_options INTERFACE)
target_compile_options(netprobe_options INTERFACE
  -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow
  -Wnon-virtual-dtor -Wold-style-cast)
if(NETPROBE_WERROR)
  target_compile_options(netprobe_options INTERFACE -Werror)
endif()
if(NETPROBE_HARDENING)
  target_compile_definitions(netprobe_options INTERFACE
    _GLIBCXX_ASSERTIONS
    _LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE
    NETPROBE_DEBUG_GUARDS=1)
endif()
if(NETPROBE_SANITIZE)
  # Sanitizers apply to everything (including gtest) so instrumentation is consistent.
  add_compile_options(-fsanitize=${NETPROBE_SANITIZE} -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=${NETPROBE_SANITIZE})
endif()

# ---- core library: every src/**/*.cpp except main.cpp ----
file(GLOB_RECURSE NETPROBE_CORE_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/*.cpp)
list(REMOVE_ITEM NETPROBE_CORE_SOURCES ${CMAKE_SOURCE_DIR}/src/main.cpp)
add_library(netprobe_core STATIC ${NETPROBE_CORE_SOURCES})
target_include_directories(netprobe_core PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(netprobe_core PUBLIC NETPROBE_VERSION="${PROJECT_VERSION}")
target_link_libraries(netprobe_core PUBLIC netprobe_options)
find_package(Threads REQUIRED)
target_link_libraries(netprobe_core PUBLIC Threads::Threads)

add_executable(netprobe src/main.cpp)
target_link_libraries(netprobe PRIVATE netprobe_core)

include(FetchContent)

if(NETPROBE_BUILD_TESTS)
  enable_testing()
  FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
    GIT_SHALLOW TRUE)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  file(GLOB_RECURSE NETPROBE_TEST_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_SOURCE_DIR}/tests/unit/*.cpp
    ${CMAKE_SOURCE_DIR}/tests/support/*.cpp
    ${CMAKE_SOURCE_DIR}/tests/reference/*.cpp)
  add_executable(netprobe_tests ${NETPROBE_TEST_SOURCES})
  target_include_directories(netprobe_tests PRIVATE ${CMAKE_SOURCE_DIR}/tests)
  target_link_libraries(netprobe_tests PRIVATE netprobe_core GTest::gtest_main)
  target_compile_definitions(netprobe_tests PRIVATE
    NETPROBE_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
  include(GoogleTest)
  gtest_discover_tests(netprobe_tests DISCOVERY_TIMEOUT 60)

  # Integration tests drive the CLI binary (tests/integration/run_*.py).
  find_package(Python3 COMPONENTS Interpreter)
  if(Python3_FOUND)
    file(GLOB NETPROBE_INTEGRATION_SCRIPTS CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/tests/integration/test_*.py)
    foreach(script ${NETPROBE_INTEGRATION_SCRIPTS})
      get_filename_component(name ${script} NAME_WE)
      add_test(NAME integration.${name}
        COMMAND ${Python3_EXECUTABLE} -I ${script} --netprobe $<TARGET_FILE:netprobe>
                --source-dir ${CMAKE_SOURCE_DIR})
    endforeach()
  endif()
endif()

if(NETPROBE_BUILD_FUZZ)
  file(GLOB NETPROBE_FUZZ_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/tests/fuzz/fuzz_*.cpp)
  foreach(src ${NETPROBE_FUZZ_SOURCES})
    get_filename_component(name ${src} NAME_WE)
    add_executable(${name} ${src})
    target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/tests)
    target_link_libraries(${name} PRIVATE netprobe_core)
    target_compile_options(${name} PRIVATE -fsanitize=fuzzer)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer)
  endforeach()
endif()

if(NETPROBE_BUILD_BENCH)
  FetchContent_Declare(benchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG v1.9.1
    GIT_SHALLOW TRUE)
  set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
  set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(benchmark)
  file(GLOB NETPROBE_BENCH_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/bench/*.cpp)
  if(NETPROBE_BENCH_SOURCES)
    add_executable(netprobe_bench ${NETPROBE_BENCH_SOURCES})
    target_include_directories(netprobe_bench PRIVATE ${CMAKE_SOURCE_DIR}/tests)
    target_link_libraries(netprobe_bench PRIVATE netprobe_core benchmark::benchmark_main)
  endif()
  if(EXISTS ${CMAKE_SOURCE_DIR}/tools/synth_pcap.cpp)
    add_executable(synth_pcap tools/synth_pcap.cpp)
    target_link_libraries(synth_pcap PRIVATE netprobe_core)
  endif()
endif()
