cmake_minimum_required(VERSION 3.10)

# NDK 路径：优先取环境变量（CI 场景），否则回退到本地默认路径
if(DEFINED ENV{ANDROID_NDK_HOME} AND NOT "$ENV{ANDROID_NDK_HOME}" STREQUAL "")
    set(NDK_PATH $ENV{ANDROID_NDK_HOME})
else()
    set(NDK_PATH E:/ndk/android-ndk-r29)
endif()

set(CMAKE_TOOLCHAIN_FILE ${NDK_PATH}/build/cmake/android.toolchain.cmake)
set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_SYSTEM_VERSION 30)
set(ANDROID_PLATFORM 30)
set(ANDROID_ABI arm64-v8a)
set(CMAKE_BUILD_TYPE Release)
project(injector C)

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -O2 -s -std=c11 -Wall")

add_executable(injector injector.c)

set_target_properties(injector PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/outputs/${ANDROID_ABI})
