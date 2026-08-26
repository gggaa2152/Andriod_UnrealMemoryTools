cmake_minimum_required(VERSION 3.10)

# NDK 路径：优先取环境变量（CI 场景），否则回退到本地默认路径
if(DEFINED ENV{ANDROID_NDK_HOME} AND NOT "$ENV{ANDROID_NDK_HOME}" STREQUAL "")
    set(NDK_PATH $ENV{ANDROID_NDK_HOME})
elseif(DEFINED ANDROID_NDK_HOME)
    set(NDK_PATH ${ANDROID_NDK_HOME})
else()
    set(NDK_PATH E:/ndk/android-ndk-r29)
endif()

set(CMAKE_TOOLCHAIN_FILE ${NDK_PATH}/build/cmake/android.toolchain.cmake)
set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_SYSTEM_VERSION 30)
set(ANDROID_PLATFORM 30)
set(ANDROID_ABI arm64-v8a)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/outputs/${ANDROID_ABI})
project(UnrealMemoryTools)

set(KITTYMEMORY_PATH KittyMemoryEx)
file(GLOB KITTYMEMORY_SRC ${KITTYMEMORY_PATH}/*.cpp)

set(DEPS_PATH deps)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -O0 -g -std=c++20 -fexceptions -fPIC -DDEBUG -DkNO_KEYSTONE -w")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O2 -s -std=c++20 -fexceptions -fPIC -DNDEBUG -DkNO_KEYSTONE -w ")

file(GLOB UE_SRC src/UE/*.cpp)
file(GLOB UE_PROFILE_SRC src/UE/UEGameProfiles/*.cpp)
file(GLOB AUTOFIX_SRC src/AutoFix/*.cpp)
file(GLOB GUI_SRC
        src/GUI/Android_draw/*.cpp
        src/GUI/Android_Graphics/*.cpp
        src/GUI/Android_my_imgui/*.cpp
        src/GUI/Android_touch/*.cpp
        src/GUI/ImGui/*.cpp
        src/GUI/ImGui/backends/*.cpp
        src/GUI/ImGui/misc/freetype/*.cpp
        src/GUI/My_Utils/*.cpp)

include_directories(
        ${DEPS_PATH}
        ${KITTYMEMORY_PATH}
        src/GUI
        src/GUI/Android_draw
        src/GUI/Android_Graphics
        src/GUI/Android_my_imgui
        src/GUI/Android_touch
        src/GUI/ImGui
        src/GUI/ImGui/backends
        src/GUI/ImGui/misc/freetype
        src/GUI/ImGui/misc/git_freetype
        src/GUI/My_Utils
        src/GUI/native_surface)
link_libraries(-llog -landroid -lEGL -lGLESv3 -lvulkan -lz -ldl)

# ===== Hook 注入模式：产物为共享动态库 libUnrealMemoryTools.so =====
# 移除了独立的 executable 入口 (src/executable.cpp 中的 main 已改为 ExecutableMain)，
# 由 src/entry.cpp 的 __attribute__((constructor)) 在注入加载时自动拉起 UI。
add_library(UnrealMemoryTools SHARED src/entry.cpp ${UE_SRC} ${UE_PROFILE_SRC} ${AUTOFIX_SRC} ${GUI_SRC} src/executable.cpp src/Dumper.cpp src/UPackageGenerator.cpp src/SDKExplorer.cpp ${KITTYMEMORY_SRC} ${DEPS_PATH}/fmt/format.cc
        src/AutoFix/NativeFunctionResolver.cpp
        src/AutoFix/PropertyOffsetFinder.cpp
        src/AutoFix/StructLayout.cpp
        src/Utils/BufferFmt.cpp
        src/Utils/KittyCmdln.cpp
        src/Utils/ProgressUtils.cpp)

target_compile_definitions(UnrealMemoryTools PRIVATE
        kEXECUTABLE
        VK_USE_PLATFORM_ANDROID_KHR
        IMGUI_IMPL_VULKAN_NO_PROTOTYPES
        IMGUI_ENABLE_FREETYPE
        IMGUI_DISABLE_DEBUG_TOOLS)

target_link_libraries(UnrealMemoryTools PRIVATE
        ${CMAKE_SOURCE_DIR}/src/GUI/ImGui/misc/git_freetype/${ANDROID_ABI}/libfreetype.a)
