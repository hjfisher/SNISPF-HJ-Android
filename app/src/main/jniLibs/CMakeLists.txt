# CMake configuration for Android native library
# Build androidnative.so for all supported ABIs

cmake_minimum_required(VERSION 3.20.0)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Android NDK toolchain (automatically detected by Gradle)
# The following variables are provided by the Android Gradle plugin:
# - ANDROID_ABI
# - ANDROID_SDK_VERSION
# - ANDROID_NDK
# - ANDROID_PLATFORM

# Create the shared library
add_library(androidnative SHARED androidnative.cpp)

# Set target properties for Android
# The output name must match what Go expects via cgo
target_include_directories(androidnative PRIVATE
    ${ANDROID_NDK}/sources/android/include
)

target_link_libraries(androidnative PRIVATE
    android
    log
)

# Set output name (cgo expects exactly "androidnative.so")
set_target_properties(androidnative PROPERTIES
    OUTPUT_NAME "androidnative"
    PREFIX ""
    SUFFIX ".so"
)

# Set properties for different Android versions
if(ANDROID_SDK_VERSION GREATER_EQUAL 26)
    # Use setsocknetwork for API level 26+
    target_compile_definitions(androidnative PRIVATE
        ANDROID_HAS_SETSOCKNETWORK=1
    )
endif()

# Optional: Set library to be built for all ABIs
# This is handled by Android Gradle plugin which creates multiple CMake instances