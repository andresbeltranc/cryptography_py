cmake_minimum_required(VERSION 3.5)

project(CryptographyPy LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CONAN_LIBS_FOLDER "conan_libs")
set(CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/${CONAN_LIBS_FOLDER}")


add_subdirectory(pybind11)
pybind11_add_module(CryptographyPy main.cpp Cipher.cpp Cipher.h)

find_package(OpenSSL REQUIRED)
if (OPENSSL_FOUND)
  # Add the static lib for linking Qt${QT_VERSION_MAJOR}::Core
  target_link_libraries(CryptographyPy PRIVATE OpenSSL::SSL OpenSSL::Crypto)
  message(STATUS "Found OpenSSL ${OPENSSL_VERSION}")
else()
  message(STATUS "OpenSSL Not Found")
endif()

# cmake -DCMAKE_PREFIX_PATH="/home/andres/Qt/6.4.3/gcc_64/lib/cmake"