project(NetCrypt)
cmake_minimum_required(VERSION 2.6)

set(Sources src/main.cpp src/SymmetricEncryption.cpp src/main_options.cpp
	src/SecureTransmission.cpp src/InsecureTansmission.cpp src/Transmission.cpp )

find_path(OPENSSL_INCLUDE_DIR openssl/evp.h)
find_path(BOOST_INCLUDE_DIR boost/program_options.hpp)

# Static libs
find_library(BOOST_LIBRARIES libboost_program_options.a REQUIRED)
find_library(CRYPTO_LIBRARIES NAMES libcrypto.a crypto REQUIRED)

include_directories( ${OPENSSL_INCLUDE_DIR} ${BOOST_INCLUDE_DIR} include )

add_executable(netcrypt ${Sources} )
target_compile_options(netcrypt PUBLIC -std=c++11 -Wall )
target_link_libraries(netcrypt ${BOOST_LIBRARIES} ${CRYPTO_LIBRARIES} ${CMAKE_DL_LIBS} )

install(TARGETS netcrypt DESTINATION bin)

