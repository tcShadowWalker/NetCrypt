project(NetCrypt)
cmake_minimum_required(VERSION 2.6)

set(Sources main.cpp SymmetricEncryption.cpp main_options.cpp )

add_executable(netcrypt ${Sources} )
target_compile_options(netcrypt PUBLIC -std=c++11)
target_link_libraries(netcrypt boost_program_options crypto)
