project(JpsNet)
cmake_minimum_required(VERSION 2.6)

set(Sources main.cpp SymmetricEncryption.cpp )

add_executable(JpsNet ${Sources} )
target_compile_options(JpsNet PUBLIC -std=c++11)
target_link_libraries(JpsNet boost_program_options crypto)
