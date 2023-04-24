cmake_minimum_required(VERSION 3.2)
project(vt_cln VERSION 0.0.1 DESCRIPTION "VT client")
set(CMAKE_CXX_FLAGS "-O2 -pipe -std=c++2a -pthread -std=gnu++2a -Wall -Wextra -fPIC")
add_executable(vt_cln ${PROJECT_SOURCE_DIR}/cln.cpp ${PROJECT_SOURCE_DIR}/../../src/libVTrans.hpp)
target_link_libraries(vt_cln -lgcc -lstdc++ -ldl -lpthread)

