cmake_minimum_required(VERSION 3.2)
project(vt_srv VERSION 0.0.1 DESCRIPTION "VT server")
set(CMAKE_CXX_FLAGS "-O2 -pipe -std=c++2a -pthread -std=gnu++2a -Wall -Wextra -fPIC")
add_executable(vt_srv ${PROJECT_SOURCE_DIR}/srv.cpp ${PROJECT_SOURCE_DIR}/../../src/libVTrans.hpp)
target_link_libraries(vt_srv -lgcc -lstdc++ -ldl -lpthread)

