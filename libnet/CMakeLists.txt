CMAKE_MINIMUM_REQUIRED(VERSION 3.0.0) 

# 定义解决方案名称
SET(NAME net)

PROJECT(${NAME} CXX) # CMAKE_CURRENT_SOURCE_DIR

# 存在未使用的变量引用阻止编译则启用 -Wall
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wextra -Werror -Wno-unused-result -Wno-unused-parameter -Wno-deprecated")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-strict-aliasing -fPIC -fvisibility=hidden")

# 配置预定义编译宏
ADD_DEFINITIONS(-DLINUX)

IF(BT MATCHES "Debug" OR CMAKE_BUILD_TYPE STREQUAL Debug)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_DEBUG -g")
ELSE()
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
ENDIF()

SET(CMAKE_EXE_LINKER_FLAGS "-static-libstdc++ -rdynamic -Wl,-Bstatic")

# 检查C/CXX编译器标志，设置C/CXX11支持变量
INCLUDE(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
CHECK_CXX_COMPILER_FLAG("-std=c++0x" COMPILER_SUPPORTS_CXX0X)

# 使用变量设置编译标志
IF(COMPILER_SUPPORTS_CXX11)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
ELSEIF(COMPILER_SUPPORTS_CXX0X)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
ELSE()
    MESSAGE(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
ENDIF()

SET(PROJECT_REFERENCES_ROOT $ENV{BUILD_ROOT}/Ppx/trunk)

# 设置编译的头文件搜索目录
INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}
    ${PROJECT_REFERENCES_ROOT}/inc
)

# 设置搜索的第三库连接目录
LINK_DIRECTORIES(${PROJECT_REFERENCES_ROOT}/lib)

# 设置编译的源文件搜索目录
FILE(GLOB_RECURSE SOURCE_FILES *.cc)

# 添加编译输出的二进制文件
ADD_LIBRARY(# Sets the name of the library.
        ${NAME}

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        ${SOURCE_FILES})

# 设置编译输出文件路径
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# 设置与依赖库之间的库连接
TARGET_LINK_LIBRARIES(${NAME} libc.a ssl crypto dl pthread boost_system boost_coroutine boost_thread boost_context) 