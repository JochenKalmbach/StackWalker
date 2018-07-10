project(StackWalker-project)

cmake_minimum_required(VERSION 3.5)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
    #set(CMAKE_BUILD_TYPE Debug)
endif()


option(StackWalker_DISABLE_TESTS  "Disable tests" OFF)


###############################
# Check compiler's capabilities
###############################

include (CheckCXXCompilerFlag)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set (CMAKE_COMPILER_IS_CLANG true)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    set (CMAKE_COMPILER_IS_MSVC true)
endif()

if(CMAKE_COMPILER_IS_MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_SECURE_SCL=0")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_CRT_SECURE_NO_DEPRECATE")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_CRT_NONSTDC_NO_DEPRECATE")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_SCL_SECURE_NO_DEPRECATE")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Zi")
else()
    message(FATAL_ERROR "${CMAKE_CXX_COMPILER_ID} is not supported yet")
endif()

message(STATUS "CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}")
set (CMAKE_INSTALL_INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
set (CMAKE_INSTALL_LIBDIR "${CMAKE_INSTALL_PREFIX}/lib")
set (CMAKE_INSTALL_BINDIR "${CMAKE_INSTALL_PREFIX}/bin")
message(STATUS "CMAKE_INSTALL_INCLUDEDIR: ${CMAKE_INSTALL_INCLUDEDIR}")
message(STATUS "CMAKE_INSTALL_LIBDIR: ${CMAKE_INSTALL_LIBDIR}")
message(STATUS "CMAKE_INSTALL_BINDIR: ${CMAKE_INSTALL_BINDIR}")

set(TARGET_StackWalker StackWalker)
add_library(${TARGET_StackWalker} STATIC
    Main/StackWalker/StackWalker.cpp)
target_include_directories(${TARGET_StackWalker} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/Main/StackWalker>
    )

install(TARGETS "${TARGET_StackWalker}"
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

install(FILES "${CMAKE_SOURCE_DIR}/Main/StackWalker/StackWalker.h"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/${TARGET_StackWalker}.dir/$\{CMAKE_INSTALL_CONFIG_NAME\}/${TARGET_StackWalker}.pdb"
    DESTINATION ${CMAKE_INSTALL_LIBDIR} OPTIONAL)


if (StackWalker_DISABLE_TESTS)
    message(STATUS "Skipping tests")
else()
    enable_testing()

    set(TARGET_StackWalker_tests StackWalker_test)
    add_executable(${TARGET_StackWalker_tests}
        Main/StackWalker/main.cpp)
    target_link_libraries(${TARGET_StackWalker_tests} PUBLIC ${TARGET_StackWalker})

    add_test(NAME ${TARGET_StackWalker_tests} COMMAND ${TARGET_StackWalker_tests})
endif()
