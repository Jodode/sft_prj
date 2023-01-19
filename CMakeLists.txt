cmake_minimum_required(VERSION 3.0)

project(SFT VERSION 1.0 LANGUAGES CXX)

set(target sft)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -DELPP_NO_DEFAULT_LOG_FILE" )
set(CMAKE_CXX_STANDARD 14)
set(SOURCE_DIR ${CMAKE_SOURCE_DIR})



include(FetchContent)

FetchContent_Declare(
        pcpp
        GIT_REPOSITORY https://github.com/seladb/PcapPlusPlus.git
        GIT_TAG dev
)
FetchContent_Declare(
        docopt
        GIT_REPOSITORY https://github.com/docopt/docopt.cpp.git
        GIT_TAG master
)
FetchContent_Declare(
        fmt
        GIT_REPOSITORY https://github.com/fmtlib/fmt.git
        GIT_TAG master
)


FetchContent_MakeAvailable(pcpp docopt fmt)

add_executable(${target} main.cpp)

option(BUILD_DOC "Build Documentation" ON)
find_package(Doxygen)

if (DOXYGEN_FOUND)
    set(DOXYGEN_IN ${CMAKE_SOURCE_DIR}/docs/Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

    message("Doxygen build started")

    add_custom_target( doc ALL
            COMMAND doxygen -g ${CMAKE_SOURCE_DIR}/docs/Doxyfile.in
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM )
else (DOXYGEN_FOUND)
    message("Doxygen need to be installed to generate the doxygen documentation")
endif (DOXYGEN_FOUND)


target_link_libraries(${target}
        -lpthread
        Pcap++
        Packet++
        Common++
        -lpcap
        docopt
        fmt::fmt
        )