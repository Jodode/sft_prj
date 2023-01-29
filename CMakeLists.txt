cmake_minimum_required(VERSION 3.10)

project(SFT VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CROSSCOMPILING BOOL TRUE)
option(BUILD_DOC "Build Documentation" ON)
option(PCAPPP_INSTALL "Install PcapPlusPlus" ON)

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

add_executable(${PROJECT_NAME} main.cpp)

find_package(Doxygen)

if (DOXYGEN_FOUND)
    set(DOXYGEN_IN ${CMAKE_SOURCE_DIR}/docs/Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT})
    message("Doxygen build started")

    add_custom_target(
            doc ALL
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating documentation with Doxygen"
            VERBATIM
            )
else (DOXYGEN_FOUND)
    message("Doxygen need to be installed to generate the doxygen documentation")
endif (DOXYGEN_FOUND)


target_link_libraries(${PROJECT_NAME}
        -lpthread
        Pcap++
        Packet++
        Common++
        -lpcap
        docopt
        fmt::fmt
        )

install(TARGETS ${PROJECT_NAME} DESTINATION sft/bin)
install (FILES ${PROJECT_SOURCE_DIR}/StatsCollector.h
        DESTINATION sft/include)
