cmake_minimum_required(VERSION 3.16)
project(SW_RACER_RE)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(
    -Werror=incompatible-pointer-types
    -Werror=implicit-function-declaration
    -mfpmath=387
)

add_library(swe1r_globals INTERFACE)
target_include_directories(swe1r_globals INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(swe1r_globals INTERFACE INCLUDE_DX_HEADERS=1)

file(GLOB SOURCES
    # base files
    src/swr.c
    src/stdPlatform.c
    # specifics
    src/Dss/*c
    src/Engine/*c
    src/General/*c
    src/Gui/*.c
    src/Main/*.c
    src/Platform/*.c
    src/Primitives/*.c
    src/Raster/*.c
    src/Unknown/*.c
    src/Win95/*.c
    # only add some of Swr at the moment because its a bit unfinished
    src/Swr/swrAssetBuffer.c
    src/Swr/swrDisplay.c
    src/Swr/swrEvent.c
    src/Swr/swrLoader.c
    src/Swr/swrModel.c
    src/Swr/swrMultiplayer.c
    src/Swr/swrObj.c
    src/Swr/swrSound.c
    src/Swr/swrSpline.c
    src/Swr/swrSprite.c
    src/Swr/swrText.c
    src/Swr/swrUI.c
)
add_library(swe1r_functions OBJECT ${SOURCES})
target_include_directories(swe1r_functions PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(swe1r_functions PUBLIC swe1r_globals winmm Comctl32)

add_subdirectory(dinput_hook)