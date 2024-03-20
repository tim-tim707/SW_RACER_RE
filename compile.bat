@echo off

cd loader
g++ loader.cpp md5.c -Imd5 -o loader
MOVE loader.exe ../build

cd ..

python3.11 scripts\GenerateGlobalHeaderFromSymbols.py
python3.11 scripts\GenerateHooks.py

set SOURCES=src\dllMain.c src\main.c src\hook.c src\swr.c src\generated\hook_generated.c src\stdPlatform.c src\Dss\*.c src\Engine\*.c src\General\*.c src\Gui\*.c src\Main\*.c src\Platform\*.c src\Primitives\*.c src\Raster\*.c src\Unknown\*.c src\Swr\*.c src\Win95\*.c
set FLAGS=-s -shared -DINCLUDE_DX_HEADERS=1 -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable
set INCLUDES=-I. -Isrc -Isrc/generated
set LIBS=-lgdi32 -lcomctl32 -lole32 -lwinmm

echo Compiling... This might take a moment
@REM TODO: parallel
gcc -o swr_reimpl.dll %SOURCES% %FLAGS% %INCLUDES% %LIBS%
MOVE swr_reimpl.dll build/
