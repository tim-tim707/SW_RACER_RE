@echo off

cd loader
g++ loader.cpp md5.c -Imd5 -o loader
MOVE loader.exe ../build

cd ..

python3.11 scripts\GenerateGlobalHeaderFromSymbols.py
python3.11 scripts\GenerateHooks.py

set SOURCES=dllMain.c main.c hook.c swr.c hook_generated.c stdPlatform.c Dss\*.c Engine\*.c General\*.c Gui\*.c Main\*.c Platform\*.c Primitives\*.c Raster\*.c Unknown\*.c Swr\*.c Win95\*.c
set FLAGS=-s -shared -DINCLUDE_DX_HEADERS=1
set INCLUDES=-I.
set LIBS=-lgdi32 -lcomctl32 -lole32 -lwinmm

cd src
gcc -o swr_reimpl.dll %SOURCES% %FLAGS% %INCLUDES% %LIBS%
MOVE swr_reimpl.dll ../build
cd ..
