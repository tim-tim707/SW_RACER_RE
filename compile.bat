cd loader
g++ loader.cpp md5.c -Imd5 -o loader
MOVE loader.exe ../build

set SOURCES=dllMain.c main.c hook.c globals.c Win95\Window.c Main\Main.c Main\swrMain.c Primitives\rdVector.c General\stdMath.c Primitives\rdMatrix.c
set FLAGS=-s -shared -fpermissive
set INCLUDES=-I. -IGeneral -IMain -IPrimitives -ISwr -IUnknown -IWin95
set LIBS=-lgdi32 -lcomctl32

cd ../src
g++ -o swr_reimpl.dll %SOURCES% %FLAGS% %INCLUDES%  %LIBS%
MOVE swr_reimpl.dll ../build
cd ..
