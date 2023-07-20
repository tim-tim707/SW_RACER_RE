cd loader
g++ loader.cpp -o loader
MOVE loader.exe ../build

cd ../src
g++ -o swr_reimpl.dll dllMain.cpp main.cpp hook.c -s -shared
@REM g++ -o swr_reimpl.dll dllMain.cpp main.c hook.c Win95\Window.c Main\Main.c Main\swrMain.c Primitives\rdVector.c General\stdMath.c Primitives\rdMatrix.c -s -shared -I. -IGeneral -IMain -IPrimitives -I Swr -IUnknown -IWin95
MOVE swr_reimpl.dll ../build
