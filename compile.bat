ECHO OFF
cd loader
g++ loader.cpp -o loader
MOVE loader.exe ../build

cd ../swr_reimpl
g++ -o swr_reimpl.dll dllMain.cpp main.cpp hook.c -s -shared
MOVE swr_reimpl.dll ../build
