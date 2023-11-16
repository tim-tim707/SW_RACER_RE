set SOURCES=dllMain.c
set FLAGS=-shared -g
set INCLUDES=
set LIBS=-lgdi32 -lcomctl32

g++ -o swr_reimpl.dll %SOURCES% %FLAGS% %INCLUDES% %LIBS%

move swr_reimpl.dll "C:\Users\Tim\Desktop\STAR WARS Racer - Copy"
