set SOURCES=dllMain.c config.c
set FLAGS=-shared -g -Wall -Wextra -pedantic
set INCLUDES=
set LIBS=-lgdi32 -lcomctl32

g++ -o swr_reimpl.dll %SOURCES% %FLAGS% %INCLUDES% %LIBS%

move swr_reimpl.dll "C:\Users\Tim\Desktop\STAR WARS Racer - Copy"
echo No | copy /-Y Loader_config.txt "C:\Users\Tim\Desktop\STAR WARS Racer - Copy"
