set SOURCES=loader.cpp md5.c
set FLAGS=-g -Wall -Wextra -pedantic

g++ -o loader %SOURCES% %FLAGS%
