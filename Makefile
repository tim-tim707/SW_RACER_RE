all:
	@echo Compiling fast for windows 32bit \(without the real compiler\)
	@# TODO: use single file compilation for obj caching instead of full compilation
	i686-w64-mingw32-gcc -Wall -Wextra -pedantic ./src/* -o build/SW_RE_fast.exe
	wine SW_RE_fast.exe 2>/dev/null

send:
	@# TODO: send the asset block in case
	cp ./src/*.c ./src/*.h "/home/tim/.wine/drive_c/Program Files (x86)/DevStudio/MyProjects/SW_RE"

get_binary:
	cp "/home/tim/.wine/drive_c/Program Files (x86)/DevStudio/MyProjects/SW_RE/Debug/SW_RE.exe" .

launch: send
	@echo "File -> Open Workspace -> SW_RE.DSW. Right click SW_RE files in the file explorer on the left and click "add files to project" to add your new files"
	wine explorer /desktop=name,1024x768 "/home/tim/.wine/drive_c/Program Files (x86)/DevStudio/SharedIDE/bin/MSDEV.EXE" 2>/dev/null

compare:
	@echo TODO: match binary blobs

compile:
	@echo TODO: use a bat file to drive CL.EXE directly from .wine/drive_c/Program Files (x86)/DevStudio/VC/bin/CL.EXE
	@echo You need  run  .wine/drive_c/Program Files (x86)/DevStudio/VC/bin/VCVARS32.BAT first but this pagefaults cmd
	@echo This would be great for a fully automatic send -> compile -> compare cycle but I'm stuck with manual compilation for now

config:
	@# TODO: check wine installation
	@# TODO: Check mingw installation sudo apt install gcc-mingw-w64
	@# TODO: Setup absolute directory
	@# TODO: From the original game, get the assets to send to compile in our code
	@echo Installing vcpp from iso... Product key is 111-11111. Project name is SW_RE
	sudo mount vcpp5.iso /media/x
	wine explorer /desktop=name,1024x768 /media/x/setup.exe 2>/dev/null

help:
	@echo Send files, launch vcpp 5.0 in wine, get the executable...
