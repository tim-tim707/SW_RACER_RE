# Installing stuff
## Needed tools
gcc, g++, nasm-shell (optional), make

Hook library:
http://www.ntcore.com/files/nthookengine.htm


# Compiling for a match

We can do this on gcc/clang:

```C
__attribute__((section(".text#")))
//The '#' on the ".text" string is not a typo. It’s a comment token and necessary to silent a warning.
// Similarly, if you’re MSVC based, you can add the following instead:

#pragma section(".text")
__declspec(allocate(".text"))
```

Does this work on `CL.exe` and `LINK.exe` (The original compiler) ?
If it does this would be great to see if we can specify additionnal settings

# External functions and references
Many functions end up calling windows headers such as the following:
- `winuser.h`
- `debugapi.h`

Don't hesitate to take a look at the microsoft documentation for the prototype of functions.

```C
Release(); // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
```

With string analysis it looks like Racer uses the JKDF2 engine (Sith Engine) (also used for Jedi Knight and such at LucasArt).
This function `FUN_00488670` especially looks similair to the one here:
https://github.com/shinyquagsire23/OpenJKDF2/blob/master/src/Win95/stdDisplay.c
(the error message in particular).

The platform abstraction is exactly the following file
https://github.com/shinyquagsire23/OpenJKDF2/blob/master/src/stdPlatform.c

From https://jkdf2.fandom.com/wiki/Sith_Engine: Models are 3DO with textures as MAT files

# structures.h file
This file is used for documentation purposes and contains the most commonly used structs.

# Macros
Most of the macros are defined in Helper-macros.c

# Global variables
Many notes are contained in the `Dat_annoted.md` file. It contains all global variable references and sometimes a comment on what it is / does.

# Additionnal informations
DirectX version = 6.1 (from the game's README)
DirectInput version 0x500 = 5
Direct3d version = 7 ? <=

Using at least IA3d4 (maybe 5 ?)
Aureal A3D 2.0
DirectSound 3D

A3D:
https://github.com/RazorbladeByte/A3D-Live-/blob/master/ia3dapi.h
http://www.worknd.ru/a3d30ref.pdf

https://learn.microsoft.com/en-us/windows/win32/direct3d9/d3dtransformstatetype
and
https://learn.microsoft.com/en-us/windows/win32/api/d3d9helper/nf-d3d9helper-idirect3ddevice9-settransform
https://learn.microsoft.com/en-us/windows/win32/api/d3d9helper/nn-d3d9helper-idirect3ddevice9

DirectDraw:
https://github.com/CnCNet/ts-ddraw/blob/master/ddraw.h

DirectInput:
https://github.com/project64/project64/blob/b0b6c03eea6ea3ef5bddca32de5fdebd94b0be7e/Source/3rdParty/directx/include/dinput.h

after preprocessing with godbolt -DDIRECTINPUT_VERSION=0x500 -E -P : ./dinput_0x500.h

# Matrix and Vectors

Matrix vector transform (scale ignored):
                            x
                            y
                            z
  rvec  lvec  uvec  scale
x                        -> x
y                        -> y
z                        -> z

# Structures
sizeof(rdCamera) = 0x878 (we have 0x464. Missing padding ?)
sizeof(rdClipFrustum) = 100 (we have 52. Missing padding ?)

# CLI Flags from  https://github.com/OpenSWE1R/openswe1r/wiki/Command-Line-Arguments

Display
-i
"Disables the introduction cutscenes when launching the game." [0]

-v
"Triggers the "Display Settings" window but does not launch the game." [0]

Multiplayer
-nut x
"Where x is the time in milliseconds to delay between network updates." [0]

Force Feedback
-force
"Disables force feedback on a force feedback gaming device. This should be used if you have a Force Feedback device that is causing problems while playing Racer." [0]

3D Sound
-s
"Turns the sound engine off. Low end machines may see an increase in framerate if the entire sound engine is off." [0]

+3DImpacts
"Turns on additional 3D collision sounds with with certain Aureal 3D cards and the Sound Blaster Live. This option will not have any effect unless 3D Audio is enabled in Racer.
NOTE: This switch will only function properly if you have an Aureal 3D or Sound Blaster Live card in your system." [0]

-d
"Changes the 3D sound doppler-scale factor to exaggerate doppler effects. The higher the number, the more exaggerated the doppler. 1.0 is the default and 0 turns Doppler Effects off." [0]

-r
"Changes the 3D sound rolloff factor. The bigger this number the faster the sounds will become quieter as they move away from you. 0.1 is the default. All 3D-Spatialized sounds will play at the same volume and will not be attenuated by distance." [0]

[0] File "Install/readme.txt" on the PC installation disc."

Undocumented
-p
Unknown, seems to be related to sound. [1]

-f
Relates to the "FullScreen" registry key. Influences graphical initialization. [1]

-snafu
Discards all other given arguments. If another bit is set in the executables data is also set, it displays a debugging HUD that displays FPS and a 3 to 4 digit number, possibly something like faces or vertices count. [1]


# Notes on Assembly (x86)

Calling convention is as follow:

```c
int fun(int a, int b, int c, int d, int e, int f, int g, int h);
fun(1,2,3,4,5,6,7,8);
<=>
8, 7, r9d, r8d, ecx, edx, esi, edi fun()
<=>
push    8
push    7
mov     r9d, 6
mov     r8d, 5
mov     ecx, 4
mov     edx, 3
mov     esi, 2
mov     edi, 1
call    fun
<=>
fun(edi, esi, edx, ecx, r8d, r9d, pop0, pop1)
```

On windows, arguments are passed on the stack instead of the registers
