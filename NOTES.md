# Various Notes of decompilation

With string analysis it looks like Racer uses the JKDF2 engine (Sith Engine) (also used for Jedi Knight and such at LucasArt).
This function `FUN_00488670` especially looks similair to the one here:
https://github.com/shinyquagsire23/OpenJKDF2/blob/master/src/Win95/stdDisplay.c
(the error message in particular).

The platform abstraction is exactly the following file
https://github.com/shinyquagsire23/OpenJKDF2/blob/master/src/stdPlatform.c

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

# Matrix and Vectors

Matrix vector transform (scale ignored):
                            x
                            y
                            z
  rvec  lvec  uvec  scale
x                        -> x
y                        -> y
z                        -> z

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
