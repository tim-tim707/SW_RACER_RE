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

DirectInput version 0x500 = 5

https://learn.microsoft.com/en-us/windows/win32/direct3d9/d3dtransformstatetype
and
https://learn.microsoft.com/en-us/windows/win32/api/d3d9helper/nf-d3d9helper-idirect3ddevice9-settransform
https://learn.microsoft.com/en-us/windows/win32/api/d3d9helper/nn-d3d9helper-idirect3ddevice9
