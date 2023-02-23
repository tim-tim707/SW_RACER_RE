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

# structures.h file
This file is used for documentation purposes and contains the most commonly used structs.

# Macros
Most of the macros are defined in Helper-macros.c

# Global variables
Many notes are contained in the `Dat_annoted.md` file. It contains all global variable references and sometimes a comment on what it is / does.
