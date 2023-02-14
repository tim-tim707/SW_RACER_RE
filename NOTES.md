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
```C
Release(); // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
```

# Matrices
Matrices look like this:

0  1  2  3
4  5  6  7
8  9  a  b
c  d  e  f
-------------
0   1   2   3
4   5   6   7
8   9  10  11
12 13  14  15

Transform matrixes look like this (Translation is on the bottom instead of on the right like with OpenGL)
Where S is a scaling factor, T a translation factor and R a rotation factor:
S_x*R  R      R      0
R      S_y*R  R      0
R      R      S_z*R  0
T_x    T_y    T_z    1.0
