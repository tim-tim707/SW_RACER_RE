# Unknown caller
Functions with an unknown caller haven't been renamed
```C
BOOL __cdecl sub_445B50(unsigned int a1) // buffer.c: is_inbound
int sub_449EF0() // A3D-Update.c: Unknown
```

Looks like the `vec.c` module is compiled but unused as well ?
Here are the functions that look like aren't called (not found with ctr+f)
```C
float *__cdecl vec_add(float *a1, float *a2, float *a3)
int __cdecl vec_scale(float *a1, float a2, float *a3)
float *__cdecl vec_scale_add(float *a1, float *a2, float a3, float *a4)
double __cdecl vec_norm_431800(float *a1)
float *__cdecl vec_set_431830(float *a1, float a2, float a3, float a4)
float *__cdecl vec_set_431830(float *a1, float a2, float a3, float a4)
BOOL __cdecl vec_equal_431870(const float *a1, const float *a2)
```
but some are used:
```C
vec_add()
```

# No reference to definition / Functions yet to Reverse Engineer
These functions have a definition but haven't been reversed yet but are called,
or the definition is in another castle

unknown types variables are names a, b, c... in prototypes
ints: i1, i2 ...
floats: f1, f2 ...
char* or strings: string1, string2 ...
with prefix * if pointers

```C
nullsub_3();

sub_42F7B0(a, 0.0f, 0.0f, 0.0f | 1.0f); // largest-function.c: ? only called trice
sub_42F7D0(a, b); // largest-function.c: ?
sub_42F830(a, b, c); // largest-function.c: ?
sub_42F8C0(a); // largest-function.c: ? called only once
sub_42F9B0(a); // largest-function.c: ?
sub_42F9F0(a, b, c); // largest-function.c: ? called only twice successivelly
sub_42FA80(int, int, float f1, int); // largest-function.c: ?
sub_430980(a, b, c); // largest-function.c ?
sub_4310B0(a, b, c, d); // largest-function.c: ?
sub_431100(a, b, c, d); // largest-function.c: ? called once
sub_431390(a, b, c, d, e, f); // largest-function.c: ?
sub_431450(int? i1, float f1, float f2, float f3, int? i2); // largest-function.c: ?
sub_431640(v18, &v83); // largest-function.c: ?
sub_4316A0(a, b); // largest-function.c: ? only called twice, almost successively
sub_431740(a, 0|1); // largest-function.c: ? called only twice. Doesn't look unrolled
sub_431770(); // Comparison in A3D-Update.c: ?
sub_431A50(a, int i1, int i2, int i3, int i4); // largest-function.c: ? hardcoded offsets or flags on last 4 arguments
sub_43E6F0(); // largest-function.c: ? only called once

sub_44BB10(a, b); // A3D-Update + largest-function.c: ?
sub_46F2C0(0, a, b, c); // largest-function.c: ? called once with 0

sub_481B30(*(_DWORD *)(a1 + 4|8|12|16|20), (float *)&unk_4C0088); // largest-function.c: ? initialize the fields of some struct. Called only 5 times successivelly on the same second argument
sub_481C30(*(_DWORD *)(a1 + (40 + i * 4)), (int)&v94, (int)&v93, *(float *)&v68, 1.0f, 0.0f, 50.0f, 0); // largest-function.c: ? only called once
set_velocity3f_484E40(); // call IA3dListener::SetVelocity3f
fsqrt_485690(v1); // vec.c: fsqrt
sub_484F10(); // A3dListener related
sub_484F40(); // A3dListener related 2
sub_484FA0(); // A3dListener related 3
```

Most of the functions of `largest-function.c` aren't decompiled: hypothesis for this file / the modules to it:
Physics engine, pod something, track | checkpoint something ?

`vec.c` file is not done from decompiling. Most of the functions aren't used as well. Maybe missing some entire module ?

# External functions and references
```C
Release(); // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
```

# List of all globals / static in address order
```C
use_some_wave_file_4B6D14 // string audio config argument
a3d_control_something_4B6D18 // A3D-Update: Control flag
dword_4B6D20 // Command-line flag. WO ?
unk_4C0088 // largest-function.c: some kind of array ? Used as second argument to sub_481B30
volume_setting_4C7D7C // Volume setting
dword_4EB450 // A3D*.c: Control flag. RO ?
dword_EC8E84 // More-Audio.c: Control flag
dword_50C614 // buffer.c: buffer index. RO ?
IA3dX_50D548 // A3D*.c: IA3dX:: Object, see http://www.worknd.ru/a3d30ref.pdf
dword_50D550 // A3D*.c: Control flag
dword_E981E4 // buffer.c: beginning of 28 bytes buffer ? Contains char* ?
config_string_EC8E84 // string (char*) config argument flag
dword_EC8E90 // string (char*) config argument value
dword_E98200 //  buffer.c: buffer for load unload
```
