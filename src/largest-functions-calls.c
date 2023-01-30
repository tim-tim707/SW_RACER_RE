/*
    Calls of largest-function

sub_42F7B0(a, 0.0f, 0.0f, 0.0f | 1.0f); // largest-function.c: ? only called
trice
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
sub_431450(int? i1, float f1, float f2, float f3, int? i2); //
largest-function.c: ? sub_431640(v18, &v83); // largest-function.c: ?
sub_4316A0(a, b); // largest-function.c: ? only called twice, almost
successively
sub_431740(a, 0|1); // largest-function.c: ? called only twice.
Doesn't look unrolled
sub_431770(); // Comparison in A3D-Update.c: ?
sub_431A50(a, int i1, int i2, int i3, int i4); // largest-function.c: ?
hardcoded offsets or flags on last 4 arguments sub_43E6F0(); //
largest-function.c: ? only called once

sub_44BB10(a, b); // A3D-Update + largest-function.c: ?
sub_46F2C0(0, a, b, c); // largest-function.c: ? called once with 0

sub_481B30(*(_DWORD *)(a1 + 4|8|12|16|20), (float *)&unk_4C0088); //
largest-function.c: ? initialize the fields of some struct. Called only 5 times
successivelly on the same second argument
*/

// Set vector ?
void FUN_0042f7b0(undefined4 *param_1, undefined4 param_2, undefined4 param_3,
                  undefined4 param_4)

{
    *param_1 = param_2;
    param_1[1] = param_3;
    param_1[2] = param_4;
    return;
}

// set_vector from vector
void FUN_0042f7d0(undefined4 *param_1, undefined4 *param_2)

{
    *param_1 = *param_2;
    param_1[1] = param_2[1];
    param_1[2] = param_2[2];
    return;
}

void FUN_0042f830(float *param_1, float *param_2, float *param_3)

{
    *param_1 = *param_3 + *param_2;
    param_1[1] = param_3[1] + param_2[1];
    param_1[2] = param_3[2] + param_2[2];
    return;
}

void FUN_0042f8c0(float *param_1)

{
    SQRT3(*param_1 * *param_1 + param_1[2] * param_1[2]
          + param_1[1] * param_1[1]);
    return;
}
