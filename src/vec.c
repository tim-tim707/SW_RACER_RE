/* Vector math */

// Research based on demo version

typedef struct {
  float x;
  float y;
} Vec2; // custom-name

typedef struct {
  float x;
  float y;
  float z;
} Vec3; // custom-name

typedef struct {
  float f[4 * 4];
} Mat4; // custom-name

// [Preceeded by some rotation-related functions]

//----- (00431760) --------------------------------------------------------
// Add Vec2 vectors
float *__cdecl sub_431760(float *a1, float *a2, float *a3) {
  a1[0] = a2[0] + a3[0];
  a1[1] = a2[1] + a3[1];
  return a3;
}

//----- (00431780) --------------------------------------------------------
// Scale Vec2
int __cdecl sub_431780(float* a1, float a2, float* a3) {
  a1[0] = a3[0] * a2;
  a1[1] = a3[1] * a2;
  return a3;
}

//----- (004317A0) --------------------------------------------------------
// Vec2 MAD (using scalar multiplication)
float* __cdecl sub_4317A0(float* a1, float* a2, float a3, float* a4) {
  a1[0] = a4[0] * a3 + a2[0];
  a1[1] = a4[1] * a3 + a2[1];
  return a4;
}

//----- (004317D0) --------------------------------------------------------
// Get Vec2 length
double __cdecl sub_4317D0(float *a1) {
  float v1 = a1[0] * a1[0] +
             a1[1] * a1[1];
  return sub_485690(v1);
}

//----- (00431800) --------------------------------------------------------
// Normalize Vec2
double __cdecl sub_431800(float *a1) {
  double result = sub_4317D0(a1);
  if (result >= 0.0001f) {
    a1[0] = a1[0] / result;
    a1[1] = a1[1] / result;
  }
  return result;
}

//----- (00431830) --------------------------------------------------------
// Set Vec3
float* __cdecl sub_431830(float* a1, float a2, float a3, float a4) {
  a1[0] = a2;
  a1[1] = a3;
  a1[2] = a4;
  return a1;
}

//----- (00431850) --------------------------------------------------------
// Copy Vec3
float __cdecl sub_431850(float* a1, const float* a2) {
  a1[0] = a2[0];
  a1[1] = a2[1];
  a1[2] = a2[2];
  return a2[2];
}

//----- (00431870) --------------------------------------------------------
// Compare Vec3
BOOL __cdecl sub_431870(const float* a1, const float* a2) {
  return (a1[0] == a2[0]) &&
         (a1[1] == a2[1]) &&
         (a1[2] == a2[2]);
}

//----- (004318B0) --------------------------------------------------------
// Add Vec3
const float *__cdecl sub_4318B0(float *a1, const float *a2, const float *a3) {
  a1[0] = a2[0] + a3[0];
  a1[1] = a2[1] + a3[1];
  a1[2] = a2[2] + a3[2];
  return a3;
}

//----- (004318E0) --------------------------------------------------------
// Subtract Vec3
float *__cdecl sub_4318E0(float *a1, const float *a2, const float *a3) {
  a1[0] = a2[0] - a3[0];
  a1[1] = a2[1] - a3[1];
  a1[2] = a2[2] - a3[2];
  return a2;
}

//----- (00431910) --------------------------------------------------------
// Get squared length of Vec3
double __cdecl sub_431910(const float* a1, const float* a2) {
  return  a2[0] * a1[0] +
          a1[1] * a2[1] +
          a1[2] * a2[2];
}

//----- (00431940) --------------------------------------------------------
double __cdecl sub_431940(const float* a1) {
  float v1 = a1[0] * a1[0] + 
             a1[1] * a1[1] +
             a1[2] * a1[2];
  return sub_485690(v1);
}

//----- (00431990) --------------------------------------------------------
// Get squared distance between Vec3
double __cdecl sub_431990(const float *a1, const float *a2) {
  double dx = a1[0] - a2[0];
  double dy = a1[1] - a2[1];
  double dz = a1[2] - a2[2];
  return dx * dx + dy * dy + dz * dz;
}

//----- (004319D0) --------------------------------------------------------
// Get distance between Vec3
double __cdecl sub_4319D0(float *a1, float *a2) {
  double dx = a2[0] - a1[0];
  double dy = a2[1] - a1[1];
  double dz = a2[2] - a1[2];
  double v7 = dx * dx + dy * dy + dz * dz;
  return sub_485690(v7);
}

//----- (00431A30) --------------------------------------------------------
// Normalize Vec3
double __cdecl sub_431A30(float *a1) {
  double result = sub_431940(a1);
  if (result >= 0.0001f) {
    a1[0] = a1[0] / result;
    a1[1] = a1[1] / result;
    a1[2] = a1[2] / result;
  }
  return result;
}

//----- (00431A70) --------------------------------------------------------
// Cross-Product of Vec3
float *__cdecl sub_431A70(float *a1, const float *a2, const float *a3) {
  a1[0] = a2[1] * a3[2] - a2[2] * a3[1];
  a1[1] = a2[2] * a3[0] - a2[0] * a3[2];
  a1[2] = a2[0] * a3[1] - a2[1] * a3[0];
  return a1;
}

//----- (00431AD0) --------------------------------------------------------
// Scale Vec3
const float* __cdecl sub_431AD0(float* a1, float a2, const float* a3) {
  a1[0] = a3[0] * a2;
  a1[1] = a3[1] * a2;
  a1[2] = a3[2] * a2;
  return a3;
}

//----- (00431B00) --------------------------------------------------------
// Scale one Vec3 and add another one
const float* __cdecl sub_431B00(float* a1, const float* a2, float a3, const float* a4) {
  a1[0] = a4[0] * a3 + a2[0];
  a1[1] = a4[1] * a3 + a2[1];
  a1[2] = a4[2] * a3 + a2[2];
  return a4;
}

//----- (00431B40) --------------------------------------------------------
// Scale 2 independent Vec3 and add them together
const float* __cdecl sub_431B40(float* a1, float a2, const float* a3, float a4, const float* a5) {
  a1[0] = a3[0] * a2 + a5[0] * a4;
  a1[1] = a3[1] * a2 + a5[1] * a4;
  a1[2] = a3[2] * a2 + a5[2] * a4;
  return a3;
}

//----- (00431B90) --------------------------------------------------------
// Set given row (column?) of Mat4 from Vec3 ?!
float* __cdecl sub_431B90(float* a1, int a2, const float* a3) {
  float* result = &a1[a2 * 4 + 0];
  result[0] = a3[0];
  result[1] = a3[1];
  result[2] = a3[2];
  return result;
}

//----- (00431BC0) --------------------------------------------------------
// Get given row (column?) of Mat4 to Vec3 ?!
float __cdecl sub_431BC0(const float* a1, int a2, float* a3) {
  float* v3 = &a1[a2 * 4 + 0];
  a3[0] = v3[0];
  a3[1] = v3[1];
  a3[2] = v3[2];
  return v3[2];
}

//----- (00431BF0) --------------------------------------------------------
// Copy Mat4 ?!
float* __cdecl sub_431BF0(float* a1, const float* a2) {
  for(int i = 0; i < 4; i++) {
    for(int j = 0; j < 4; j++) {
      a1[i * 4 + j] = a2[i * 4 + j];
    }
  }
  return a1;
}

//----- (00431C20) --------------------------------------------------------
// Multiply Mat4
float* __cdecl sub_431C20(float *a1, const float *a2, const float *a3) {

  // Make a copy of a2
  Mat4 a;
  for(unsigned int i = 0; i < 4 * 4; i++) {
     a.f[i] = a2[i];
  }

  // Make a copy of a3
  Mat4 b;
  for(unsigned int i = 0; i < 4 * 4; i++) {
     b.f[i] = a3[i];
  }

  // Multiply matrices
  for(int i = 0; i < 4; i++) {
    for(int j = 0; j < 4; j++) {
      a1[i * 4 + j] = b.f[0 * 4 + j] * a.f[i * 4 + 0] +
                      b.f[1 * 4 + j] * a.f[i * 4 + 1] + 
                      b.f[2 * 4 + j] * a.f[i * 4 + 2] + 
                      b.f[3 * 4 + j] * a.f[i * 4 + 3];
    }
  }

  return a1;
}

//----- (00432030) --------------------------------------------------------
// Multiply Mat4 inplace
float *__cdecl sub_432030(float *a1, const float *a2) {

  // Make a copy of a1
  Mat4 a;
  for(unsigned int i = 0; i < 4 * 4; i++) {
     a.f[i] = a1[i];
  }

  // Multiply matrices
  for(int i = 0; i < 4; i++) {
    for(int j = 0; j < 4; j++) {
      a1[i * 4 + j] = a.f[0 * 4 + j] * a2[i * 4 + 0] +
                      a.f[1 * 4 + j] * a2[i * 4 + 1] + 
                      a.f[2 * 4 + j] * a2[i * 4 + 2] + 
                      a.f[3 * 4 + j] * a2[i * 4 + 3];
    }
  }

  return a2;
}

//----- (004323C0) --------------------------------------------------------
float* __cdecl sub_4323C0(float* a1, const float *a2) {
  float v5; // edx
  double v6; // st4
  double v7; // rt2
  double v8; // st5
  double v11; // st7
  double v12; // st7
  double v13; // st2
  double v14; // st7
  float v15; // [esp+8h] [ebp+4h]
  float v17; // [esp+8h] [ebp+4h]
  float v18; // [esp+Ch] [ebp+8h]
  float v20; // [esp+Ch] [ebp+8h]

  //FIXME: This is a bit more complicated because a2 is still being read while a1 has been written.
  //       This means the order of operation suddenly becomes critical if regions in a1 and a2 overlap.

  // Get squared length
  float v19 = a2[0 * 4 + 0] * a2[0 * 4 + 0] +
              a2[0 * 4 + 1] * a2[0 * 4 + 1] +
              a2[0 * 4 + 2] * a2[0 * 4 + 2];
  double v3 = a2[1 * 4 + 0] * a2[1 * 4 + 0] +
              a2[1 * 4 + 1] * a2[1 * 4 + 1] +
              a2[1 * 4 + 2] * a2[1 * 4 + 2];
  float v16 = a2[2 * 4 + 0] * a2[2 * 4 + 0] +
              a2[2 * 4 + 1] * a2[2 * 4 + 1] +
              a2[2 * 4 + 2] * a2[2 * 4 + 2];

  // Can't trust a2 after this (might have been written):

  a1[0 * 4 + 1] = a2[1 * 4 + 0] / v3;
  a1[0 * 4 + 2] = a2[2 * 4 + 0] / v16;

  a1[1 * 4 + 2] = a2[2 * 4 + 1] / v16;


  a1[1 * 4 + 0] = a2[0 * 4 + 1] / v19;
  a1[2 * 4 + 0] = a2[0 * 4 + 2] / v19;

  a1[2 * 4 + 1] = a2[1 * 4 + 2] / v3;

  a1[0 * 4 + 0] = a2[0 * 4 + 0] / v19;

  a1[1 * 4 + 1] = a2[1 * 4 + 1] / v3;

  v11 = a2[2 * 4 + 2] / v16;

  a1[0 * 4 + 3] = 0.0f;
  a1[1 * 4 + 3] = 0.0f;
  a1[2 * 4 + 3] = 0.0f;
  a1[3 * 4 + 3] = 1.0f;

  a1[2 * 4 + 2] = v11;

  v20 = a2[3 * 4 + 0];
  v17 = a2[3 * 4 + 1];
  v12 = a2[3 * 4 + 2];

  v13 = v12 * a1[2 * 4 + 1];

  a1[3 * 4 + 0] = -(v17 * a1[1 * 4 + 0] + v12 * a1[2 * 4 + 0] + a1[0 * 4 + 0] * v20);
  v14 = -(v17 * a1[1 * 4 + 2] + v20 * a1[0 * 4 + 2] + v12 * a1[2 * 4 + 2]);

  a1[3 * 4 + 1] = -(v13 + v20 * a1[0 * 4 + 1] + v17 * a1[1 * 4 + 1];
  a1[3 * 4 + 2] = v14;
  return a1;
}

// [More matrix functions follow]
