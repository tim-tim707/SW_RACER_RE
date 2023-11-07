#ifndef SWRSPLINE_H
#define SWRSPLINE_H

#define swrSpline_LoadSpline_ADDR (0x00446fc0)

#define swrSpline_LoadSplineById_ADDR (0x004472e0)

void swrSpline_LoadSpline(int index, unsigned short** b);

char* swrSpline_LoadSplineById(char* splineBuffer);

#endif // SWRSPLINE_H
