// a1 = angle in degrees
// Returns the wrapped angle [0.0; 360.0[ in degrees
float __cdecl sub_48C830(float a1)
{
    float result;

    if (a1 >= 0.0)
    {
        // If it's already a good angle, we can just return it
        if (a1 < 360.0)
        {
            return a1;
        }

        // Wrap around
        result = a1 - sub_48C8F0(a1 / 360.0) * 360.0;
    }
    else
    {
        float positive_angle = -a1;
        if (positive_angle >= 360.0)
        {
            // Wrap around
            result = 360.0
                - (positive_angle - sub_48C8F0(positive_angle / 360.0) * 360.0);
        }
        else
        {
            result = 360.0 - positive_angle;
        }
    }

    if (result == 360.0)
    {
        result = 0.0;
    }
    return result;
}
float __cdecl sub_48C8F0(float a1)
{
    return _frndint(a1);
}
// a1 = angle in degrees
// Returns angle in range ]-180.0;180.0] where input / output angles are:
//    0.0 ~>    0.0
//  180.0 ~>  180.0
//  180.1 ~> -179.9
//  359.9 ~>   -0.1
//  360.0 ~>    0.0
float __cdecl sub_48C910(float a1)
{
    float angle = sub_48C830(a1);
    if (angle > 180.0)
    {
        angle = -(360.0 - angle);
    }
    return angle;
}
// same as 48C8F0 but returns int
int __cdecl sub_48CD30(float a1)
{
    return _frndint(a1);
}
// a1 = angle in degree
// a2 = sin (?) for angle
// a3 = cos (?) for angle
// Very similar to sub_48CD50 (which does the same for sin (?) only)
void __cdecl sub_48C950(float a1, float *a2, float *a3)
{
    float angle = sub_48C830(a1);

    // Figure out which quadrant this angle belongs to
    int quadrant;
    if (angle < 90.0)
    {
        quadrant = 0;
    }
    else if (angle < 180.0)
    {
        quadrant = 1;
    }
    else if (angle < 270.0)
    {
        quadrant = 2;
    }
    else
    {
        quadrant = 3;
    }

    // Get angle for index and the delta to the closest integer
    float angle_index = angle * 45.511112; // (4096 * 4) / 360 = 45.511112
    float delta = angle_index - sub_48C8F0(angle_index);
    int index0 = sub_48CD30(angle_index);
    int index1 = index0 + 1;

    switch (quadrant)
    {
    case 0:

        if (index1 >= 0x1000)
        {
            index1 -= 0x1000;
        v24 = dword_4C98E8[0xFFF - index1]);
        v25 = -dword_4C98E8[index1];
        }
        else
        {
        v24 = dword_4C98E8[index1]);
        v25 = dword_4C98E8[0xFFF - index1];
        }

        float a = dword_4C98E8[index0];
        *a2 = (v24 - a) * delta + a;

        float b = dword_4C98E8[0xFFF - index0];
        *a3 = (v25 - b) * delta + b;

        break;

    case 1:

        index0 -= 0x1000;
        index1 -= 0x1000;

        if (index1 >= 0x1000)
        {
            index1 -= 0x1000;
            v26 = -dword_4C98E8[index1];
            v9 = -dword_4C98E8[0xFFF - index1];
        }
        else
        {
            v26 = dword_4C98E8[0xFFF - index1];
            v9 = -dword_4C98E8[index1];
        }

        float a = dword_4C98E8[0xFFF - index0]; // sin
        *a2 = (v26 - a) * delta + a;

        float b = -dword_4C98E8[index0];
        *a3 = (v9 - b) * delta + b;

        break;

    case 2:

        index0 -= 0x2000;
        index1 -= 0x2000;

        if (index1 >= 0x1000)
        {
            index1 -= 0x1000;
            v12 = -dword_4C98E8[0xFFF - index1]; // sin
            v27 = dword_4C98E8[index1];
        }
        else
        {
            v12 = -dword_4C98E8[index1];
            v27 = -dword_4C98E8[0xFFF - index1]; // sin
        }

        float a = -dword_4C98E8[index0];
        *a2 = (v12 - a) * delta + a;

        float b = -dword_4C98E8[0xFFF - index0]; // sin
        *a3 = (v27 - b) * delta + b;

        break;

    case 3:

        index0 -= 0x3000;
        index1 -= 0x3000;

        if (index1 >= 0x1000)
        {
            index1 -= 0x1000;
            v28 = dword_4C98E8[index1];
            v29 = dword_4C98E8[0xFFF - index1]; // sin
        }
        else
        {
            v28 = -dword_4C98E8[0xFFF - index1]; // sin
            v29 = dword_4C98E8[index1];
        }

      float a = -dword_4C98E8[0xFFF - index0)]; // sin
      *a2 = (v28 - a) * delta + a;

      float b = dword_4C98E8[index0];
      *a3 = (v29 - b) * delta + b;

      break;

    default:
        break;
    }
}
