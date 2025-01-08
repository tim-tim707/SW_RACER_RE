#include "rdClip.h"

#include <macros.h>
#include <math.h>

// 0x00494980
int rdClip_Line2(rdCanvas* canvas, int* pX1, int* pY1, int* pX2, int* pY2)
{
    unsigned int clipOutcodeX1Y1;
    signed int clipOutcodeX2Y2;
    signed int fY1_same_fY2;
    unsigned int clipCode;
    double x_clipped;
    double y_clipped;
    float fY1;
    float fX2;
    float fY2;
    float fX1;

    clipOutcodeX1Y1 = rdClip_CalcOutcode2(canvas, *pX1, *pY1);
    clipOutcodeX2Y2 = rdClip_CalcOutcode2(canvas, *pX2, *pY2);

    fX1 = (double)*pX1;
    fX2 = (double)*pX2;
    fY1 = (double)*pY1;
    fY2 = (double)*pY2;

    if (!(clipOutcodeX1Y1 | clipOutcodeX2Y2))
        return 1;

    if (clipOutcodeX2Y2 & clipOutcodeX1Y1)
        return 0;

    while (1)
    {
        if (!(clipOutcodeX1Y1 | clipOutcodeX2Y2))
            break;

        if (clipOutcodeX2Y2 & clipOutcodeX1Y1)
            return 0;

        clipCode = clipOutcodeX1Y1;
        if (!clipOutcodeX1Y1)
            clipCode = clipOutcodeX2Y2;

        if (clipCode & CLIP_TOP)
        {
            x_clipped = (fY2 == fY1) ? fX1 : (fX2 - fX1) / (fY2 - fY1) * ((double)canvas->yStart - fY1) + fX1;
            y_clipped = (double)canvas->yStart;
        }
        else if (clipCode & CLIP_BOTTOM)
        {
            x_clipped = (fY2 == fY1) ? fX1 : (fX2 - fX1) / (fY2 - fY1) * ((double)canvas->heightMinusOne - fY1) + fX1;
            y_clipped = (double)canvas->heightMinusOne;
        }
        else if (clipCode & CLIP_RIGHT)
        {
            x_clipped = (double)canvas->widthMinusOne;
            y_clipped = (fX2 == fX1) ? fY1 : (fY2 - fY1) / (fX2 - fX1) * ((double)canvas->widthMinusOne - fX1) + fY1;
        }
        else if (clipCode & CLIP_LEFT)
        {
            x_clipped = (double)canvas->xStart;
            y_clipped = (fX2 == fX1) ? fY1 : (float)((fY2 - fY1) / (fX2 - fX1) * ((double)canvas->xStart - fX1) + fY1);
        }

        if (clipCode == clipOutcodeX1Y1)
        {
            fX1 = x_clipped;
            fY1 = y_clipped;
            clipOutcodeX1Y1 = rdClip_CalcOutcode2(canvas, round(x_clipped), round(y_clipped));
        }
        else
        {
            fX2 = x_clipped;
            fY2 = y_clipped;
            clipOutcodeX2Y2 = rdClip_CalcOutcode2(canvas, round(x_clipped), round(y_clipped));
        }
    }

    *pX1 = round(fX1);
    *pY1 = round(fY1);
    *pX2 = round(fX2);
    *pY2 = round(fY2);
    return 1;
}

// 0x00494c20
int rdClip_CalcOutcode2(rdCanvas* canvas, int x, int y)
{
    int result = 0;

    if (x > canvas->widthMinusOne)
        result |= CLIP_RIGHT;
    else if (x < canvas->xStart)
        result |= CLIP_LEFT;

    if (y < canvas->yStart)
        result |= CLIP_TOP;
    else if (y > canvas->heightMinusOne)
        result |= CLIP_BOTTOM;

    return result;
}

// 0x00494c60
int rdClip_Face3W(rdClipFrustum* pFrustrum, rdVector3* aVertices, int numVertices)
{
    HANG("TODO");
}

// 0x00495600
int rdClip_Face3WOrtho(rdClipFrustum* pFrustrum, rdVector3* aVertices, int numVertices)
{
    HANG("TODO");
}

// 0x00495d50
int rdClip_Face3S(rdClipFrustum* pFrustrum, rdVector3* aVertices, int numVertices)
{
    HANG("TODO");
}

// 0x004966f0
int rdClip_Face3SOrtho(rdClipFrustum* pFrustum, rdVector3* aVertices, int numVertices)
{
    HANG("TODO");
}

// 0x00496e40
int rdClip_Face3GS(rdClipFrustum* pFrustrum, rdVector3* aVertices, rdVector4* aIntensities, int numVertices)
{
    HANG("TODO");
}

// 0x00497da0
int rdClip_Face3GSOrtho(rdClipFrustum* pFrustum, rdVector3* aVertices, rdVector4* aIntensities, int numVertices)
{
    HANG("TODO");
}

// 0x00498a60
int rdClip_Face3GT(rdClipFrustum* pFrustrum, rdVector3* aVertices, rdVector2* aTexVertices, int numVertices)
{
    HANG("TODO");
}

// 0x00499840
int rdClip_Face3GTOrtho(rdClipFrustum* pFrustrum, rdVector3* aVertices, rdVector2* aTexVertices, int numVertices)
{
    HANG("TODO");
}

// 0x0049a390
int rdClip_Face3T(rdClipFrustum* pFrustrum, rdVector3* aVertices, rdVector2* aTexVertices, rdVector4* aIntensities, int numVertices)
{
    HANG("TODO");
}

// 0x0049b7d0
int rdClip_Face3TOrtho(rdClipFrustum* pFrustum, rdVector3* aVertices, rdVector2* aTexVertices, rdVector4* aIntensities, int numVertices)
{
    HANG("TODO");
}
