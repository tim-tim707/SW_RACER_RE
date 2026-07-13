#include "rdClip.h"

#include "globals.h"

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

// Clips a shaded (position-only) triangle against the perspective view frustum
// using Sutherland-Hodgman, ping-ponging between the caller's vertex array and
// rdClip_workVerts. Returns the clipped vertex count (< 3 means fully culled).
// 0x00495d50
int rdClip_Face3S(rdClipFrustum* pFrustrum, rdVector3* aVertices, int numVertices)
{
    rdVector3* pPrev;
    rdVector3* pCur;
    rdVector3* pDst;
    rdVector3* pSwap;
    int numIn;
    int numOut;
    int i;
    float prevBound;
    float curBound;
    float dR;
    float dC;
    float denom;
    float cross;
    float iC;
    float adR;
    float adC;
    float t;

    rdClip_faceStatus = 0;
    rdClip_pSrcVerts = aVertices;
    rdClip_pDstVerts = rdClip_workVerts;

    // ---- pass 1: rightPlane, clip x, keep x >= plane * y ----
    numOut = 0;
    if (numVertices > 0) {
        pDst = rdClip_pDstVerts;
        pPrev = rdClip_pSrcVerts + numVertices - 1;
        pCur = rdClip_pSrcVerts;
        i = numVertices;
        do {
            prevBound = pFrustrum->rightPlane * pPrev->y;
            curBound = pFrustrum->rightPlane * pCur->y;
            if (prevBound <= pPrev->x || curBound <= pCur->x) {
                if (pPrev->x != prevBound && pCur->x != curBound && (pPrev->x < prevBound || pCur->x < curBound)) {
                    dR = pCur->y - pPrev->y;
                    dC = pCur->x - pPrev->x;
                    denom = pFrustrum->rightPlane * dR - dC;
                    cross = pPrev->x * pCur->y - pPrev->y * pCur->x;
                    if (denom != 0.0) {
                        cross = cross / denom;
                    }
                    iC = pFrustrum->rightPlane * cross;
                    adR = dR < 0.0 ? -dR : dR;
                    adC = dC < 0.0 ? -dC : dC;
                    t = adR <= adC ? (iC - pPrev->x) / dC : (cross - pPrev->y) / dR;
                    pDst[numOut].x = iC;
                    pDst[numOut].y = cross;
                    pDst[numOut].z = (pCur->z - pPrev->z) * t + pPrev->z;
                    numOut++;
                    rdClip_faceStatus |= rdClip_FaceStatus_PLANE_A;
                }
                if (curBound <= pCur->x) {
                    pDst[numOut] = *pCur;
                    numOut++;
                }
            }
            pPrev = pCur;
            pCur++;
            i--;
        } while (i != 0);
    }
    if (numOut < 3) {
        return numOut;
    }
    pSwap = rdClip_pSrcVerts;
    rdClip_pSrcVerts = rdClip_pDstVerts;
    rdClip_pDstVerts = pSwap;

    // ---- pass 2: bottomPlane, clip x, keep x <= plane * y ----
    numIn = numOut;
    numOut = 0;
    pDst = rdClip_pDstVerts;
    pPrev = rdClip_pSrcVerts + numIn - 1;
    pCur = rdClip_pSrcVerts;
    i = numIn;
    do {
        prevBound = pFrustrum->bottomPlane * pPrev->y;
        curBound = pFrustrum->bottomPlane * pCur->y;
        if (pPrev->x <= prevBound || pCur->x <= curBound) {
            if (pPrev->x != prevBound && pCur->x != curBound && (prevBound < pPrev->x || curBound < pCur->x)) {
                dR = pCur->y - pPrev->y;
                dC = pCur->x - pPrev->x;
                denom = pFrustrum->bottomPlane * dR - dC;
                cross = pPrev->x * pCur->y - pPrev->y * pCur->x;
                if (denom != 0.0) {
                    cross = cross / denom;
                }
                iC = pFrustrum->bottomPlane * cross;
                adR = dR < 0.0 ? -dR : dR;
                adC = dC < 0.0 ? -dC : dC;
                t = adR <= adC ? (iC - pPrev->x) / dC : (cross - pPrev->y) / dR;
                pDst[numOut].x = iC;
                pDst[numOut].y = cross;
                pDst[numOut].z = (pCur->z - pPrev->z) * t + pPrev->z;
                numOut++;
                rdClip_faceStatus |= rdClip_FaceStatus_PLANE_B;
            }
            if (pCur->x <= curBound) {
                pDst[numOut] = *pCur;
                numOut++;
            }
        }
        pPrev = pCur;
        pCur++;
        i--;
    } while (i != 0);
    if (numOut < 3) {
        return numOut;
    }
    pSwap = rdClip_pSrcVerts;
    rdClip_pSrcVerts = rdClip_pDstVerts;
    rdClip_pDstVerts = pSwap;

    // ---- pass 3: leftPlane, clip z, keep z <= plane * y ----
    numIn = numOut;
    numOut = 0;
    pDst = rdClip_pDstVerts;
    pPrev = rdClip_pSrcVerts + numIn - 1;
    pCur = rdClip_pSrcVerts;
    i = numIn;
    do {
        prevBound = pFrustrum->leftPlane * pPrev->y;
        curBound = pFrustrum->leftPlane * pCur->y;
        if (pPrev->z <= prevBound || pCur->z <= curBound) {
            if (pPrev->z != prevBound && pCur->z != curBound && (prevBound < pPrev->z || curBound < pCur->z)) {
                dR = pCur->y - pPrev->y;
                dC = pCur->z - pPrev->z;
                denom = pFrustrum->leftPlane * dR - dC;
                cross = pPrev->z * pCur->y - pPrev->y * pCur->z;
                if (denom != 0.0) {
                    cross = cross / denom;
                }
                iC = pFrustrum->leftPlane * cross;
                adR = dR < 0.0 ? -dR : dR;
                adC = dC < 0.0 ? -dC : dC;
                t = adR <= adC ? (iC - pPrev->z) / dC : (cross - pPrev->y) / dR;
                pDst[numOut].x = (pCur->x - pPrev->x) * t + pPrev->x;
                pDst[numOut].y = cross;
                pDst[numOut].z = iC;
                numOut++;
                rdClip_faceStatus |= rdClip_FaceStatus_PLANE_C;
            }
            if (pCur->z <= curBound) {
                pDst[numOut] = *pCur;
                numOut++;
            }
        }
        pPrev = pCur;
        pCur++;
        i--;
    } while (i != 0);
    if (numOut < 3) {
        return numOut;
    }
    pSwap = rdClip_pSrcVerts;
    rdClip_pSrcVerts = rdClip_pDstVerts;
    rdClip_pDstVerts = pSwap;

    // ---- pass 4: orthoBottomPlane, clip z, keep z >= plane * y ----
    numIn = numOut;
    numOut = 0;
    pDst = rdClip_pDstVerts;
    pPrev = rdClip_pSrcVerts + numIn - 1;
    pCur = rdClip_pSrcVerts;
    i = numIn;
    do {
        prevBound = pFrustrum->orthoBottomPlane * pPrev->y;
        curBound = pFrustrum->orthoBottomPlane * pCur->y;
        if (prevBound <= pPrev->z || curBound <= pCur->z) {
            if (pPrev->z != prevBound && pCur->z != curBound && (pPrev->z < prevBound || pCur->z < curBound)) {
                dR = pCur->y - pPrev->y;
                dC = pCur->z - pPrev->z;
                denom = pFrustrum->orthoBottomPlane * dR - dC;
                cross = pPrev->z * pCur->y - pPrev->y * pCur->z;
                if (denom != 0.0) {
                    cross = cross / denom;
                }
                iC = pFrustrum->orthoBottomPlane * cross;
                adR = dR < 0.0 ? -dR : dR;
                adC = dC < 0.0 ? -dC : dC;
                t = adR <= adC ? (iC - pPrev->z) / dC : (cross - pPrev->y) / dR;
                pDst[numOut].x = (pCur->x - pPrev->x) * t + pPrev->x;
                pDst[numOut].y = cross;
                pDst[numOut].z = iC;
                numOut++;
                rdClip_faceStatus |= rdClip_FaceStatus_PLANE_D;
            }
            if (curBound <= pCur->z) {
                pDst[numOut] = *pCur;
                numOut++;
            }
        }
        pPrev = pCur;
        pCur++;
        i--;
    } while (i != 0);
    if (numOut < 3) {
        return numOut;
    }
    pSwap = rdClip_pSrcVerts;
    rdClip_pSrcVerts = rdClip_pDstVerts;
    rdClip_pDstVerts = pSwap;

    // ---- pass 5: zNear, clip y against constant, keep y >= zNear ----
    numIn = numOut;
    numOut = 0;
    pDst = rdClip_pDstVerts;
    pPrev = rdClip_pSrcVerts + numIn - 1;
    pCur = rdClip_pSrcVerts;
    i = numIn;
    do {
        if (pFrustrum->zNear <= pPrev->y || pFrustrum->zNear <= pCur->y) {
            if (pPrev->y != pFrustrum->zNear && pCur->y != pFrustrum->zNear && (pPrev->y < pFrustrum->zNear || pCur->y < pFrustrum->zNear)) {
                t = (pFrustrum->zNear - pPrev->y) / (pCur->y - pPrev->y);
                pDst[numOut].y = pFrustrum->zNear;
                pDst[numOut].z = (pCur->z - pPrev->z) * t + pPrev->z;
                pDst[numOut].x = (pCur->x - pPrev->x) * t + pPrev->x;
                numOut++;
                rdClip_faceStatus |= rdClip_FaceStatus_NEARZ;
            }
            if (pFrustrum->zNear <= pCur->y) {
                pDst[numOut] = *pCur;
                numOut++;
            }
        }
        pPrev = pCur;
        pCur++;
        i--;
    } while (i != 0);
    if (numOut < 3) {
        rdClip_faceStatus |= rdClip_FaceStatus_DEGENERATE;
        return numOut;
    }

    // ---- pass 6: zFar, clip y against constant, keep y <= zFar (only if far clip enabled) ----
    if (pFrustrum->bFarClip != 0) {
        pSwap = rdClip_pSrcVerts;
        rdClip_pSrcVerts = rdClip_pDstVerts;
        rdClip_pDstVerts = pSwap;

        numIn = numOut;
        numOut = 0;
        pDst = rdClip_pDstVerts;
        pPrev = rdClip_pSrcVerts + numIn - 1;
        pCur = rdClip_pSrcVerts;
        i = numIn;
        do {
            if (pPrev->y <= pFrustrum->zFar || pCur->y <= pFrustrum->zFar) {
                if (pPrev->y != pFrustrum->zFar && pCur->y != pFrustrum->zFar && (pFrustrum->zFar < pPrev->y || pFrustrum->zFar < pCur->y)) {
                    t = (pFrustrum->zFar - pPrev->y) / (pCur->y - pPrev->y);
                    pDst[numOut].y = pFrustrum->zFar;
                    pDst[numOut].z = (pCur->z - pPrev->z) * t + pPrev->z;
                    pDst[numOut].x = (pCur->x - pPrev->x) * t + pPrev->x;
                    numOut++;
                    rdClip_faceStatus |= rdClip_FaceStatus_FARZ;
                }
                if (pCur->y <= pFrustrum->zFar) {
                    pDst[numOut] = *pCur;
                    numOut++;
                }
            }
            pPrev = pCur;
            pCur++;
            i--;
        } while (i != 0);
        if (numOut < 3) {
            return numOut;
        }
    }

    if (rdClip_pDstVerts != aVertices) {
        for (i = 0; i < numOut; i++) {
            aVertices[i] = rdClip_pDstVerts[i];
        }
    }
    return numOut;
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

// Clips a textured, per-vertex-lit triangle against the orthographic view box
// (Sutherland-Hodgman), interpolating position, UVs and intensities at each
// crossing. Ping-pongs the three attribute streams between the caller's arrays
// and the rdClip work buffers. Returns the clipped vertex count (< 3 = culled).
// 0x0049b7d0
int rdClip_Face3TOrtho(rdClipFrustum* pFrustum, rdVector3* aVertices, rdVector2* aTexVertices, rdVector4* aIntensities, int numVertices)
{
    rdVector3* pPrev;
    rdVector3* pCur;
    rdVector3* pDst;
    rdVector3* pSwapV;
    rdVector2* pPrevTex;
    rdVector2* pCurTex;
    rdVector2* pDstTex;
    rdVector2* pSwapT;
    rdVector4* pPrevInt;
    rdVector4* pCurInt;
    rdVector4* pDstInt;
    rdVector4* pSwapI;
    int numIn;
    int numOut;
    int i;
    float plane;
    float t;

    rdClip_faceStatus = 0;
    rdClip_pSrcVerts = aVertices;
    rdClip_pDstVerts = rdClip_workVerts;
    rdClip_pSrcTexVerts = aTexVertices;
    rdClip_pDstTexVerts = rdClip_workTexVerts;
    rdClip_pSrcIntensities = aIntensities;
    rdClip_pDstIntensities = rdClip_workIntensities;

    // ---- pass 1: nearPlane, clip x, keep x >= nearPlane ----
    numOut = 0;
    plane = pFrustum->nearPlane;
    if (numVertices > 0) {
        pDst = rdClip_pDstVerts;
        pDstTex = rdClip_pDstTexVerts;
        pDstInt = rdClip_pDstIntensities;
        pPrev = rdClip_pSrcVerts + numVertices - 1;
        pCur = rdClip_pSrcVerts;
        pPrevTex = rdClip_pSrcTexVerts + numVertices - 1;
        pCurTex = rdClip_pSrcTexVerts;
        pPrevInt = rdClip_pSrcIntensities + numVertices - 1;
        pCurInt = rdClip_pSrcIntensities;
        i = numVertices;
        do {
            if (plane <= pPrev->x || plane <= pCur->x) {
                if (pPrev->x != plane && pCur->x != plane && (pPrev->x < plane || pCur->x < plane)) {
                    t = (plane - pPrev->x) / (pCur->x - pPrev->x);
                    pDst[numOut].x = plane;
                    pDst[numOut].y = (pCur->y - pPrev->y) * t + pPrev->y;
                    pDst[numOut].z = (pCur->z - pPrev->z) * t + pPrev->z;
                    pDstTex[numOut].x = (pCurTex->x - pPrevTex->x) * t + pPrevTex->x;
                    pDstTex[numOut].y = (pCurTex->y - pPrevTex->y) * t + pPrevTex->y;
                    pDstInt[numOut].x = (pCurInt->x - pPrevInt->x) * t + pPrevInt->x;
                    pDstInt[numOut].y = (pCurInt->y - pPrevInt->y) * t + pPrevInt->y;
                    pDstInt[numOut].z = (pCurInt->z - pPrevInt->z) * t + pPrevInt->z;
                    numOut++;
                    rdClip_faceStatus |= rdClip_FaceStatus_PLANE_A;
                }
                if (plane <= pCur->x) {
                    pDst[numOut] = *pCur;
                    pDstTex[numOut] = *pCurTex;
                    pDstInt[numOut] = *pCurInt;
                    numOut++;
                }
            }
            pPrev = pCur;
            pCur++;
            pPrevTex = pCurTex;
            pCurTex++;
            pPrevInt = pCurInt;
            pCurInt++;
            i--;
        } while (i != 0);
    }
    if (numOut < 3) {
        return numOut;
    }
    pSwapV = rdClip_pSrcVerts;
    rdClip_pSrcVerts = rdClip_pDstVerts;
    rdClip_pDstVerts = pSwapV;
    pSwapT = rdClip_pSrcTexVerts;
    rdClip_pSrcTexVerts = rdClip_pDstTexVerts;
    rdClip_pDstTexVerts = pSwapT;
    pSwapI = rdClip_pSrcIntensities;
    rdClip_pSrcIntensities = rdClip_pDstIntensities;
    rdClip_pDstIntensities = pSwapI;

    // ---- pass 2: orthoLeftPlane, clip x, keep x <= orthoLeftPlane ----
    numIn = numOut;
    numOut = 0;
    plane = pFrustum->orthoLeftPlane;
    pDst = rdClip_pDstVerts;
    pDstTex = rdClip_pDstTexVerts;
    pDstInt = rdClip_pDstIntensities;
    pPrev = rdClip_pSrcVerts + numIn - 1;
    pCur = rdClip_pSrcVerts;
    pPrevTex = rdClip_pSrcTexVerts + numIn - 1;
    pCurTex = rdClip_pSrcTexVerts;
    pPrevInt = rdClip_pSrcIntensities + numIn - 1;
    pCurInt = rdClip_pSrcIntensities;
    i = numIn;
    do {
        if (pPrev->x <= plane || pCur->x <= plane) {
            if (pPrev->x != plane && pCur->x != plane && (plane < pPrev->x || plane < pCur->x)) {
                t = (plane - pPrev->x) / (pCur->x - pPrev->x);
                pDst[numOut].x = plane;
                pDst[numOut].y = (pCur->y - pPrev->y) * t + pPrev->y;
                pDst[numOut].z = (pCur->z - pPrev->z) * t + pPrev->z;
                pDstTex[numOut].x = (pCurTex->x - pPrevTex->x) * t + pPrevTex->x;
                pDstTex[numOut].y = (pCurTex->y - pPrevTex->y) * t + pPrevTex->y;
                pDstInt[numOut].x = (pCurInt->x - pPrevInt->x) * t + pPrevInt->x;
                pDstInt[numOut].y = (pCurInt->y - pPrevInt->y) * t + pPrevInt->y;
                pDstInt[numOut].z = (pCurInt->z - pPrevInt->z) * t + pPrevInt->z;
                numOut++;
                rdClip_faceStatus |= rdClip_FaceStatus_PLANE_B;
            }
            if (pCur->x <= plane) {
                pDst[numOut] = *pCur;
                pDstTex[numOut] = *pCurTex;
                pDstInt[numOut] = *pCurInt;
                numOut++;
            }
        }
        pPrev = pCur;
        pCur++;
        pPrevTex = pCurTex;
        pCurTex++;
        pPrevInt = pCurInt;
        pCurInt++;
        i--;
    } while (i != 0);
    if (numOut < 3) {
        return numOut;
    }
    pSwapV = rdClip_pSrcVerts;
    rdClip_pSrcVerts = rdClip_pDstVerts;
    rdClip_pDstVerts = pSwapV;
    pSwapT = rdClip_pSrcTexVerts;
    rdClip_pSrcTexVerts = rdClip_pDstTexVerts;
    rdClip_pDstTexVerts = pSwapT;
    pSwapI = rdClip_pSrcIntensities;
    rdClip_pSrcIntensities = rdClip_pDstIntensities;
    rdClip_pDstIntensities = pSwapI;

    // ---- pass 3: farPlane, clip z, keep z <= farPlane ----
    numIn = numOut;
    numOut = 0;
    plane = pFrustum->farPlane;
    pDst = rdClip_pDstVerts;
    pDstTex = rdClip_pDstTexVerts;
    pDstInt = rdClip_pDstIntensities;
    pPrev = rdClip_pSrcVerts + numIn - 1;
    pCur = rdClip_pSrcVerts;
    pPrevTex = rdClip_pSrcTexVerts + numIn - 1;
    pCurTex = rdClip_pSrcTexVerts;
    pPrevInt = rdClip_pSrcIntensities + numIn - 1;
    pCurInt = rdClip_pSrcIntensities;
    i = numIn;
    do {
        if (pPrev->z <= plane || pCur->z <= plane) {
            if (pPrev->z != plane && pCur->z != plane && (plane < pPrev->z || plane < pCur->z)) {
                t = (plane - pPrev->z) / (pCur->z - pPrev->z);
                pDst[numOut].x = (pCur->x - pPrev->x) * t + pPrev->x;
                pDst[numOut].y = (pCur->y - pPrev->y) * t + pPrev->y;
                pDst[numOut].z = plane;
                pDstTex[numOut].x = (pCurTex->x - pPrevTex->x) * t + pPrevTex->x;
                pDstTex[numOut].y = (pCurTex->y - pPrevTex->y) * t + pPrevTex->y;
                pDstInt[numOut].x = (pCurInt->x - pPrevInt->x) * t + pPrevInt->x;
                pDstInt[numOut].y = (pCurInt->y - pPrevInt->y) * t + pPrevInt->y;
                pDstInt[numOut].z = (pCurInt->z - pPrevInt->z) * t + pPrevInt->z;
                numOut++;
                rdClip_faceStatus |= rdClip_FaceStatus_PLANE_C;
            }
            if (pCur->z <= plane) {
                pDst[numOut] = *pCur;
                pDstTex[numOut] = *pCurTex;
                pDstInt[numOut] = *pCurInt;
                numOut++;
            }
        }
        pPrev = pCur;
        pCur++;
        pPrevTex = pCurTex;
        pCurTex++;
        pPrevInt = pCurInt;
        pCurInt++;
        i--;
    } while (i != 0);
    if (numOut < 3) {
        return numOut;
    }
    pSwapV = rdClip_pSrcVerts;
    rdClip_pSrcVerts = rdClip_pDstVerts;
    rdClip_pDstVerts = pSwapV;
    pSwapT = rdClip_pSrcTexVerts;
    rdClip_pSrcTexVerts = rdClip_pDstTexVerts;
    rdClip_pDstTexVerts = pSwapT;
    pSwapI = rdClip_pSrcIntensities;
    rdClip_pSrcIntensities = rdClip_pDstIntensities;
    rdClip_pDstIntensities = pSwapI;

    // ---- pass 4: orthoTopPlane, clip z, keep z >= orthoTopPlane ----
    numIn = numOut;
    numOut = 0;
    plane = pFrustum->orthoTopPlane;
    pDst = rdClip_pDstVerts;
    pDstTex = rdClip_pDstTexVerts;
    pDstInt = rdClip_pDstIntensities;
    pPrev = rdClip_pSrcVerts + numIn - 1;
    pCur = rdClip_pSrcVerts;
    pPrevTex = rdClip_pSrcTexVerts + numIn - 1;
    pCurTex = rdClip_pSrcTexVerts;
    pPrevInt = rdClip_pSrcIntensities + numIn - 1;
    pCurInt = rdClip_pSrcIntensities;
    i = numIn;
    do {
        if (plane <= pPrev->z || plane <= pCur->z) {
            if (pPrev->z != plane && pCur->z != plane && (pPrev->z < plane || pCur->z < plane)) {
                t = (plane - pPrev->z) / (pCur->z - pPrev->z);
                pDst[numOut].x = (pCur->x - pPrev->x) * t + pPrev->x;
                pDst[numOut].y = (pCur->y - pPrev->y) * t + pPrev->y;
                pDst[numOut].z = plane;
                pDstTex[numOut].x = (pCurTex->x - pPrevTex->x) * t + pPrevTex->x;
                pDstTex[numOut].y = (pCurTex->y - pPrevTex->y) * t + pPrevTex->y;
                pDstInt[numOut].x = (pCurInt->x - pPrevInt->x) * t + pPrevInt->x;
                pDstInt[numOut].y = (pCurInt->y - pPrevInt->y) * t + pPrevInt->y;
                pDstInt[numOut].z = (pCurInt->z - pPrevInt->z) * t + pPrevInt->z;
                numOut++;
                rdClip_faceStatus |= rdClip_FaceStatus_PLANE_D;
            }
            if (plane <= pCur->z) {
                pDst[numOut] = *pCur;
                pDstTex[numOut] = *pCurTex;
                pDstInt[numOut] = *pCurInt;
                numOut++;
            }
        }
        pPrev = pCur;
        pCur++;
        pPrevTex = pCurTex;
        pCurTex++;
        pPrevInt = pCurInt;
        pCurInt++;
        i--;
    } while (i != 0);
    if (numOut < 3) {
        return numOut;
    }
    pSwapV = rdClip_pSrcVerts;
    rdClip_pSrcVerts = rdClip_pDstVerts;
    rdClip_pDstVerts = pSwapV;
    pSwapT = rdClip_pSrcTexVerts;
    rdClip_pSrcTexVerts = rdClip_pDstTexVerts;
    rdClip_pDstTexVerts = pSwapT;
    pSwapI = rdClip_pSrcIntensities;
    rdClip_pSrcIntensities = rdClip_pDstIntensities;
    rdClip_pDstIntensities = pSwapI;

    // ---- pass 5: zNear, clip y, keep y >= zNear ----
    numIn = numOut;
    numOut = 0;
    plane = pFrustum->zNear;
    pDst = rdClip_pDstVerts;
    pDstTex = rdClip_pDstTexVerts;
    pDstInt = rdClip_pDstIntensities;
    pPrev = rdClip_pSrcVerts + numIn - 1;
    pCur = rdClip_pSrcVerts;
    pPrevTex = rdClip_pSrcTexVerts + numIn - 1;
    pCurTex = rdClip_pSrcTexVerts;
    pPrevInt = rdClip_pSrcIntensities + numIn - 1;
    pCurInt = rdClip_pSrcIntensities;
    i = numIn;
    do {
        if (plane <= pPrev->y || plane <= pCur->y) {
            if (pPrev->y != plane && pCur->y != plane && (pPrev->y < plane || pCur->y < plane)) {
                t = (plane - pPrev->y) / (pCur->y - pPrev->y);
                pDst[numOut].y = plane;
                pDst[numOut].z = (pCur->z - pPrev->z) * t + pPrev->z;
                pDst[numOut].x = (pCur->x - pPrev->x) * t + pPrev->x;
                pDstTex[numOut].x = (pCurTex->x - pPrevTex->x) * t + pPrevTex->x;
                pDstTex[numOut].y = (pCurTex->y - pPrevTex->y) * t + pPrevTex->y;
                // NOTE: faithful to the original - the zNear pass interpolates the
                // intensity y/z deltas against prevInt.x (not .y/.z). This is a bug
                // in the shipped game, isolated to this pass; kept for byte fidelity.
                pDstInt[numOut].x = (pCurInt->x - pPrevInt->x) * t + pPrevInt->x;
                pDstInt[numOut].y = (pCurInt->y - pPrevInt->x) * t + pPrevInt->y;
                pDstInt[numOut].z = (pCurInt->z - pPrevInt->x) * t + pPrevInt->z;
                numOut++;
                rdClip_faceStatus |= rdClip_FaceStatus_NEARZ;
            }
            if (plane <= pCur->y) {
                pDst[numOut] = *pCur;
                pDstTex[numOut] = *pCurTex;
                pDstInt[numOut] = *pCurInt;
                numOut++;
            }
        }
        pPrev = pCur;
        pCur++;
        pPrevTex = pCurTex;
        pCurTex++;
        pPrevInt = pCurInt;
        pCurInt++;
        i--;
    } while (i != 0);
    if (numOut < 3) {
        rdClip_faceStatus |= rdClip_FaceStatus_DEGENERATE;
        return numOut;
    }

    // ---- pass 6: zFar, clip y, keep y <= zFar (only if far clip enabled) ----
    if (pFrustum->bFarClip != 0) {
        pSwapV = rdClip_pSrcVerts;
        rdClip_pSrcVerts = rdClip_pDstVerts;
        rdClip_pDstVerts = pSwapV;
        pSwapT = rdClip_pSrcTexVerts;
        rdClip_pSrcTexVerts = rdClip_pDstTexVerts;
        rdClip_pDstTexVerts = pSwapT;
        pSwapI = rdClip_pSrcIntensities;
        rdClip_pSrcIntensities = rdClip_pDstIntensities;
        rdClip_pDstIntensities = pSwapI;

        numIn = numOut;
        numOut = 0;
        plane = pFrustum->zFar;
        pDst = rdClip_pDstVerts;
        pDstTex = rdClip_pDstTexVerts;
        pDstInt = rdClip_pDstIntensities;
        pPrev = rdClip_pSrcVerts + numIn - 1;
        pCur = rdClip_pSrcVerts;
        pPrevTex = rdClip_pSrcTexVerts + numIn - 1;
        pCurTex = rdClip_pSrcTexVerts;
        pPrevInt = rdClip_pSrcIntensities + numIn - 1;
        pCurInt = rdClip_pSrcIntensities;
        i = numIn;
        do {
            if (pPrev->y <= plane || pCur->y <= plane) {
                if (pPrev->y != plane && pCur->y != plane && (plane < pPrev->y || plane < pCur->y)) {
                    t = (plane - pPrev->y) / (pCur->y - pPrev->y);
                    pDst[numOut].y = plane;
                    pDst[numOut].z = (pCur->z - pPrev->z) * t + pPrev->z;
                    pDst[numOut].x = (pCur->x - pPrev->x) * t + pPrev->x;
                    pDstTex[numOut].x = (pCurTex->x - pPrevTex->x) * t + pPrevTex->x;
                    pDstTex[numOut].y = (pCurTex->y - pPrevTex->y) * t + pPrevTex->y;
                    pDstInt[numOut].x = (pCurInt->x - pPrevInt->x) * t + pPrevInt->x;
                    pDstInt[numOut].y = (pCurInt->y - pPrevInt->y) * t + pPrevInt->y;
                    pDstInt[numOut].z = (pCurInt->z - pPrevInt->z) * t + pPrevInt->z;
                    numOut++;
                    rdClip_faceStatus |= rdClip_FaceStatus_FARZ;
                }
                if (pCur->y <= plane) {
                    pDst[numOut] = *pCur;
                    pDstTex[numOut] = *pCurTex;
                    pDstInt[numOut] = *pCurInt;
                    numOut++;
                }
            }
            pPrev = pCur;
            pCur++;
            pPrevTex = pCurTex;
            pCurTex++;
            pPrevInt = pCurInt;
            pCurInt++;
            i--;
        } while (i != 0);
        if (numOut < 3) {
            return numOut;
        }
    }

    if (rdClip_pDstVerts != aVertices) {
        for (i = 0; i < numOut; i++) {
            aVertices[i] = rdClip_pDstVerts[i];
            aTexVertices[i] = rdClip_pDstTexVerts[i];
            aIntensities[i] = rdClip_pDstIntensities[i];
        }
    }
    return numOut;
}
