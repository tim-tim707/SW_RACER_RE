#ifndef RDCLIP_H
#define RDCLIP_H

#include "types.h"

#define rdClip_Line2_ADDR (0x00494980)
#define rdClip_CalcOutcode2_ADDR (0x00494c20)
#define rdClip_Face3W_ADDR (0x00494c60)
#define rdClip_Face3WOrtho_ADDR (0x00495600)
#define rdClip_Face3S_ADDR (0x00495d50)
#define rdClip_Face3SOrtho_ADDR (0x004966f0)
#define rdClip_Face3GS_ADDR (0x00496e40)
#define rdClip_Face3GSOrtho_ADDR (0x00497da0)
#define rdClip_Face3GT_ADDR (0x00498a60)
#define rdClip_Face3GTOrtho_ADDR (0x00499840)
#define rdClip_Face3T_ADDR (0x0049a390)
#define rdClip_Face3TOrtho_ADDR (0x0049b7d0)

int rdClip_Line2(rdCanvas* canvas, int* pX1, int* pY1, int* pX2, int* pY2);
int rdClip_CalcOutcode2(rdCanvas* canvas, int x, int y);
int rdClip_Face3W(rdClipFrustum* pFrustrum, rdVector3* aVertices, int numVertices);
int rdClip_Face3WOrtho(rdClipFrustum* pFrustrum, rdVector3* aVertices, int numVertices);
int rdClip_Face3S(rdClipFrustum* pFrustrum, rdVector3* aVertices, int numVertices);
int rdClip_Face3SOrtho(rdClipFrustum* pFrustum, rdVector3* aVertices, int numVertices);
int rdClip_Face3GS(rdClipFrustum* pFrustrum, rdVector3* aVertices, rdVector4* aIntensities, int numVertices);
int rdClip_Face3GSOrtho(rdClipFrustum* pFrustum, rdVector3* aVertices, rdVector4* aIntensities, int numVertices);
int rdClip_Face3GT(rdClipFrustum* pFrustrum, rdVector3* aVertices, rdVector2* aTexVertices, int numVertices);
int rdClip_Face3GTOrtho(rdClipFrustum* pFrustrum, rdVector3* aVertices, rdVector2* aTexVertices, int numVertices);
int rdClip_Face3T(rdClipFrustum* pFrustrum, rdVector3* aVertices, rdVector2* aTexVertices, rdVector4* aIntensities, int numVertices);
int rdClip_Face3TOrtho(rdClipFrustum* pFrustum, rdVector3* aVertices, rdVector2* aTexVertices, rdVector4* aIntensities, int numVertices);

#endif // RDCLIP_H
