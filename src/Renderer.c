// a1 = fovY
// a2 = aspectRatio
// a3 = znear
// a4 = zfar
int __cdecl sub_48B260(float a1, float a2, float a3, float a4)
{
    // zrange
    float v11 = a4 - a3;
    if (fabs(v11) < 0.01f)
        return 0x80070057;

    // First part of cotangent
    float v7 = sin(a1 * 0.5f);
    if (fabs(v7) < 0.01f)
        return 0x80070057;

    // Get cot(fovY/2)
    float v8 = cos(a1 * 0.5f) / v7;

    // Prepare the matrix
    float m[4 * 4]; // v12
    memset(m, 0x00, sizeof(m));
    m[0] = a2 * v8; // xScale = aspectRatio * cot(fovY/2)
    m[5] = v8; // yScale = cot(fovY/2)
    m[10] = a4 / v11; // zf/(zf-zn)
    m[11] = 1.0f;
    m[14] = -(m[10] * a3); // -zn*zf/(zf-zn)

    // Set D3D projection matrix
    return dword_52E644->SetTransform(D3DTS_PROJECTION, m);
}
typedef struct
{
    ... uint32_t unk; // +124 alphamodulate rendering flag
    ... struct
    {
        ... DIRECT3DTEXTURE2 *d3d_texture; // +128
    } * unk; // +144 ; v13
} Texture

    typedef struct
{
    uint32_t rendering_flags; // [0]
    uint32_t color_blending_mode; // [1] ???
    uint32_t vertex_count; // [2]
    uint32_t unk3;
    [3] struct
    {
        float x;
        float y;
        float z;
    } * positions; // [4]
    struct
    {
        float u;
        float v;
    } * uvs; // [5]
    struct
    {
        float r;
        float g;
        float b;
        float a;
    } * colors; // [6]
    Texture *texture; // v10
    uint32_t unk8;
    float r; // [9]
    float g; // [10]
    float b; // [11]
    float a; // [12] ???
    uint32_t unk13;
    float u_offset; // [14]
    float v_offset; // [15]
} Model;
// a1 number of models
// a2 array of input models
void __cdecl sub_48DF30(uint32_t a1, Model *a2)
{
    int v5; // ecx
    int v6; // ecx
    int v7; // ecx
    int v8; // ecx
    int v9; // eax
    int v11; // ecx
    int v13; // edi
    unsigned int v15; // ecx
    unsigned int v17; // ebx
    int v18; // edx
    double v21; // st7
    float v22; // ST2C_4
    bool v25; // zf
    double v26; // st7
    signed int v32; // edx
    float v33; // ST4C_4
    float v37; // ST4C_4
    float v41; // ST4C_4
    int v44; // edx
    unsigned int v45; // edx
    float v46; // ST44_4
    char v49; // dl
    float v50; // ST44_4
    signed int v53; // edi
    float v54; // ST44_4
    unsigned int v57; // eax
    int v58; // edi
    signed __int16 v59; // dx
    _WORD *v60; // eax
    int v61; // eax
    unsigned int v62; // ebx
    int v65; // [esp+10h] [ebp-58h]
    __int16 v67; // [esp+18h] [ebp-50h]
    unsigned int v68; // [esp+1Ch] [ebp-4Ch]
    signed __int16 v69; // [esp+1Ch] [ebp-4Ch]
    int v71; // [esp+20h] [ebp-48h]
    signed int v72; // [esp+24h] [ebp-44h]
    signed __int16 v74; // [esp+2Ch] [ebp-3Ch]
    int v76; // [esp+30h] [ebp-38h]
    int v77; // [esp+34h] [ebp-34h]
    int v78; // [esp+38h] [ebp-30h]
    int v79; // [esp+3Ch] [ebp-2Ch]
    unsigned int v80; // [esp+40h] [ebp-28h]
    int v81; // [esp+44h] [ebp-24h]
    int v82; // [esp+48h] [ebp-20h]
    int v83; // [esp+4Ch] [ebp-1Ch]
    float v84; // [esp+50h] [ebp-18h]
    float v85; // [esp+54h] [ebp-14h]
    float v86; // [esp+58h] [ebp-10h]
    int v87; // [esp+5Ch] [ebp-Ch]
    int v88; // [esp+60h] [ebp-8h]
    int v89; // [esp+64h] [ebp-4h]
    int v90; // [esp+74h] [ebp+Ch]

    typedef struct
    {
        uint8_t unk[56];
        float fov_y; // 56
        uint32_t unk; // 60
        float aspect_ratio; // 64
        uint32_t unkb; // 68
        struct
        {
            uint32_t unk; // 0
            float near; // 4
            float far; // 8
        } * zrange; // 72
    }; // dword_DF7F2C

    // Setup D3D projection matrix
    sub_48B260(*(float *)(dword_DF7F2C + 56), *(float *)(dword_DF7F2C + 64),
               *(float *)(*(_DWORD *)(dword_DF7F2C + 72) + 4),
               *(float *)(*(_DWORD *)(dword_DF7F2C + 72) + 8));

    sub_49EA00();

    Model *v3 = a2;

    for (int v80 = 0; v80 < a1; v80++)
    {
        uint32_t v4 = v3[0];

        v90 = 0x13;
        if (v4 & 0x2)
        {
            v90 |= 0x200;
        }
        if (v4 & 0x4)
        {
            v90 |= 0x800;
        }
        if (v4 & 0x8)
        {
            v90 |= 0x1000;
        }
        if (!(v4 & 0x10))
        {
            v90 |= 0x80;
        }
        if (v4 & 0x20)
        {
            v90 |= 0x2000;
        }
        if (v4 & 0x300)
        {
            v90 |= 0x8000;
        }

        // Setup texture if there is one
        Texture *v10 = v3[7];
        if (v10)
        {
            v11 = *(_DWORD *)(v10 + 124);
            if (v11)
            {
                v90 |= 0x400;
            }
            v13 = *(_DWORD *)(v10 + 144);
            sub_48E5F0(v13, v11);
            v65 = *(_DWORD *)(v13 + 128);
        }
        else
        {
            v65 = 0;
        }

        v15 = 0;
        v83 = 0;
        dword_A530D0 = 0;
        dword_5430C0 = *(_DWORD *)(*(_DWORD *)(dword_DF7F2C + 72) + 4);
        while (1)
        {
            v68 = *((_DWORD *)v3 + 2);
            dword_5430C4 = *((_DWORD *)v3 + 4);
            dword_AF30DC = *((_DWORD *)v3 + 6);
            v67 = v15;

            // Check if the wanted color blending mode works?
            v72 = *((_DWORD *)v3 + 1);
            if (v72 >= dword_ECC424)
            {
                v72 = dword_ECC424;
            }

            for (v17 = 0; v17 < v68; v17++)
            {
                struct
                {
                    float x;
                    float y;
                    float z;
                } *v18 = &dword_5430C4[v17];

                struct
                {
                    float r;
                    float g;
                    float b;
                    float a;
                } *v19 = &dword_AF30DC[v17];

                // Generate output address (v15 = vertex index, 32 = stride)
                struct
                {
                    float x; // 0
                    float y; // 4
                    float z; // 8
                    float rhw; // 12
                    uint32_t color1; // 16
                    uint32_t color2; // 20
                    float u; // 24
                    float v; // 28
                } *v20 = &unk_B6B0E8[v15]; // unk_B6B0E8 is of the outputvertex
                                           // type too

                // Copy X and Y
                v20->x = v18->x;
                v20->y = v18->y;

                // Generate RHW
                if (v18->z == 0.0)
                {
                    v21 = 0.0;
                }
                else
                {
                    v21 = inverse(v18->z);
                }

                // Copy Z and RHW
                if (v18->z == *(float *)&dword_5430C0)
                {
                    v20->z = 0.0;
                }
                else
                {
                    v20->z = 1.0 - v21 * *(float *)&dword_5430C0;
                }
                v20->rhw = v21;

                // Distance fading of objects or fog emulation?
                if (v4 & 0x200)
                {
                    if (v18->z > *(float *)&flt_EC8578)
                    {
                        if (v18->z < *(float *)&flt_EC857C)
                        {
                            v22 = (1.0
                                   - (v18->z - *(float *)&flt_EC8578)
                                       * flt_EC8574);
                            v79 = frndint(v22 * 255.0f);
                            v20->color2 = (v79 << 24) | 0xFFFFFF;
                        }
                        else
                        {
                            v20->color2 = 0x00FFFFFF;
                        }
                    }
                    else
                    {
                        v20->color2 = 0xFFFFFFFF;
                    }
                }

                if (v72 <= 0)
                {
                    v84 = 1.0f;
                    v85 = 1.0f;
                    v86 = 1.0f;
                }
                else
                {
                    v86 = v19->r;
                    v85 = v19->g;
                    v84 = v19->b;
                }
                v26 = v19->a;

                if (v72 == 3)
                {
                    v86 += v3[9];
                    v85 += v3[10];
                    v84 += v3[11];
                    if (v3[12] != 1.0f)
                    {
                        v26 += v3[12];
                    }
                }

                // Clamp colors
                v86 = min(v86, 1.0f);
                v85 = min(v85, 1.0f);
                v84 = min(v84, 1.0f);
                v26 = min(v26, 1.0f);

                // Convert colors from float to integer
                v88 = frndint(v86 * 255.0f);
                v82 = frndint(v85 * 255.0f);
                v78 = frndint(v84 * 255.0f);
                if (v4 & 2)
                {
                    v89 = frndint(v26 * 255.0f);
                }
                else
                {
                    v89 = 0xFF;
                }

                // Create actual color
                v20->color1 = (v89 << 24) | (v88 << 16) | (v82 << 8) | v78;

                // Copy UV
                v20->u = *(float *)(*((_DWORD *)v3 + 5) + 8 * v17 + 0) + v3[14];
                v20->v = *(float *)(*((_DWORD *)v3 + 5) + 8 * v17 + 4) + v3[15];

                // Generate next index
                v15 = ++dword_A530D0;
            }

            v57 = v3[2];
            if (v57 <= 3)
            {
                // Emit indices for triangle
                word_AF30E8[v83++] = v67 + 0;
                word_AF30E8[v83++] = v67 + 1;
                word_AF30E8[v83++] = v67 + 2;
            }
            else
            {
                v59 = 0;
                v74 = 1;
                v69 = v57 - 1;

                for (int32_t v76 = 0; v76 < (v57 - 2); v76++)
                {
                    word_AF30E8[v83++] = v67 + v59;
                    word_AF30E8[v83++] = v67 + v74;
                    word_AF30E8[v83++] = v67 + v69;
                    if (v76 & 1)
                    {
                        v59 = v69--;
                    }
                    else
                    {
                        v59 = v74++;
                    }
                }
            }

            // Get vertexcount of next object.
            // FIXME: I have a gut feeling these checks are in wrong, wtf IDA or
            // MSVC compiler
            v61 = v3[16 + 2];

            // Check if there is enough space in the index or vertexbuffer
            // FIXME: index_count + 3 * (next_vertex_count - 2)
            if ((v83 + 3 * (v61 - 2)) >= (unsigned int)dword_52E624)
            {
                break;
            }

            // Check if the next object exists, if not, just draw queued objects
            // FIXME: Related to gut feeling above.. shouldn't this be checked
            // first?
            if (v62 >= (v80 + 1))
            {
                break;
            }

            // Go to next object
            v3 += 16;

            // If the next object has a different texture or renderstates, draw
            // the queued objects
            if ((v10 != v3[7]) || (v4 != v3[0]))
            {
                break;
            }
        }

        // Do the drawing
        sub_48A350(v65, v90, (int)&unk_B6B0E8, v15, (int)word_AF30E8, v83);
    }

    return;
}
// a1 = texture
// a2 = renderstates
// a3 = vertex pointer
// a4 = vertex count
// a5 = index pointer
// a6 = index count
void __cdecl sub_48A350(int a1, int a2, int a3, unsigned int a4, int a5, int a6)
{
    // Check if we are below the maximum vertex count
    // FIXME: Not 100% sure
    if (a4 > dword_52E624)
    {
        return;
    }

    // Prepare renderstates
    sub_48A450(a2);

    // Check if the planned texture is already set, if not, set it
    if (dword_52E628 != a1)
    {
        if (dword_52E644->SetTexture(0, a1) == 0)
        {
            // Update the current texture
            dword_52E628 = a1;
        }
    }

    // Draw the data
    dword_52E644->DrawIndexedPrimitive(4, 452, a3, a4, a5, a6, 24);

    return;
}
// a1 = the renderstates to set
void __cdecl sub_48A450(int a1)
{
    // Don't worry if all states are already set correctly
    if (dword_52E610 == a1)
    {
        return;
    }

    if ((dword_52E610 ^ a1) & 0x600)
    {
        if (a1 & 0x400)
        {
            dword_52E644->SetRenderState(D3DRENDERSTATE_ALPHABLENDENABLE, 1);
            dword_52E644->SetRenderState(D3DRENDERSTATE_TEXTUREMAPBLEND,
                                         D3DTBLEND_MODULATEALPHA);
        }
        else if (a1 & 0x200)
        {
            dword_52E644->SetRenderState(D3DRENDERSTATE_ALPHABLENDENABLE, 1);
            dword_52E644->SetRenderState(D3DRENDERSTATE_TEXTUREMAPBLEND,
                                         D3DTBLEND_MODULATE);
        }
        else
        {
            dword_52E644->SetRenderState(D3DRENDERSTATE_ALPHABLENDENABLE, 0);
        }
    }

    if ((dword_52E610 ^ a1) & 0x2000)
    {
        if (a1 & 0x2000)
        {
            dword_52E644->SetRenderState(D3DRENDERSTATE_ZWRITEENABLE, 0);
        }
        else
        {
            dword_52E644->SetRenderState(D3DRENDERSTATE_ZWRITEENABLE, 1);
        }
    }

    if ((dword_52E610 ^ a1) & 0x800)
    {
        if (a1 & 0x800)
        {
            dword_52E644->SetTextureStageState(0, D3DTSS_ADDRESSU,
                                               D3DTADDRESS_CLAMP);
        }
        else
        {
            dword_52E644->SetTextureStageState(0, D3DTSS_ADDRESSU,
                                               D3DTADDRESS_WRAP);
        }
    }

    if ((dword_52E610 ^ a1) & 0x1000)
    {
        if (a1 & 0x1000)
        {
            dword_52E644->SetTextureStageState(0, D3DTSS_ADDRESSV,
                                               D3DTADDRESS_CLAMP);
        }
        else
        {
            dword_52E644->SetTextureStageState(0, D3DTSS_ADDRESSV,
                                               D3DTADDRESS_WRAP);
        }
    }

    if ((dword_52E610 ^ a1) & 0x8000) != 0 )
        {
            if (a1 & 0x8000 && dword_4C98B0)
            {
                dword_52E644->SetRenderState(D3DRENDERSTATE_FOGENABLE, 1);
            }
            else
            {
                dword_52E644->SetRenderState(D3DRENDERSTATE_FOGENABLE, 0);
            }
        }

    // Setup texture interpolation (keeps mipmap filter unchanged as
    // dword_52E614 is the current state)
    if ((dword_52E610 ^ a1) & 0x80) != 0)
        {
            dword_52E610 = a1;
            if ((sub_48B1B0(dword_52E614) != 0))
            {
                return;
            }
        }

    // Update the internal state tracker
    dword_52E610 = a1

        return;
}
// a1 = mipmap filter
// Depends on the current renderstate in dword_52E610 being set!
// returns D3D error code / success
int __cdecl sub_48B1B0(int a1)
{
    int result; // eax

    if ((dword_52E610 & 0x80) != 0)
    {
        result = dword_52E644->SetTextureStageState(0, D3DTSS_MAGFILTER,
                                                    D3DTFG_LINEAR);
        if (result)
        {
            return result;
        }

        result = dword_52E644->SetTextureStageState(0, D3DTSS_MINFILTER,
                                                    D3DTFN_LINEAR);
        if (result)
        {
            return result;
        }
    }
    else
    {
        result = dword_52E644->SetTextureStageState(0, D3DTSS_MAGFILTER,
                                                    D3DTFG_POINT);
        if (result)
        {
            return result;
        }

        result = dword_52E644->SetTextureStageState(0, D3DTSS_MINFILTER,
                                                    D3DTFN_POINT);
        if (result)
        {
            return result;
        }
    }

    // Update internal mipmap filter state tracker
    dword_52E614 = a1;

    if (a1 == 1)
    {
        return dword_52E644->SetTextureStageState(0, D3DTSS_MIPFILTER,
                                                  D3DTFP_POINT);
    }
    if (a1 == 2)
    {
        return dword_52E644->SetRenderState(D3DRENDERSTATE_TEXTUREMIN,
                                            D3DFILTER_MIPNEAREST);
    }
    return dword_52E644->SetTextureStageState(0, D3DTSS_MIPFILTER, D3DTFP_NONE);
}
