//----- (00422440) --------------------------------------------------------
signed int __cdecl parse_audio_config(int a1)
{
    char v2; // [esp+Ch] [ebp-100h]

    if (!dword_4EB450)
    {
        return 1;
    }

    sprintf(&v2, aSSS, aDataConfig, a1, aAudioCfg);
    if (!file_access_fopen(&v2))
    {
        file_access_close();
        return -1;
    }

    while (read_line_unk())
    {
        // Wait for EOF marker
        if (!strcmp(dword_EC8E84, aEnd))
        {
            break;
        }

        // Parse an audio argument
        if (!_strcmpi(dword_EC8E84, aAudio))
        {
            if (!_strcmpi(dword_EC8E8C, aHires))
            {
                dword_4B6D14 = _strcmpi(dword_EC8E90, aOn) == 0;
            }
            else if (!_strcmpi(dword_EC8E8C, off_4B74D0))
            {
                dword_4B6D20 = _strcmpi(dword_EC8E90, aOn) == 0;
            }
            else if (!_strcmpi(dword_EC8E8C, a3d))
            {
                dword_50D550 = _strcmpi(dword_EC8E90, aOn) == 0;
            }
            else if (!_strcmpi(dword_EC8E8C, aDoppler))
            {
                dword_4B6D18 = _strcmpi(dword_EC8E90, aOn) == 0;
            }
            else if (!_strcmpi(dword_EC8E8C, aGainmatch))
            {
                dword_4B6D24 = atof(dword_EC8E90);
                sub_484D40(dword_4B6D24);
            }
            else if (!_strcmpi(dword_EC8E8C, aVoice))
            {
                dword_4B6D28 = _strcmpi(dword_EC8E90, aOn) == 0;
            }
            else if (!_strcmpi(dword_EC8E8C, aMusic))
            {
                dword_4EB45C = _strcmpi(dword_EC8E90, aOn) == 0;
            }
        }
    }
    file_access_close();

    return 1;
}

//----- (00484D40) --------------------------------------------------------
void __cdecl sub_484D40(float a1)
{
    if (a1 < 0.0f)
    {
        flt_4C7D7C = 0.0f;
    }
    else if (a1 > 10.0f)
    {
        flt_4C7D7C = 10.0f;
    }
    else
    {
        flt_4C7D7C = a1;
    }
    return;
}

//----- (004848A0) --------------------------------------------------------
signed int sub_4848A0()
{
    // Check if we already have a A3D instance
    if (dword_50D548)
    {
        return 0;
    }

    // Load A3D COM module
    sub_49E940();

    // Presumably creates A3D instance
    HRESULT v1 = sub_49E970(0, &dword_50D548, 0, 128);
    if (v1 >= 0 && dword_50D548)
    {
        dword_50D550 = 1;
    }
    else
    {
        dword_4C7D80 = 0;
        dword_50D550 = 0;
        if (v1 < 0)
        {
            dword_50D548 = 0;
            return 0;
        }
    }

    // dword_50D548 is A3d4*
    // dword_50D520 is A3DCAPS_HARDWARE
    dword_50D520.dwSize = 36; // sizeof(A3DCAPS_HARDWARE)
    dword_50D548->GetHardwareCaps(&dword_50D520);
    dword_50D55C = dword_50D520.dwFlags
        & (A3D_DIRECT_PATH_GENERIC | A3D_DIRECT_PATH_A3D); // Check & 0x28
    dword_50D554 = dword_50D520.dwFlags & A3D_1ST_REFLECTIONS; // Check & 0x2

    int v2 = get_hwnd();
    if (dword_50D548->SetCooperativeLevel(v2, 1) < 0)
    {
        dword_50D548->Release();
        dword_50D548 = 0;
        return 0;
    }

    dword_50D548->SetCoordinateSystem(0);
    dword_50D548->SetNumFallbackSources(8);
    dword_50D548->GetOutputGain(&unk_50D544);

    sub_484A80(dword_4C7D70);

    if (dword_50D550)
    {
        if (dword_50D548->QueryInterface(&unk_4AE158, &dword_50D560) < 0)
        {
            dword_4C7D80 = 0;
            dword_50D550 = 0;
            dword_50D560 = 0;
            return 1;
        }
        dword_50D548->SetUnitsPerMeter(
            3.28f); // Game uses feet as unit (encoded as 0x4051EB85)
        dword_50D548->SetDistanceModelScale(LODWORD(flt_4C7D78));
        dword_50D548->SetDopplerScale(LODWORD(flt_4C7D74));
    }

    return 1;
}

//----- (0049E940) --------------------------------------------------------
HRESULT sub_49E940()
{
    HRESULT v0 = CoInitialize(0);
    sub_49E750();
    return v0;
}

//----- (0049E750) --------------------------------------------------------
int sub_49E750()
{
    sub_49E8E0(off_4D1D5C, &Class, aA3dObject);
    sub_49E8E0(aA3dClsid, &Class, aD8f1eee0F63411);
    sub_49E8E0(aClsidD8f1eee0F, &Class, aA3dObject);
    sub_49E8E0(aClsidD8f1eee0F_0, &Class, aA3dDll);
    sub_49E8E0(aClsidD8f1eee0F_0, aThreadingmodel, aApartment);

    sub_49E8E0(aA3dapi, &Class, aA3dapiObject);
    sub_49E8E0(aA3dapiClsid, &Class, a92fa2c24253c11);
    sub_49E8E0(aClsid92fa2c242, &Class, aA3dapiObject);
    sub_49E8E0(aClsid92fa2c242, aAppid, a92fa2c24253c11_0);
    sub_49E8E0(aClsid92fa2c242_0, &Class, aA3dapiDll);
    sub_49E8E0(aClsid92fa2c242_0, aThreadingmodel, aApartment);

    sub_49E8E0(aA3ddal, &Class, aA3ddalObject);
    sub_49E8E0(aA3ddalClsid, &Class, a442d12a1264111);
    sub_49E8E0(aClsid442d12a12, &Class, aA3ddalObject);
    sub_49E8E0(aClsid442d12a12, aAppid, a442d12a1264111_0);
    sub_49E8E0(aClsid442d12a12_0, &Class, aA3dDll);
    sub_49E8E0(aClsid442d12a12_0, aThreadingmodel, aApartment);

    return 0;
}

//----- (0049E8E0) --------------------------------------------------------
LSTATUS __cdecl sub_49E8E0(LPCSTR lpSubKey, LPCSTR lpValueName, BYTE *lpData)
{
    DWORD dwDisposition; // [esp+4h] [ebp-4h]
    RegCreateKeyExA(HKEY_CLASSES_ROOT, lpSubKey, 0, aRegSz, 0, 0xF003Fu, 0,
                    (PHKEY)&lpSubKey, &dwDisposition);
    RegSetValueExA((HKEY)lpSubKey, lpValueName, 0, 1u, lpData,
                   strlen((const char *)lpData));
    return RegCloseKey((HKEY)lpSubKey);
}

//----- (0049E970) --------------------------------------------------------
HRESULT __cdecl sub_49E970(LPGUID a1, IA3d4 **a2, LPUNKNOWN pUnkOuter, DWORD a4)
{
    // Check for required argument and clear it
    if (a2 == 0)
    {
        return 0x80070057;
    }
    *a2 = 0;

    // Load A3D COM module
    sub_49E940();

    // Create the A3D instance
    LPVOID ppv = 0; // [esp+10h] [ebp-4h]
    HRESULT result =
        CoCreateInstance(&stru_4AE0E8, pUnkOuter, 1u, &stru_4AE128, &ppv);
    if (result < 0)
    {
        return result;
    }

    // Make sure we got a pointer to the instance
    if (ppv == 0)
    {
        return 0x80004005;
    }

    // FIXME: ???
    if (ppv->Init(a1, a4, 0) < 0)
    {
        ppv->Release();
        return 0x80004005;
    }

    // Writeback pointer to the instance and return with success
    *a2 = ppv;
    return 0;
}

//----- (00484A80) --------------------------------------------------------
void __cdecl sub_484A80(float a1)
{
    if (dword_50D548)
    {
        dword_50D548->SetOutputGain(a1);
    }
    return;
}

//----- (00484D90) --------------------------------------------------------
int __cdecl sub_484D90(A3dSource *a1, float a2)
{
    if (!dword_50D548)
    {
        return dword_50D548;
    }

    // Check if this is a native source and fixup the volume
    if (sub_485040(a1) & A3DSOURCE_RENDERMODE_NATIVE)
    {
        a2 *= flt_4C7D7C;
    }

    return a1->SetGain(a2);
}

//----- (00485040) --------------------------------------------------------
int __cdecl sub_485040(A3dSource *a1)
{
    DWORD v4 = -1; // [esp+8h] [ebp-4h]
    a1->GetRenderMode(&v4);
    return v4;
}

//----- (00484E10) --------------------------------------------------------
int __cdecl sub_484E10(A3dSource *a1, const float *a2)
{
    return a1->SetPosition3f(a2[0], a2[2], -a2[1]);
}
