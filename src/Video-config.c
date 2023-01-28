//----- (00408880) --------------------------------------------------------
signed int __cdecl sub_408880(int a1)
{
    char v8[32]; // [esp+0h] [ebp-140h]
    char v9[32]; // [esp+20h] [ebp-120h]

    char v10[256]; // [esp+40h] [ebp-100h]
    sprintf(&v10, aSSS, aDataConfig, a1, aVideoCfg);
    if (!sub_4877D0(&v10))
    {
        sub_487960();
        return -1;
    }

    sprintf(&v9, aVideo);
    if (sub_4879F0(aSSettings, &v9))
    {
        goto HandleError;
    }

    sprintf(&v8, aReflectionsS, dword_EC86A0 ? "ON" : "OFF");
    if (sub_4879F0(a28s28s, &v9, &v8))
    {
        goto HandleError;
    }

    sprintf(&v8, aZeffectsS, dword_EC86A4 ? "ON" : "OFF");
    if (sub_4879F0(a28s28s, &v9, &v8))
    {
        goto HandleError;
    }

    sprintf(&v8, aDynamicLightin_0, dword_EC86A8 ? "ON" : "OFF");
    if (sub_4879F0(a28s28s, &v9, &v8))
    {
        goto HandleError;
    }

    sprintf(&v8, aVsyncS, dword_EC86AC ? "ON" : "OFF");
    if (sub_4879F0(a28s28s, &v9, &v8))
    {
        goto HandleError;
    }

    sprintf(&v8, aLensflareS, dword_EC86B0 ? "ON" : "OFF");
    if (sub_4879F0(a28s28s, &v9, &v8))
    {
        goto HandleError;
    }

    sprintf(&v8, aEngineexhaustS, dword_EC86B4 ? "ON" : "OFF");
  if ( sub_4879F0(a28s28s, &v9, &v8) {
        goto HandleError;
  }

  sprintf(&v8, aTextureResI, dword_EC86B8);
  if (sub_4879F0(a28s28s, &v9, &v8)) {
        goto HandleError;
  }

  sprintf(&v8, aModelDetailI, dword_EC86BC);
  if (sub_4879F0(a28s28s, &v9, &v8)) {
        goto HandleError;
  }

  sprintf(&v8, aDrawdistanceI, dword_EC86C0);
  if (sub_4879F0(a28s28s, &v9, &v8)) {
        goto HandleError;
  }

  if (sub_4879A0(aEnd_0) ) {
        goto HandleError;
  }

  sub_487960();
  return 1;

HandleError:
  sub_487960();
  return 0;
}
