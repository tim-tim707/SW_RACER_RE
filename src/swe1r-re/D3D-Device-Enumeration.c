int32_t sub_489DC0() {
  int result; // eax

  memset(&unk_52D570, 0, 0x300u);
  memset(&unk_52D870, 0, 0xDA0u);

  dword_52E638 = sub_489260();
  if ( dword_52E638 == 0) {
    return 0;
  }

  // Get IDirect3D3
  if (dword_52E638->QueryInterface(&unk_4AF278, &dword_52E640) ) {
    return 0;
  }

  // Set number of devices to 0 and then start counting them
  dword_52D56C = 0;
  if (dword_52E640->EnumDevices(sub_48B540, 0) ) {
    return 0;
  }

  // If no devices are found, we can't return anything
  if ( dword_52D56C == 0) {
    return 0;
  }

  // Otherwise mark that we have a device and return success
  dword_52E64C = 1;
  return 1;
}
HRESULT __stdcall sub_48B540(GUID FAR *lpGuid, LPSTR lpDeviceDescription, LPSTR lpDeviceName, LPD3DDEVICEDESC a, LPD3DDEVICEDESC b, LPVOID* user) {
  int v7; // ebp
  _DWORD *v8; // edx
  int v9; // edx
  unsigned int v10; // eax
  int v11; // ebx
  int v12; // ecx
  BOOL v13; // ecx
  int v14; // eax
  int v15; // edx
  int v16; // ecx
  int v17; // eax

  //FIXME: These 2 should be a single object
  uint8_t v18[676]; // [esp+10h] [ebp-2A4h]
  //int v19; // [esp+118h] [ebp-19Ch]
  uint32_t* v19 = &v18[264];

  // Must have device descs and GUID
  if ( !lpGuid || !a || !b ) {
    return 0;
  }

  // Make sure this is GUID {84E63DE0-46AA-11CF-816F-0000C020156E} (IDirect3DHALDevice)
  if ( !memcmp((const void *)lpGuid, &unk_4AF2D8, 0x10u) )
    return 1;

  // Only allow up to 4 devices
  if ( (unsigned int)dword_52D56C >= 4 ) {
    return 0;
  }

  // Get pointer to memory for this device info
  struct {
    uint8_t unk[28];
    uint32_t square_only_textures; // 28
    uint32_t min_texture_width; // 32
    uint32_t max_texture_height; // 36
    uint32_t min_texture_width; // 40
    uint32_t max_texture_height; // 44
    uint32_t max_vertex_count; // 48
    char name[128]; // 52
    char description[128]; // 180
    uint8_t unk1[8]; // 308
    D3DDEVICEDESC desc; // 316 [0xFC bytes] copied from A
    GUID guid; // 568
  }* v7; // 872 bytes in total
  v7 = 872 * dword_52D56C + 0x52D870;

  // Copy GUID
  v8 = (_DWORD *)(v7 + 568);
  *(_DWORD *)(v7 + 568) = *(_DWORD *)lpGuid;
  v8[1] = *(_DWORD *)(lpGuid + 4);
  v8[2] = *(_DWORD *)(lpGuid + 8);
  v8[3] = *(_DWORD *)(lpGuid + 12);

  // Copy device description
  strncpy((char *)(v7 + 180), lpDeviceDescription, 0x7Fu);
  *(_BYTE *)(v7 + 307) = 0;

  // Copy device name
  strncpy((char *)(v7 + 52), lpDeviceName, 0x7Fu);
  *(_BYTE *)(v7 + 179) = 0;

  v9 = *(_DWORD *)(a + 4);
  *(_DWORD *)v7 = (v9 != 0);
  if ( v9 == 0) {
    return 1;
  }

  qmemcpy((void *)(v7 + 316), (const void *)a, 0xFCu);

  // Retrieve some object of sorts
  if ( sub_4880C0(&v18) ) {
    return 0;
  }

  if ( !*v19 && !*(_DWORD *)v7 ) {
    return 1;
  }


  v11 = v7->desc.dwDeviceZBufferBitDepth;
  *(_DWORD *)(v7 + 8) = v11 != 0;

  v10 = v7->desc.dpcTriCaps.dwTextureCaps;
  *(_DWORD *)(v7 + 4) = v10 & D3DPTEXTURECAPS_PERSPECTIVE;
  *(_DWORD *)(v7 + 16) = v10 & D3DPTEXTURECAPS_ALPHA;
  *(_DWORD *)(v7 + 12) = v10 & D3DPTEXTURECAPS_TRANSPARENCY;
  *(_DWORD *)(v7 + 28) = v10 & D3DPTEXTURECAPS_SQUAREONLY;

  v12 = v7->desc.dpcTriCaps.dwShadeCaps;
  *(_DWORD *)(v7 + 20) = !(v12 & D3DPSHADECAPS_ALPHAFLATBLEND) && (v12 & D3DPSHADECAPS_ALPHAFLATSTIPPLED );

  v13 = (v7->desc.dpcTriCaps.dwTextureBlendCaps & D3DPTBLENDCAPS_MODULATEALPHA) && (v12 & D3DPSHADECAPS_ALPHAGOURAUDBLEND) || *(_DWORD *)(v7 + 20);
  *(_DWORD *)(v7 + 24) = v13;



  // Check if this device has a minimum / maximum height set
  v14 = v7->desc.dwMinTextureWidth;
  v15 = v7->desc.dwMinTextureHeight;
  v17 = v7->desc.dwMaxTextureWidth;
  v16 = v7->desc.dwMaxTextureHeight;
  if ( v14 ) {
    // Set minimum width, height
    *(_DWORD *)(v7 + 32) = v14;
    *(_DWORD *)(v7 + 36) = v15;

    // Set maximum width, height
    *(_DWORD *)(v7 + 40) = v17;
    *(_DWORD *)(v7 + 44) = v16;
  } else {
    // Set minimum width, height
    *(_DWORD *)(v7 + 32) = 16;
    *(_DWORD *)(v7 + 36) = 16;
    // Set maximum width, height
    *(_DWORD *)(v7 + 40) = 256;
    *(_DWORD *)(v7 + 44) = 256;
  }

  // Get maximum vertexcount
  *(_DWORD *)(v7 + 48) = v7->desc.dwMaxVertexCount;

  // Increment device count / index
  dword_52D56C++;

  return 1;
}
signed int __cdecl sub_4880C0(void *a1) {
  if (dword_52D444 == 0) {
    return 1;
  }
  qmemcpy(a1, (const void *)(0x52A9F8 + 676 * dword_529514), 676);
  return 0;
}
