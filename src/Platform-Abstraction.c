// debugapi.h // DebugBreak
// winuser.h // MessageBoxA

//----- (0048C3D0) --------------------------------------------------------
typedef struct
{
    float unkf0;
    uint32_t unk1;
    uint32_t unk2;
    uint32_t unk3;
    uint32_t unk4;
    uint32_t unk5;
    uint32_t unk6;
    uint32_t unk7;
    uint32_t unk8;
    uint32_t unk9;
    uint32_t unk10;
    uint32_t unk11;
    uint32_t unk12;
    uint32_t unk13;
    uint32_t unk14;
    uint32_t unk15;
    uint32_t unk16;
    uint32_t unk17;
    uint32_t unk18;
    uint32_t unk19;
    uint32_t unk20;
    uint32_t unk21;
    uint32_t unk22;
    uint32_t unk23;
    uint32_t unk24;
    uint32_t unk25;
    uint32_t unk26;
    uint32_t unk27;
} A1;

// a1 = Pointer to some kind of vtable?
// Probably void, but might return a1
void __cdecl load_platform_abstraction(A1 *a1)
{
    a1->unk2 = debugprintf; // debugprintf(fmt, ...)
    a1->unk1 = debugprintf; // debugprintf(fmt, ...)
    a1->unk3 = debugprintf; // debugprintf(fmt, ...)
    a1->unk4 = debugprintf; // debugprintf(fmt, ...)
    a1->unkf0 = 1000.0f; // Maybe some kind of version identifier? (Dz\0\0 when
                         // read as ascii)
    a1->unk5 = 0;
    a1->unk6 = dump_exit; // print_assert(char* message, char* file, int line)
    a1->unk7 = 0;
    a1->unk8 = sub_48D7E0; // FIXME: maybe some kind of malloc() ???
    a1->unk9 =
        sub_48D9A0; // FIXME: maybe some kind of free() ? prints "Attempting to
                    // dispose a bogus or already-disposed-of block!"
    a1->unk10 = sub_48DA80; // FIXME: Something like realloc() ???
    a1->unk11 = timeGetTime; // Retrieves the system time, in milliseconds
    a1->unk12 = platform_fopen; // fopen
    a1->unk13 = platform_fclose; // fclose
    a1->unk14 = platform_fread; // readfile(FILE *a1, void *buffer, size_t size)
                                // //FIXME: Confirm signature
    a1->unk15 = platform_fgets; // fgets(a2, a3, a1);
    a1->unk16 =
        platform_fwrite; // writefile(FILE *a1, void *buffer, size_t size)
    a1->unk17 = feof;
    a1->unk18 = platform_ftell; // ftell()
    a1->unk19 = platform_fseek; // fseek()
    a1->unk20 = go_to_eof; // FIXME: ???
    a1->unk21 = platform_fprintf; // fprintf() up to 0x800 bytes
    a1->unk22 = platform_fgetws; // fgetws(a2, a3, a1);
    a1->unk23 = sub_48C5A0;
    a1->unk24 = sub_48C5B0;
    a1->unk25 = sub_48C5C0;
    a1->unk26 = platform_identity; // int f(int x) { return x; }
    a1->unk27 = nullsub_1; //
}

//----- (0048C4A0) --------------------------------------------------------
// a1 = presumably condition / message
// a2 = presumably path
// a3 = presumably line number
void __cdecl __noreturn dump_exit(char *a1, char *a2, int32_t a3)
{
    // FIXME: Check if debugger is on?
    if (dword_52EE58)
    {
        DebugBreak(); // debugapi.h
        exit_0(1);
    }

    dword_52EE58 = 1;

    // Search for the last backslash so we can isolate the filename
    int32_t v5 = 0;
    int32_t v4 = 0;
    int32_t v3 = 0;
    while (a2[v5] != '\0')
    {
        if (a2[v5] == '\\')
        {
            v4 = 1;
            v3 = v5;
        }
        v5++;
    }

    // If we found the last backslash, advance v3 to point behind it
    if (v4)
    {
        v3++;
    }

    // Do a debug print and open a messagebox
    CHAR Text[0x200]; // [esp+Ch] [ebp-200h]
    _snprintf(&Text, 0x200u, aSDS, &a2[v3], a3, a1);
    dword_ECC420->unk4(aAssertS, &Text);
    MessageBoxA(0, &Text, aAssertHandler, MB_TASKMODAL); // winuser.h

    DebugBreak();
    exit_0(1);
}

//----- (0048C570) --------------------------------------------------------
int debugprintf(char *a1, ...)
{
    va_list va; // [esp+8h] [ebp+8h]
    va_start(va, a1);
    _vsnprintf(OutputString, 0x800u, a1, va);
    OutputDebugStringA(OutputString);
    return 1;
}

//----- (0048C5E0) --------------------------------------------------------
// FIXME: Figure out what this might have been used for
int __cdecl platform_identity(int a1)
{
    return a1;
}

//----- (0048C5F0) --------------------------------------------------------
FILE *__cdecl platform_fopen(char *a1, char *a2)
{
    return fopen(a1, a2);
}

//----- (0048C610) --------------------------------------------------------
int __cdecl platform_fclose(FILE *a1)
{
    fclose(a1);
    return 0;
}

//----- (0048C620) --------------------------------------------------------
size_t __cdecl platform_fread(FILE *a1, void *a2, size_t a3)
{
    return fread_locked(a2, 1u, a3, a1);
}

//----- (0048C640) --------------------------------------------------------
size_t __cdecl platform_fwrite(FILE *a1, void *a2, size_t a3)
{
    return fwrite_locked(a2, 1u, a3, a1);
}

//----- (0048C660) --------------------------------------------------------
char *__cdecl platform_fgets(FILE *a1, char *a2, int a3)
{
    return fgets(a2, a3, a1);
}

//----- (0048C680) --------------------------------------------------------
// FIXME: Rarely seen wchar here.. is this correct?
wchar_t *__cdecl platform_fgetws(FILE *a1, wchar_t *a2, int a3)
{
    return fgetws(a2, a3, a1);
}

//----- (0048C6B0) --------------------------------------------------------
int __cdecl platform_ftell(FILE *a1)
{
    return ftell(a1);
}

//----- (0048C6C0) --------------------------------------------------------
int __cdecl platform_fseek(FILE *stream, int offset, int whence)
{
    return fseek(stream, offset, whence);
}

//----- (0048C6E0) --------------------------------------------------------
// go to end of file ?
FILE *__cdecl go_to_eof(char *a1)
{
    FILE *result; // eax
    FILE *v2; // esi
    FILE *v3; // edi

    result = platform_fopen(a1, aRb);
    v2 = result;
    if (result)
    {
        platform_fseek(result, 0, SEEK_END);
        v3 = (FILE *)platform_ftell(v2);
        platform_fclose(v2);
        result = v3;
    }
    return result;
}

//----- (0048C730) --------------------------------------------------------
int platform_fprintf(FILE *a1, char *a2, ...)
{
    va_list va; // [esp+Ch] [ebp+Ch]
    va_start(va, a2);
    int32_t v2 = _vsnprintf(byte_52E658, 0x800u, a2, va);
    platform_fwrite(a1, byte_52E658, v2);
    return 0;
}
