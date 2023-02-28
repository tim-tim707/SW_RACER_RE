//----- (004846E0) --------------------------------------------------------
// a1 = output string
// a2 = output buffer length
// a3 = path name
// a4 = filename
char *__cdecl contruct_path(char *a1, int a2, char *a3, char *a4)
{
    // Copy the path and ensure that the buffer is zero terminated
    strncpy(a1, a3, a2 - 1);
    a1[a2 - 1] = 0;

    // Append the filename to the path
    return _contruct_path(a1, a4, a2);
}

//----- (00484690) --------------------------------------------------------
// a1 = output buffer which holds path
// a2 = filename to concatenate
// a3 = output buffer length
char *__cdecl _contruct_path(char *a1, char *a2, int a3)
{
    // Check if the last symbol is already a path seperator
    uint32_t v4 = strlen(a1);
    if (a1[v4 - 1] != '\\')
    {
        // Now check if there is at least one byte space in the buffer left.
        // FIXME: the check for *a1 is a bit late, isn't it?! we are already out
        // of bounds if a1 is ""
        int32_t v3 = v4;
        if ((v3 < (a3 - 1)) && (*a1 != '\0'))
        {
            // Append a path seperator
            a1[v3] = '\\';
            v3++;
            a1[v3] = '\0';
        }
    }

    // Now append the filename and return the constructed path
    strncat(a1, a2, a3 - v3 - 1);
    return a1;
}

typdef struct
{
    uint32_t unk0; // +0 = search mode (0 = ?, 1 = only files, 2 = only
                   // directories, 3 = ?)
    uint32_t unk1; // +4 = index of file in directory?
    char path[128] // +8 = path
        intptr_t handle; // +136 = filesearch handle
    // 140 byte total
} FileSearch;

typdef struct
{
    char path[256]; // unusure
    uint32_t unk;
    uint32_t is_subdirectory; // +260 Value 0x10 if this is a subdirectory,
                              // otherwise 0
    uint32_t time_write; // + 264 Time of the last write to file. This time is
                         // stored in UTC format.
} FileSearchResult;

//----- (00484140) --------------------------------------------------------
// a1 = Path
// a2 = search mode
// a3 = extension to search for in mode 3 (Examples: ".bmp" or "bmp", the dot is
// added implicitly)
char *__cdecl sub_484140(char *a1, int a2, char *a3)
{
    char *result; // eax // FIXME: A FileSearch
    result = dword_ECC420->unk8(140);
    if (result == 0)
    {
        return 0;
    }

    memset(result, 0x00, 140);

    if (a2 >= 0)
    {
        if (a2 <= 2)
        {
            // Mode 0, 1, 2: Search for "<path>\\*.*" or just "*.*"
            contruct_path(result->path, 128, a1, "*.*");
        }
        else if (a2 == 3)
        {
            // Mode 3: Search for a specific extension using
            // "<path>\\*.<extension>"
            if (*(_BYTE *)a3 == '.')
            {
                a3++;
            }
            sprintf(OutputString, "*.%s", a3);
            contruct_path(result->path, 128, a1, OutputString);
        }
    }

    result->unk0 = a2;
    return result;
}

//----- (004841E0) --------------------------------------------------------
// a1 = some file search handle? FIXME: FileSearch
// Probably returns nothing
void __cdecl sub_4841E0(uint32_t *a1)
{
    if (a1 == 0)
    {
        return;
    }

    if (a1[1])
    {
        findclose(a1[34]); // +136
    }

    // Free memory
    // FIXME: This check feels redundant? Probably part of some SAFE_FREE macro.
    if (a1)
    {
        dword_ECC420->unk9(a1);
    }

    return;
}

//----- (00484220) --------------------------------------------------------
// a1 = file search object
// a2 = current file being returned (FileSearchResult) FIXME
BOOL __cdecl sub_484220(FileSearch *a1, int a2)
{
    BOOL result; // eax
    int v3; // eax
    int v4; // eax
    int v5; // esi
    char v6; // dl
    time_t v7; // ecx
    struct _finddata_t v8; // [esp+Ch] [ebp-118h]

    if (a1 == 0)
    {
        return 0;
    }

    if (a1->unk1 == 0)
    {
        v4 = _findfirst(a1->path, &v8);
        a1->handle = v4;
    }
    else
    {
        v4 = _findnext(a1->handle, &v8);
    }
    a1->unk1 = a1->unk1 + 1;

    // Check for errors
    if (v4 == -1)
    {
        return 0;
    }

    uint32_t is_subdirectory = v8.attrib & _A_SUBDIR;

    result = 0;
    result = result || (a1->unk0 == 0); // Unspecified search mode?
  result = result || (a1->unk0 == 1 && !is_subdirectory) // File search and this is not a directory
  result = result || (a1->unk0 == 2 && is_subdirectory)); // Directory search and this is a directory
  result = result || (a1->unk0 == 3); // Unspecified search mode?
  if (!result)
  {
      return 0;
  }

  strcpy(a2->name, v8.name);
  a2->is_subdirectory = is_subdirectory;
  a2->time_write = v8.time_write;
  return 1;
}

//----- (00484310) --------------------------------------------------------
BOOL __cdecl create_dir(LPCSTR lpPathName)
{
    return CreateDirectoryA(lpPathName, 0);
}

//----- (00484320) --------------------------------------------------------
BOOL __cdecl delete_file(LPCSTR lpFileName)
{
    return DeleteFileA(lpFileName);
}

//----- (00484330) --------------------------------------------------------
// Returns 1 on success, something else otherwise
BOOL __cdecl delete_dir(LPCSTR lpPathName)
{
    HANDLE hFindFile; // [esp+10h] [ebp-248h]

    CHAR FileName[260]; // [esp+14h] [ebp-244h] //FIXME: Probably just 256
                        // bytes?!

    struct _WIN32_FIND_DATAA FindFileData; // [esp+118h] [ebp-140h]

    // Construct the pathname
    strcpy(&FileName, lpPathName);
    strcat(&FileName, asc_4C7D60);

    hFindFile = FindFirstFileA(&FileName, &FindFileData);
    if (hFindFile == (HANDLE)-1)
    {
        return 0;
    }

    // Loop until our success-flag is cleared
    // This is a bug in the game. Should be `!= 0` as Microsoft only defines a
    // value for failure.
    int32_t v1 = 1;
    while (v1 == 1)
    {
        if (FindFileData.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)
        {
            // This is a directory, make sure this is not "." or "..", and
            // delete it recursively
            if (!(!strcmp(FindFileData.cFileName, ".")
                  || !strcmp(FindFileData.cFileName, "..")))
            {
                strcpy(&FileName, lpPathName);
                strcat(&FileName, (const char *)&unk_4B3B48);
                strcat(&FileName, FindFileData.cFileName);
                v1 = delete_dir(&FileName);
            }
        }
        else
        {
            // Delete this file
            strcpy(&FileName, lpPathName);
            strcat(&FileName, (const char *)&unk_4B3B48);
            strcat(&FileName, FindFileData.cFileName);
            v1 = DeleteFileA(&FileName);
        }

        // Get the next file
        if (!FindNextFileA(hFindFile, &FindFileData))
        {
            break;
        }
    }

    // Close the filesearch
    FindClose(hFindFile);

    // Now that the directory is empty, delete it
    if (v1)
    {
        return RemoveDirectoryA(lpPathName);
    }
    return v1;
}

//----- (004845B0) --------------------------------------------------------
// a1 = path, seperated using backslashes
// Returns filename, or full path if no backslash was found
char *__cdecl get_basename(char *a1)
{
    char v2; // cl

    char *result = strrchr(a1, '\\');
    if (result == NULL)
    {
        return a1;
    }

    // This scans forward until we are not on a backslash anymore.
    // This is probably useless, because strrchr already kind-of did this for
    // us.. So basically this does `result++` once.
    while (*result == '\\')
    {
        result++;
    }

    return result;
}

//----- (004845E0) --------------------------------------------------------
// a1 = path, seperated using backslashes
// Returns extension or NULL if no extension found
char *__cdecl get_extension(char *a1)
{
    char *filename = get_basename(a1);
    char *extension = strrchr(v1, '.');
    if (extension == NULL)
    {
        return NULL;
    }
    return extension + 1;
}
