#include "stdFileUtil.h"
#include "stdFnames.h"

#include <fileapi.h>
#include <io.h>

#include "globals.h"

// 0x00484140
stdFileSearch* stdFileUtil_NewFind(char* path, int searchMode, char* extension)
{
    stdFileSearch* search;
    int iVar1;
    stdFileSearch* search_;

    search = (stdFileSearch*)(*stdPlatform_hostServices_ptr->alloc)(sizeof(stdFileSearch));
    if (search == NULL)
    {
        return NULL;
    }
    search_ = search;
    for (iVar1 = 0x23; iVar1 != 0; iVar1 = iVar1 + -1)
    {
        search_->searchMode = 0;
        search_ = (stdFileSearch*)&search_->isNotFirst;
    }
    if (-1 < searchMode)
    {
        if (searchMode < 3)
        {
            stdFnames_MakePath(search->path, 0x80, path, "*.*");
        }
        else if (searchMode == 3)
        {
            if (*extension == '.')
            {
                extension = extension + 1;
            }
            sprintf(std_output_buffer, "*.%s", extension);
            stdFnames_MakePath(search->path, 0x80, path, std_output_buffer);
            search->searchMode = 3;
            return search;
        }
    }
    search->searchMode = searchMode;
    return search;
}

// 0x004841e0
void stdFileUtil_DisposeFind(stdFileSearch* search)
{
    if (search != NULL)
    {
        if (search->isNotFirst)
        {
            _findclose(search->filesearchHandle);
        }
        if (search != NULL)
        {
            (*stdPlatform_hostServices_ptr->free)(search);
        }
    }
}

// 0x00484220
int stdFileUtil_FindNext(stdFileSearch* search, stdFileSearchResult* result)
{
    intptr_t v4; // eax
    struct _finddata_t finddata_; // [esp+8h] [ebp-118h] BYREF

    if (!search)
        return 0;

    if (search->isNotFirst++)
    {
        v4 = _findnext(search->filesearchHandle, &finddata_);
    }
    else
    {
        v4 = _findfirst(search->path, &finddata_);
        search->filesearchHandle = v4;
    }
    if (v4 == -1)
        return 0;

    // Added: strcpy -> strncpy
    strncpy(result->fpath, finddata_.name, sizeof(result->fpath) - 1);

    result->time_write = finddata_.time_write;
    result->is_subdirectory = finddata_.attrib & 0x10;
    return 1;
}

// 0x00484310
BOOL stdFileUtil_MkDir(LPCSTR lpPathName)
{
    return CreateDirectoryA(lpPathName, NULL);
}

// 0x00484320
void stdFileUtil_DeleteFile(LPCSTR lpFileName)
{
    DeleteFileA(lpFileName);
}

// 0x00484330
int stdFileUtil_DelTree(LPCSTR lpPathName)
{
    int v2; // ebx
    char* v3; // edi
    int v4; // eax
    HANDLE hFindFile; // [esp+10h] [ebp-248h]
    char FileName[260]; // [esp+14h] [ebp-244h] BYREF
    struct _WIN32_FIND_DATAA FindFileData; // [esp+118h] [ebp-140h] BYREF

    strcpy(FileName, lpPathName);
    v2 = 1;
    v3 = &FileName[strlen(FileName)];
    strcpy(v3, "\\*.*");
    hFindFile = FindFirstFileA(FileName, &FindFileData);
    if (hFindFile == (HANDLE)-1)
        return 0;
    do
    {
        if (FindFileData.dwFileAttributes != 16)
        {
            strcpy(FileName, lpPathName);
            strcpy(&FileName[strlen(FileName)], "\\");
            strcat(FileName, FindFileData.cFileName);
            v4 = DeleteFileA(FileName);
            goto LABEL_7;
        }
        if (strcmp(FindFileData.cFileName, ".") && strcmp(FindFileData.cFileName, ".."))
        {
            strcpy(FileName, lpPathName);
            strcpy(&FileName[strlen(FileName)], "\\");
            strcat(FileName, FindFileData.cFileName);
            v4 = stdFileUtil_DelTree(FileName);
        LABEL_7:
            v2 = v4;
        }
    } while (FindNextFileA(hFindFile, &FindFileData) && v2 == 1);
    FindClose(hFindFile);
    if (v2)
        return RemoveDirectoryA(lpPathName);
    return v2;
}
