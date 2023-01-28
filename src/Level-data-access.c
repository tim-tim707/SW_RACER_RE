void __cdecl sub_42D680(int32_t a1)
{
    const char *v1; // edi
    switch (a1)
    {
    case 0:
        v1 = off_4B9598;
        break; // "data/lev01/out_modelblock.bin"
    case 1:
        v1 = off_4B958C[0];
        break; // "data/lev01/out_spriteblock.bin"
    case 2:
        v1 = off_4B9590[0];
        break; // "data/lev01/out_splineblock.bin"
    case 3:
        v1 = off_4B9594;
        break; // "data/lev01/out_textureblock.bin"
    default:
        v1 = (const char *)a1;
        break;
    }

    // Get the file pointer to fill out
    FILE **result = sub_42D600(a1);

    // Only open the file if it wasn't loaded before
    if (*result == 0)
    {
        // Open the file
        *result = fopen(v1, aRb);

        // Stick in a loop if file didn't open
        // Well.. that's one way to "handle" I/O errors.. good job LA
        if (*result == 0)
        {
            while (1)
                ;
        }
    }

    return;
}
FILE **__cdecl sub_42D600(int32_t a1)
{
    switch (a1)
    {
    case 0:
        return &unk_50C098;
    case 1:
        return &unk_50C08C;
    case 2:
        return &unk_50C090;
    case 3:
        return &unk_50C094;
    default:
        break;
    }
    return 0;
}
size_t __cdecl sub_42D640(int a1, int a2, void *a3, size_t a4)
{
    FILE **v4 = sub_42D600(a1);
    fseek(*v4, a2, SEEK_SET);
    return sub_49FFE0(a3, a4, 1u, *v4); // fread
}
void __cdecl sub_42D6F0(int32_t a1)
{
    // Get file handle
    FILE **v1 = (FILE **)sub_42D600(a1);

    // Close file and clear file handle to mark file as closed
    fclose(*v1);
    *v1 = 0;

    return;
}
