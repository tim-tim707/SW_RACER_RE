static inline float selectStrengthFactor(uint32_t strength)
{
    if (strength != 0)
    {
        if (strength == 1)
        {
            return 0.6f;
        }
        else if (strength == 2)
        {
            return 0.8f;
        }
        else
        {
            return 1.0f;
        }
    }
    return -1.0f;
}

int sub_40A680()
{
    memset(&unk_EC8400, 0, 0x150u);
    dword_4B493C = selectStrengthFactor(dword_EC83E0);
    flt_EC84D0 = selectStrengthFactor(dword_EC83E4);
    flt_EC8404[0] = dword_EC83F8 ? 1.0f : -1.0f;
    dword_EC8518 = dword_EC83FC ? 1.0f : -1.0f;
    dword_EC84E8 = selectStrengthFactor(dword_EC83E8);
    dword_EC84F4 = selectStrengthFactor(dword_EC83E8);
    dword_EC8434 = selectStrengthFactor(dword_EC83F4);
    dword_EC8440 = selectStrengthFactor(dword_EC83F4);
    dword_EC8458 = selectStrengthFactor(dword_EC83F4);
    dword_EC8464 = selectStrengthFactor(dword_EC83F4);
    dword_EC847C = selectStrengthFactor(dword_EC83F4);
    dword_EC8488 = selectStrengthFactor(dword_EC83F4);
    dword_EC841C = selectStrengthFactor(dword_EC83F4);
    dword_EC844C = selectStrengthFactor(dword_EC83F4);
    dword_EC8470 = selectStrengthFactor(dword_EC83F0);
    dword_EC850C = selectStrengthFactor(dword_EC83EC);
    dword_EC8548 = selectStrengthFactor(dword_EC83EC);
    dword_EC8410 = selectStrengthFactor(dword_EC83EC);
    dword_EC8500 = selectStrengthFactor(dword_EC83EC);
    dword_EC853C = selectStrengthFactor(dword_EC83EC);
    dword_EC84A0 = 1.0f;
    dword_EC8494 = 1.0f;
    dword_EC8428 = 1.0f;
    dword_EC84DC = 1.0f;
    dword_EC8524 = 1.0f;
    dword_EC8530 = 1.0f;
    dword_EC84AC = 1.0f;
    dword_EC84B8 = 1.0f;
    dword_EC84C4 = 1.0f;
    return dword_EC83EC;
}
