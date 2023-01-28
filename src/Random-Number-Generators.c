int32_t sub_4866D0()
{
    // Check if the RNG has been initialized yet to retrieve the current seed
    int32_t v0;
    if (byte_517E58)
    {
        v0 = dword_517E54;
    }
    else
    {
        // Initialize the RNG
        v0 = 41222736;
        byte_517E58 = 1;
    }

    // Linear congruential generator
    int32_t result = 1103515245 * v0 + 12345;
    dword_517E54 = result;

    // Output a value in range [0, 0x7FFFFFFF]
    // The smallest representable negative value would not fit into 31 bits, so
    // a special check is done for it. All other negative numbers will be turned
    // into positive numbers.
    if (result == 0x80000000)
    {
        return 0;
    }
    if (result < 0)
    {
        return -result;
    }
    return result;
}
