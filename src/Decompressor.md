uint8_t* __cdecl sub_42D520(uint8_t* a1, uint8_t* a2) {
  uint8_t* v2 = a1;
  uint8_t* result = a2;
  uint8_t* v4 = &a1[-0x1000];
  int32_t v5 = 1;

  while(1) {
    // Read input byte
    uint8_t v20 = *v2++;

    // Loop over input bits
    for(int32_t v23 = 0; v23 < 8; v23++) {

      // Check if we want to use a byte copy instead of the window block copy
      if (v20 & (1 << v23)) {
        // Copy byte to output byte and to window
        uint8_t byte = *v2++;
        *result++ = byte;
        v4[v5] = byte;

        // Advance address in window
        v5 = (v5 + 1) & 0xFFF;
        continue;
      }

      // If this is block copy, get more parameters
      uint8_t v9 = *v2++; // 4 msb = number of bytes to copy; 4 lsb = source page (0x100 bytes) in window
      uint8_t v10 = *v2++; // byte offset within input page

      int32_t v11 = ((v9 & 0xF) * 0x100) + v10; // Get offset to source byte in window
      int32_t v12 = (v9 >> 4) & 0xF; // Get number of bytes to copy

      // If source offset is 0, it marks the end of the stream
      if (v11 == 0) {
        return result;
      }

      for(int32_t v14 = 0; v14 <= (v12 + 1); v14++) {
        // Copy byte to output and window
        uint8_t byte = v4[(v14 + v11) & 0xFFF];
        *result++ = byte;
        v4[v5] = byte;

        // Advance address in window
        v5 = (v5 + 1) & 0xFFF;
      }

    }
  }
}
