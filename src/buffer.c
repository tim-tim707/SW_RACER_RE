/*

Buffer helpers

The buffer system seems to be used when loading game data.
A big buffer of data seems to be allocated and then a function will query the
current pointer / offset into the buffer.
The current pointer points into unused memory.
It then "reserves" space in the buffer by moving the pointer / offset forward.

*/

// Research based on patched US version

//----- (00445B20) --------------------------------------------------------
// Set pointer / offset in allocated buffer
int __cdecl sub_445B20(int a1) {
  dword_E98200[dword_50C614] = a1;
  return nullsub_3();
}

//----- (00445B40) --------------------------------------------------------
// Get pointer / offset in allocated buffer
int sub_445B40() {
  return dword_E98200[dword_50C614];
}

//----- (00445B50) --------------------------------------------------------
// Something like EOF?
BOOL __cdecl sub_445B50(unsigned int a1) {
  return a1 < sub_445B40();
}

//----- (00445BF0) --------------------------------------------------------
// Get remaining number of bytes in buffer
int sub_445BF0() {
  return dword_E981E4 - sub_445B40();
}
