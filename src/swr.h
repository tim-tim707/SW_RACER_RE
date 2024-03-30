#ifndef SWR_H
#define SWR_H

#define swr_noop2_ADDR (0x00426910)

#define swr_noop4_ADDR (0x004270c0)

#define swr_noop1_ADDR (0x00482e50)

#define swr_noop3_ADDR (0x00483ba0)

#define sub_483A90_ADDR (0x00483A90)

#define sub_409510_ADDR (0x00409510)

void swr_noop2(void);

void swr_noop4(void);

void swr_noop1(void);

void swr_noop3(void);

void sub_483A90(int x);

void sub_409510(int a1, int a2);

#endif // SWR_H
