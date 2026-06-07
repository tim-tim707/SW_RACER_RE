#ifndef SWR_H
#define SWR_H

#define swr_noop2_ADDR (0x00426910)

#define playASoundImpl_ADDR (0x00426A00)
#define playASound_ADDR (0x00426C80)
#define playASound2_ADDR (0x00426CC0)

#define swr_noop4_ADDR (0x004270c0)

#define swr_noop1_ADDR (0x00482e50)

#define swr_noop3_ADDR (0x00483ba0)

void swr_noop2(void);

void  playASoundImpl(int, short, float, float, short, int, int, int *);
void  playASound(int, short, float, float, int);
void  playASound2(int, short, float, float, int);

void swr_noop4(void);

void swr_noop1(void);

void swr_noop3(void);

#endif // SWR_H
