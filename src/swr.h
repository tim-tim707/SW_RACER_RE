#ifndef SWR_H
#define SWR_H

#define swr_noop2_ADDR (0x00426910)

#define swrSound_RequestVoice_ADDR (0x00426A00)
#define swrSound_Play2D_ADDR (0x00426C80)
#define swrSound_Play2DMinVolume_ADDR (0x00426CC0)

#define swr_noop4_ADDR (0x004270c0)

#define swr_noop1_ADDR (0x00482e50)

#define swr_noop3_ADDR (0x00483ba0)

void swr_noop2(void);

void  swrSound_RequestVoice(int, short, float, float, short, int, int, int *);
void  swrSound_Play2D(int, short, float, float, int);
void  swrSound_Play2DMinVolume(int, short, float, float, int);

void swr_noop4(void);

void swr_noop1(void);

void swr_noop3(void);

#endif // SWR_H
