#ifndef SWR_H
#define SWR_H

#ifdef __cplusplus
extern "C"
{
#endif

#define swr_noop2_ADDR (0x00426910)
#define swr_noop1_ADDR (0x00482E50)

    void swr_noop1(void);
    void swr_noop2(void);

#ifdef __cplusplus
}
#endif

#endif // SWR_H
