#ifndef SWRRACE_H
#define SWRRACE_H

#define swrRace_UpdatePartsHealth_ADDR (0x0043d720)

#define swrRace_UpdateTurn_ADDR (0x0044ae40)

#define swrRace_ReplaceMarsGuoWithJinnReeso_ADDR (0x0044B530)
#define swrRace_ReplaceBullseyeWithCyYunga_ADDR (0x0044B5E0)

#define swrRace_Repair_ADDR (0x0046ab10)

#define swrRace_Tilt_ADDR (0x0046b5a0)

void swrRace_UpdatePartsHealth(void);

void swrRace_UpdateTurn(float* param_1, float* param_2, float param_3, float param_4, float param_5, float param_6);

void swrRace_ReplaceMarsGuoWithJinnReeso(void);
void swrRace_ReplaceBullseyeWithCyYunga(void);

void swrRace_Repair(int player);

void swrRace_Tilt(int player, float b);

#endif // SWRRACE_H
