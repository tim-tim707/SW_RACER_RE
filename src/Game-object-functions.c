int __cdecl sub_429DC0(int a1, char *a2, int a3, int a4, int a5) {
  int v5; // esi
  const char *v6; // ST0C_4
  const char *v7; // eax
  int result; // eax
  double v9; // st7

  *(_BYTE *)a3 = 0;

  // Get the current selected podracer pointer
  v5 = sub_450AA0(1415934836, dword_50C050);
  if ( !v5 )
    return 0;

  *(_DWORD *)a4 = -10000;
  switch ( a1 ) {
    case 0:
      v6 = sub_421360(*(const char **)(*(_DWORD *)(*(_DWORD *)(v5 + 7792) + 24) + 24));
      v7 = sub_421360(*(const char **)(*(_DWORD *)(*(_DWORD *)(v5 + 7792) + 24) + 20));
      sprintf(a2, aNameSS, v7, v6);
      result = 1;
      *(_DWORD *)a5 = -943501440;
      break;
    case 1:
      sprintf(a2, aAntiSkid);
      *(_DWORD *)a5 = *(_DWORD *)(v5 + 108);
      result = 1;
      break;
    case 2:
      sprintf(a2, aTurnResponse);
      *(_DWORD *)a5 = *(_DWORD *)(v5 + 112);
      result = 1;
      break;
    case 3:
      sprintf(a2, aMaxTurnRate);
      *(_DWORD *)a5 = *(_DWORD *)(v5 + 116);
      result = 1;
      break;
    case 4:
      sprintf(a2, aAcceleration);
      *(_DWORD *)a5 = *(_DWORD *)(v5 + 120);
      result = 1;
      break;
    case 5:
      sprintf(a2, aMaxSpeed);
      *(_DWORD *)a5 = *(_DWORD *)(v5 + 124);
      result = 1;
      break;
    case 6:
      sprintf(a2, aAirbrakeInv);
      *(_DWORD *)a5 = *(_DWORD *)(v5 + 128);
      result = 1;
      break;
    case 7:
      sprintf(a2, aDecelInv);
      *(_DWORD *)a5 = *(_DWORD *)(v5 + 132);
      result = 1;
      break;
    case 8:
      sprintf(a2, aBoostThrust);
      *(_DWORD *)a5 = *(_DWORD *)(v5 + 136);
      result = 1;
      break;
    case 9:
      sprintf(a2, aHeatRate);
      *(_DWORD *)a5 = *(_DWORD *)(v5 + 140);
      result = 1;
      break;
    case 10:
      sprintf(a2, aCoolRate);
      *(_DWORD *)a5 = *(_DWORD *)(v5 + 144);
      result = 1;
      break;
    case 11:
      sprintf(a2, aHoverHeight);
      *(_DWORD *)a5 = *(_DWORD *)(v5 + 148);
      result = 1;
      break;
    case 12:
      sprintf(a2, aRepairRate);
      *(_DWORD *)a5 = *(_DWORD *)(v5 + 152);
      result = 1;
      break;
    case 13:
      sprintf(a2, aBumpMass);
      *(_DWORD *)a5 = *(_DWORD *)(v5 + 156);
      result = 1;
      break;
    case 14:
      sprintf(a2, aDmgImmunity);
      *(_DWORD *)a5 = *(_DWORD *)(v5 + 160);
      result = 1;
      break;
    case 15:
      sprintf(a2, aIsectRadius);
      *(_DWORD *)a5 = *(_DWORD *)(v5 + 168);
      result = 1;
      break;
    case 16:
      sprintf(a2, aAiLookAhead);
      v9 = sub_480670(*(float *)(v5 + 264));
      result = 1;
      *(float *)a5 = v9;
      break;
    default:
      sprintf(a2, aUnimplemented);
      *(_DWORD *)a5 = 0;
      return 0;
  }
  return result;
}
v6 = sub_421360(*(const char **)(*(_DWORD *)(*(_DWORD *)(v5 + 7792) + 24) + 24)); // prename?
v7 = sub_421360(*(const char **)(*(_DWORD *)(*(_DWORD *)(v5 + 7792) + 24) + 20)); // lastname?
sprintf(a2, aNameSS, v7, v6);
struct {
uint8_t unk[108];
float AntiSkid; // 108
float TurnResponse; // 112
float MaxTurnRate; // 116
float Acceleration; // 120
float MaxSpeed; // 124
float AirbrakeInv; // 128
float DecelInv; // 132
float BoostThrust; // 136
float HeatRate; // 140
float CoolRate; // 144
float HoverHeight; // 148
float RepairRate; // 152
float BumpMass // 156
float DmgImmunity // 160
float unknown; // 164
float IsectRadius; // 168
float AiLookAhead // 264 (displayed as sqrt(AiLookAhead) in menu)

... FIXME

struct {
  uint8_t unk[24];
  struct { // 24
    uint8_t unk[20];
    const char* prename; // 20
    const char* lastname; // 24
  }* name_second_ptr;
}* name_first_ptr; // 7792

}
typedef struct {
  uint32_t type; // 4 letter string
  uint32_t unk;
  uint32_t element_count; // object count
  uint32_t element_size; // size per object
  void* first_element; // pointer to first object
} ObjectList;

typedef struct {
  uint32_t unk; // 0
  uint16_t handle; // 4
  uint16_t flags; // 6   0x100 = object is not present / unsearchable?
  uint8_t data[];
} ObjectHeader;

//----- (00450AA0) --------------------------------------------------------
// a1 = list type
// a2 = handle of object
ObjectHeader* __cdecl sub_450AA0(uint32_t a1, int a2) {

  // Get pointer to object lists
  ObjectList** v2 = off_4BFEC0;

  while(1) {

    // Lookup object list, if there is none, we can abort as we don't have a list to search
    ObjectList* v3 = *v2++;
    if ( !v3 ) {
      break;
    }

    // Skip lists with wrong type
    if (v3->type != a1) {
      continue;
    }

    for (int32_t i = 0; i < v3->element_count; i++) {
      ObjectHeader* r = (uintptr_t)v3->first_element + i * v3->element_size;

      //FIXME: What is this flag?
      if (r->flags & 0x100) {
        continue;
      }

      if (r->handle == a2) {
        return r;
      }
    }

  }

  return 0;
}
