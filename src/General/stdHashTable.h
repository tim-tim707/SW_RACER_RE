#ifndef STDHASHTABLE_H
#define STDHASHTABLE_H

#include "types.h"

#define stdHashTable_CalculateHash_ADDR (0x0048bea0)
#define stdHashTable_New_ADDR (0x0048bee0)
#define stdHashTable_GetPrime_ADDR (0x0048bf50)
#define stdHashTable_nextPrime_ADDR (0x0048bf90)
#define stdHashTable_isPrime_ADDR (0x0048bfc0)
#define stdHashTable_GetTailNode_ADDR (0x0048c000)
#define stdHashTable_FreeListNodes_ADDR (0x0048c020)
#define stdHashTable_Free_ADDR (0x0048c050)
#define stdHashTable_Add_ADDR (0x0048c0a0)
#define stdHashTable_Find_ADDR (0x0048c160)
#define stdHashTable_FindNode_ADDR (0x0048c190)
#define stdHashTable_Remove_ADDR (0x0048c210)

unsigned int stdHashTable_CalculateHash(char* pData, int hashSize);

tHashTable* stdHashTable_New(size_t size);
int stdHashTable_GetPrime(int x);
int stdHashTable_nextPrime(int x);
int stdHashTable_isPrime(int x);
tLinkListNode* stdHashTable_GetTailNode(tLinkListNode* pCur);
void stdHashTable_FreeListNodes(tLinkListNode* pNode);
int stdHashTable_Free(tHashTable* pTable);
int stdHashTable_Add(tHashTable* pTable, char* pName, void* pData);
void* stdHashTable_Find(tHashTable* pTable, char* pName);
tLinkListNode* stdHashTable_FindNode(tHashTable* pTable, char* pName, int* pNodeHash);
int stdHashTable_Remove(tHashTable* pTable, char* pName);

#endif // STDHASHTABLE_H
