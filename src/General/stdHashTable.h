#ifndef STDHASHTABLE_H
#define STDHASHTABLE_H

#include "types.h"

#define stdHashtbl_CalculateHash_ADDR (0x0048bea0)
#define stdHashtbl_New_ADDR (0x0048bee0)
#define stdHashtbl_GetPrime_ADDR (0x0048bf50)
#define stdHashtbl_nextPrime_ADDR (0x0048bf90)
#define stdHashtbl_isPrime_ADDR (0x0048bfc0)
#define stdHashtbl_GetTailNode_ADDR (0x0048c000)
#define stdHashtbl_FreeListNodes_ADDR (0x0048c020)
#define stdHashtbl_Free_ADDR (0x0048c050)
#define stdHashtbl_Add_ADDR (0x0048c0a0)
#define stdHashtbl_Find_ADDR (0x0048c160)
#define stdHashtbl_FindNode_ADDR (0x0048c190)
#define stdHashtbl_Remove_ADDR (0x0048c210)

unsigned int stdHashtbl_CalculateHash(char* pData, int hashSize);

tHashTable* stdHashtbl_New(size_t size);
int stdHashtbl_GetPrime(int x);
int stdHashtbl_nextPrime(int x);
int stdHashtbl_isPrime(int x);
tLinkListNode* stdHashtbl_GetTailNode(tLinkListNode* pCur);
void stdHashtbl_FreeListNodes(tLinkListNode* pNode);
int stdHashtbl_Free(tHashTable* pTable);
int stdHashtbl_Add(tHashTable* pTable, char* pName, void* pData);
void* stdHashtbl_Find(tHashTable* pTable, char* pName);
tLinkListNode* stdHashtbl_FindNode(tHashTable* pTable, char* pName, int* pNodeHash);
int stdHashtbl_Remove(tHashTable* pTable, char* pName);

#endif // STDHASHTABLE_H
