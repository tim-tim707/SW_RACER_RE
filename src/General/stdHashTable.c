#include "stdHashTable.h"

#include "globals.h"
#include "stdLinkList.h"

#include <macros.h>

// 0x0048bea0
unsigned int stdHashtbl_CalculateHash(char* pData, int hashSize)
{
    HANG("TODO");
}

// 0x0048bee0
tHashTable* stdHashtbl_New(size_t size)
{
    HANG("TODO");
}

// 0x0048bf50
int stdHashtbl_GetPrime(int x)
{
    int* piVar1;
    int res;
    int i;

    i = 0;
    piVar1 = stdMath_Primes;
    do
    {
        if (x < *piVar1)
        {
            res = stdMath_Primes[i];
            break;
        }
        piVar1 = piVar1 + 1;
        i = i + 1;
        res = x;
    } while ((int)piVar1 < 0x4aef30);
    if (1999 < x)
    {
        res = stdHashtbl_nextPrime(x);
    }
    return res;
}

// 0x0048bf90
int stdHashtbl_nextPrime(int x)
{
    int isPrime;

    isPrime = stdHashtbl_isPrime(x);
    while (isPrime == 0)
    {
        x = x + 1;
        isPrime = stdHashtbl_isPrime(x);
    }
    return x;
}

// 0x0048bfc0
int stdHashtbl_isPrime(int x)
{
    int i;

    i = 2;
    if (x + -1 < 3)
    {
        return 1;
    }
    do
    {
        if (x % i == 0)
        {
            return 0;
        }
        i = i + 1;
    } while (i < x + -1);
    return 1;
}

// 0x0048c000
tLinkListNode* stdHashtbl_GetTailNode(tLinkListNode* pCur)
{
    tLinkListNode* ptVar1;
    tLinkListNode* ptVar2;

    ptVar2 = pCur->next;
    while (ptVar1 = ptVar2, ptVar1 != NULL)
    {
        pCur = ptVar1;
        ptVar2 = ptVar1->next;
    }
    return pCur;
}

// 0x0048c020
void stdHashtbl_FreeListNodes(tLinkListNode* pNode)
{
    tLinkListNode* next;
    tLinkListNode* next_next;

    next = pNode->next;
    while (next != NULL)
    {
        next_next = next->next;
        (*stdPlatform_hostServices_ptr->free)(next);
        next = next_next;
    }
    return;
}

// 0x0048c050
int stdHashtbl_Free(tHashTable* pTable)
{
    int iVar1;
    int result;

    result = 0;
    if (0 < pTable->numNodes)
    {
        iVar1 = 0;
        do
        {
            stdHashtbl_FreeListNodes((tLinkListNode*)((int)&pTable->paNodes->prev + iVar1));
            result = result + 1;
            iVar1 = iVar1 + 0x10;
        } while (result < pTable->numNodes);
    }
    (*stdPlatform_hostServices_ptr->free)(pTable->paNodes);
    (*stdPlatform_hostServices_ptr->free)(pTable);
    return result;
}

// 0x0048c0a0 TODO: crashes on release build, works fine on debug
int stdHashtbl_Add(tHashTable* pTable, char* pName, void* pData)
{
    void* pvVar1;
    unsigned int uVar2;
    tLinkListNode* ptVar3;
    tLinkListNode* pNodeToAdd;

    pvVar1 = stdHashtbl_Find(pTable, pName);
    if (pvVar1 != NULL)
    {
        return 0;
    }
    uVar2 = (*pTable->hashFunc)(pName, pTable->numNodes);
    ptVar3 = stdHashtbl_GetTailNode(pTable->paNodes + uVar2);
    if (ptVar3->name == NULL)
    {
        ptVar3 = pTable->paNodes + uVar2;
        ptVar3->prev = NULL;
        ptVar3->next = NULL;
        ptVar3->name = NULL;
        ptVar3->data = NULL;
        pTable->paNodes[uVar2].name = pName;
        pTable->paNodes[uVar2].data = pData;
        return 1;
    }
    pNodeToAdd = (tLinkListNode*)(*stdPlatform_hostServices_ptr->alloc)(0x10);
    if (pNodeToAdd == NULL)
    {
        return 0;
    }
    pNodeToAdd->prev = NULL;
    pNodeToAdd->next = NULL;
    pNodeToAdd->name = NULL;
    pNodeToAdd->data = NULL;
    pNodeToAdd->name = pName;
    pNodeToAdd->data = pData;
    stdLinkList_AddNode(ptVar3, pNodeToAdd);
    return 1;
}

// 0x0048c160
void* stdHashtbl_Find(tHashTable* pTable, char* pName)
{
    HANG("TODO");
}

// 0x0048c190
tLinkListNode* stdHashtbl_FindNode(tHashTable* pTable, char* pName, int* pNodeHash)
{
    HANG("TODO");
}

// 0x0048c210 TODO: crashes on release build, works fine on debug
int stdHashtbl_Remove(tHashTable* pTable, char* pName)
{
    tLinkListNode* ptVar1;
    tLinkListNode* ptVar2;
    tLinkListNode* ptVar3;

    ptVar2 = stdHashtbl_FindNode(pTable, pName, (int*)&pName);
    if (ptVar2 == NULL)
    {
        return 0;
    }
    ptVar1 = ptVar2->next;
    stdLinkList_RemoveNode(ptVar2);
    ptVar3 = pTable->paNodes + (int)pName;
    if (ptVar3 == ptVar2)
    {
        if (ptVar1 == NULL)
        {
            ptVar3->prev = NULL;
            ptVar3->next = NULL;
            ptVar3->name = NULL;
            ptVar3->data = NULL;
            return 1;
        }
        ptVar3->prev = ptVar1->prev;
        ptVar3->next = ptVar1->next;
        ptVar3->name = ptVar1->name;
        ptVar3->data = ptVar1->data;
        ptVar2 = pTable->paNodes[(int)pName].next;
        if (ptVar2 != NULL)
        {
            ptVar2->prev = pTable->paNodes + (int)pName;
        }
        (*stdPlatform_hostServices_ptr->free)(ptVar1);
        return 1;
    }
    (*stdPlatform_hostServices_ptr->free)(ptVar2);
    return 1;
}
