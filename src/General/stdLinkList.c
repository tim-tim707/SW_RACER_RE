#include "stdLinkList.h"

// 0x0048d790
void stdLinkList_AddNode(tLinkListNode* pCur, tLinkListNode* pNodeToAdd)
{
    tLinkListNode* ptVar1;

    ptVar1 = pCur->next;
    pNodeToAdd->prev = pCur;
    pNodeToAdd->next = ptVar1;
    pCur->next = pNodeToAdd;
    if (ptVar1 != NULL)
    {
        ptVar1->prev = pNodeToAdd;
    }
    return;
}

// 0x0048d7b0
tLinkListNode* stdLinkList_RemoveNode(tLinkListNode* pCur)
{
    if (pCur->prev != NULL)
    {
        pCur->prev->next = pCur->next;
    }
    if (pCur->next != NULL)
    {
        pCur->next->prev = pCur->prev;
    }
    pCur->next = NULL;
    pCur->prev = NULL;
    return pCur;
}
