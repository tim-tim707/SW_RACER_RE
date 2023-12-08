#ifndef STDLINKLIST_H
#define STDLINKLIST_H

#include "types.h"

#define stdLinkList_AddNode_ADDR (0x0048d790)
#define stdLinkList_RemoveNode_ADDR (0x0048d7b0)

void stdLinkList_AddNode(tLinkListNode* pCur, tLinkListNode* pNodeToAdd);
tLinkListNode* stdLinkList_RemoveNode(tLinkListNode* pCur);

#endif // STDLINKLIST_H
