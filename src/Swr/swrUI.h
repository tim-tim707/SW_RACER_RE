#ifndef SWRUI_H
#define SWRUI_H

#include "types.h"

// typedef swrUI_unk* (*swrUI_unk_F1)(swrUI_unk* self, int param_2, void* param_3, int param_4);
// typedef swrUI_unk* (*swrUI_unk_F2)(swrUI_unk* self, unsigned int param_2, void* param_3, int param_4);

// F1 element procs (registered by swrUI_New; prototypes + addresses below).
// Each tail-calls swrUI_DefaultElementProc.
/*
FUN_00415850  swrUI_DefaultElementProc
FUN_00415b80  swrUI_LabelProc
FUN_00415ca0  swrUI_ButtonProc
FUN_00415ed0  swrUI_ScreenTextProc
FUN_00416130  swrUI_ListProc
FUN_00416370  swrUI_TextEntryProc
FUN_00416690  swrUI_NumberFieldProc
FUN_00416820  swrUI_DialogProc
FUN_00417940  swrUI_FramedTextProc
FUN_00417be0  swrUI_3PatchBoxProc
FUN_0041ac00  swrUI_RaceResultRowProc
*/

// Menu / UI system functions documented via the widescreen-UI investigation.
// F2 page procs (signature: int(swrUI_unk*, unsigned int msg, void*, swrUI_unk*)):
#define swrUI_Menu_Main_ADDR (0x00401000)
#define swrUI_Menu_SettingsHub_ADDR (0x00401960)
#define swrUI_Menu_SaveLoadConfig_ADDR (0x00401af0)
#define swrUI_Menu_VideoSettings_ADDR (0x004030f0)
#define swrUI_Menu_AudioSettings_ADDR (0x00403430)
#define swrUI_Menu_ForceFeedback_ADDR (0x004039a0)
#define swrUI_Menu_ReservedSettings_ADDR (0x00403d70)
#define swrUI_UpdateMouseState_ADDR (0x004083d0)
#define swrUI_UpdateProgressBar_ADDR (0x00408640)
#define swrUI_ResetProgressBar_ADDR (0x00408800)
#define swrUI_Initialize_ADDR (0x00410fd0)
#define swrUI_BroadcastToWindows_ADDR (0x00411120)        // fire msg 0x4a to all visible class-0 windows
#define swrUI_IsPrevPage_ADDR (0x00411140)                // did the leaving page (DAT_004d8bd4) have this id?
#define swrUI_AddNavButton_ADDR (0x00411170)              // standard Quit/Cancel/Back button (by kind)
#define swrUI_AddOkButton_ADDR (0x00411210)               // standard OK button
#define swrUI_AddRestoreButton_ADDR (0x00411270)          // standard Restore button (id 0x26)
#define swrUI_AddDefaultButton_ADDR (0x004112f0)          // standard Default button (id 0x25)
#define swrUI_RefreshRoot_ADDR (0x00411370)               // relayout the root menu tree
#define swrUI_AlignElementTo_ADDR (0x00411390)            // anchor element a's edge to element b (edge-flag bits)
#define swrUI_CenterElement_ADDR (0x00411440)             // center an element on the 640x480 screen
#define swrUI_GetUI1_ADDR (0x00411480)
#define swrUI_EnableElement_ADDR (0x00411490)             // clear the disabled/gray flag (bit 0x100)
#define swrUI_DisableElement_ADDR (0x004114b0)            // set the disabled/gray flag (bit 0x100)
#define swrUI_SetCaretActive_ADDR (0x00411730)        // enable/disable the caret
#define swrUI_SetCaretRect_ADDR (0x00411740)          // set the caret x/y/w/h
#define swrUI_AddTimer_ADDR (0x00411770)              // register a UI timer (fires msg 0x45 on a target)
#define swrUI_RemoveTimer_ADDR (0x004117b0)           // remove a UI timer by param
#define swrUI_ResetPageStack_ADDR (0x004117e0)            // clear the page stack
#define swrUI_GetPageStackDepth_ADDR (0x00411800)         // current page-stack depth
#define swrUI_GetCurrentPage_ADDR (0x00411810)            // the page at the top of the stack
#define swrUI_PushMenuPage_ADDR (0x00411820)
#define swrUI_PopMenuPage_ADDR (0x004118b0)
#define swrUI_ReparentElement_ADDR (0x00411910)           // move an element under a new parent
#define swrUI_BuildAuxPages_ADDR (0x004121f0)             // build aux/overlay windows 0x81-0x89
#define swrUI_Shutdown_ADDR (0x00412e40)              // UI teardown (free tree + sprite materials + hash table)
#define swrUI_AddSprite_ADDR (0x00412fb0)
#define swrUI_SetSpriteColor_ADDR (0x00413090)
#define swrUI_SetSpriteFlag_ADDR (0x004130e0)         // set/clear flag 0x20000 on a sprite slot
#define swrUI_NewWindow_ADDR (0x00413130)
#define swrUI_NewLabel_ADDR (0x004131c0)
#define swrUI_NewButton_ADDR (0x004132a0)
#define swrUI_NewScreenText_ADDR (0x00413340)
#define swrUI_SetMaxLength_ADDR (0x00413500)          // text-entry max length (+0x534)
#define swrUI_SelectListItem_ADDR (0x00413610)        // single-select: clear siblings, select this item
#define swrUI_FindChildByText_ADDR (0x004136f0)       // case-insensitive child lookup by text (+0x4d4)
#define swrUI_GetSelectedIndex_ADDR (0x00413740)      // index of the selected item (bit 0x80000 @+0x508), -1 if none
#define swrUI_GetSelectableItem_ADDR (0x00413770)     // n-th selectable child (flags & 0xc == 0xc)
#define swrUI_GetSelectedItem_ADDR (0x004137a0)       // the selected child element
#define swrUI_CountSelectableItems_ADDR (0x004137d0)
#define swrUI_RefreshListSelection_ADDR (0x00413800)  // save selection into the list (+0x520 index, +0x51c text)
#define swrUI_RestoreListSelection_ADDR (0x00413870)  // reapply the saved selection (by index, else by text)
#define swrUI_SetListHighlightColor_ADDR (0x004138b0) // set the highlight color (+0x4c4) and re-apply to items
#define swrUI_AddListItem_ADDR (0x004138f0)           // create a labeled list item
#define swrUI_AddListElement_ADDR (0x00413a30)        // append an existing element as a list item
#define swrUI_GetNumberValue_ADDR (0x00413b10)        // read a number/slider widget's value (+0x55c)
#define swrUI_SetNumberValue_ADDR (0x00413b30)        // set the value (+0x55c) + rebuild slider sprites
#define swrUI_SetSliderValue_ADDR (0x00413b60)        // set the slider fill percent (+0x54c) + rebuild
#define swrUI_NewSpriteElement_ADDR (0x00413b90)
#define swrUI_NewFramedText_ADDR (0x00413c50)
#define swrUI_GetValue_ADDR (0x00413fa0)
#define swrUI_New3PatchBox_ADDR (0x00413fc0)
#define swrUI_SetChecked_ADDR (0x00414420)
#define swrUI_ToggleChecked_ADDR (0x00414590)
#define swrUI_ShowConfirmDialog_ADDR (0x004145b0)
#define swrUI_NewDialog_ADDR (0x004146c0)
#define swrUI_SetValueText_ADDR (0x00414ab0)          // set the secondary value-text (+0x4f8) + value (+0x4fc)
#define swrUI_SetValue_ADDR (0x00414ae0)              // set an element's value field (+0x4fc)
#define swrUI_GetValueText_ADDR (0x00414af0)          // get the value-text (+0x4f8)
#define swrUI_SetSize_ADDR (0x00414b40)
#define swrUI_SetPos_ADDR (0x00414b60)
#define swrUI_RunCallbacksScreenText_ADDR (0x00414b80)
#define swrUI_GetAllocatedString_ADDR (0x00414ba0)
#define swrUI_SetColorUnk_ADDR (0x00414be0)
#define swrUI_SetColorUnk4_ADDR (0x00414c10)
#define swrUI_SetColorUnk3_ADDR (0x00414c40)
#define swrUI_SetColorUnk5_ADDR (0x00414c70)
#define swrUI_SetColorUnk2_ADDR (0x00414ca0)
#define swrUI_SetSlotValue_ADDR (0x00414cd0)          // exchange the indexed slot value (+0x44 array); returns old
#define swrUI_GetSlotValue_ADDR (0x00414cf0)          // read the indexed slot value (+0x44 array)
#define swrUI_FreeElement_ADDR (0x00414d00)           // recursive destroy (fires callback 0x10)
#define swrUI_FindByClass_ADDR (0x00414d60)           // recursive find descendant by class id (+0x18)
#define swrUI_GetById_ADDR (0x00414d90)
#define swrUI_GetFirstSibling_ADDR (0x00414df0)       // walk prev2 to the head
#define swrUI_GetLastSibling_ADDR (0x00414e10)        // walk next2 to the tail
#define swrUI_SetSelected_ADDR (0x00414e30)
#define swrUI_RunCallbacks2_ADDR (0x00414e60)
#define swrUI_IsElementVisible_ADDR (0x00414e80)      // true if this element + all ancestors have flag 0x40
#define swrUI_SetUI4_ADDR (0x00414eb0)                // set the focused element (flag 0x10, callback 1)
#define swrUI_SetUI5_ADDR (0x00414f00)
#define swrUI_FocusElement_ADDR (0x00414f10)          // focus + optionally warp the cursor to the element
#define swrUI_SetFocusedElement_ADDR (0x00414f70)     // the keyboard-focus setter (flag 0x20, msg 0xd)
#define swrUI_GetUI4_ADDR (0x00414fe0)
#define swrUI_GetUI5_ADDR (0x00414ff0)
#define swrUI_GetUI6_ADDR (0x00415000)
#define swrUI_ClearUI5_ADDR (0x00415010)
#define swrUI_RenderTree_ADDR (0x00415020)            // per-frame: step transitions + render sprites + msg 9 (draw)
#define swrUI_HitTest_ADDR (0x004150e0)
#define swrUI_RunCallbacks_ADDR (0x004151a0)
#define swrUI_RenderElementSprites_ADDR (0x004151f0)  // emit one element's sprite slots to the sprite system
#define swrUI_ProcessMouse_ADDR (0x00415400)
#define swrUI_HandleKeyEvent_ADDR (0x00415640)
#define swrUI_StartPageTransition_ADDR (0x004156a0)   // arm the page slide-in (save home pos, offset off-screen)
#define swrUI_ReplaceIndex_ADDR (0x004157d0)
#define swrUI_SetBBox_ADDR (0x00415810)
#define swrUI_DefaultElementProc_ADDR (0x00415850)
#define swrUI_LabelProc_ADDR (0x00415b80)          // basic Label (swrUI_NewLabel)
#define swrUI_ButtonProc_ADDR (0x00415ca0)         // Button (swrUI_NewButton)
#define swrUI_ScreenTextProc_ADDR (0x00415ed0)     // class 3   (swrUI_NewScreenText)
#define swrUI_ListProc_ADDR (0x00416130)           // class 5   (swrUI_NewList)
#define swrUI_TextEntryProc_ADDR (0x00416370)      // class 9   (swrUI_NewTextEntry)
#define swrUI_NumberFieldProc_ADDR (0x00416690)    // class 6   (swrUI_NewNumberField)
#define swrUI_DialogProc_ADDR (0x00416820)         // swrUI_NewDialog container (pass-through)
#define swrUI_Enqueue_ADDR (0x00416840)
#define swrUI_UnlinkElement_ADDR (0x00416890)         // unlink from the parent's child list
#define swrUI_ClearElementRefs_ADDR (0x004168f0)      // null this element out of the UI4/UI5/UI6 globals
#define swrUI_StepPageTransition_ADDR (0x00416930)    // per-frame transition tick (lerp toward home)
#define swrUI_NavigateFocus_ADDR (0x00416a40)         // arrow-key focus movement (VK 0x25-0x28)
#define swrUI_ProcessNavAxis_ADDR (0x00416bd0)        // analog axis -> synthetic nav keys
#define swrUI_QuantizeNavAxis_ADDR (0x00416cc0)       // analog x/y -> discrete -2..2
#define swrUI_HandleKeyEvent2_ADDR (0x00416D70)
#define swrUI_New_ADDR (0x00416d90)
#define swrUI_OnSetElementSize_ADDR (0x00416f20)
#define swrUI_OnSetElementPos_ADDR (0x00416f50)
#define swrUI_ClearAllSprites_ADDR (0x00417060)
#define swrUI_SetSpriteRect_ADDR (0x004171a0)         // configure a sprite slot's dest rect + texture UV scale
#define swrUI_ElementContainsPoint_ADDR (0x004172a0)
#define swrUI_UpdateElementColor_ADDR (0x004172f0)
#define swrUI_DrawText_ADDR (0x004173c0)
#define swrUI_replaceAllocatedStr_ADDR (0x004174e0)
#define swrUI_DrawTextAligned_ADDR (0x00417540)
#define swrUI_IsElementFocused_ADDR (0x00417670)
#define swrUI_SetHighlightState_ADDR (0x00417690)
#define swrUI_GetPaddedTextBBox_ADDR (0x004176f0)
#define swrUI_GetButtonRowBBox_ADDR (0x004177b0)
#define swrUI_FramedTextProc_ADDR (0x00417940)     // class 0xa (swrUI_NewFramedText; checkable/radio item)
#define swrUI_3PatchBoxProc_ADDR (0x00417be0)      // class 0xb (swrUI_New3PatchBox)
#define swrUI_RefreshListLayout_ADDR (0x00417ca0)     // re-layout / scroll items, draw selection, spawn scrollbar
#define swrUI_DrawWrappedText_ADDR (0x00417fe0)
#define swrUI_UpdateTimers_ADDR (0x004180c0)          // tick all UI timers
#define swrUI_HandleTextEntryKey_ADDR (0x00418120)    // text-entry edit handler (insert/erase/cursor/commit)
#define swrUI_DrawCaret_ADDR (0x004184d0)             // draw/blink the text caret sprite (0xfa)
#define swrUI_GetSubstringWidth_ADDR (0x00418680)
#define swrUI_ClearGroupChecked_ADDR (0x00418b70)
#define swrUI_ApplyListColors_ADDR (0x00418bc0)       // propagate the list's 5 color sets to its items
#define swrUI_BuildHighlightSprites_ADDR (0x00418cb0)
#define swrUI_SetSpriteOffset_ADDR (0x00419030)
#define swrUI_GetFrameTextureDim_ADDR (0x00419070)     // pick a window-frame sprite by flag bits, return its texture dims
#define swrUI_RandomizeSpriteAlpha_ADDR (0x00419140)   // randomize alpha over a range of an element's sprites
#define swrUI_Menu_MpSelectVehicle_ADDR (0x004191f0)
#define swrUI_Menu_MpSelectPlanet_ADDR (0x00419390)
#define swrUI_Menu_MpPage83_ADDR (0x004194c0)
#define swrUI_Menu_MpPage84_ADDR (0x00419570)
#define swrUI_Menu_MpPage88_ADDR (0x00419620)
#define swrUI_Menu_MpPage89_ADDR (0x004196b0)
#define swrUI_Menu_MpPage85_ADDR (0x00419700)
#define swrUI_Menu_MpPage86_ADDR (0x00419770)
#define swrUI_BuildPanelFrame_ADDR (0x00419830)       // build the panel's 9-slice background sprites
#define swrUI_BuildSliderSprites_ADDR (0x00419db0)    // render a slider/scrollbar (track/fill/thumb/ticks) from its value
#define swrUI_HandleSliderKey_ADDR (0x0041a640)        // +/- (key) adjust of a slider value, clamped 0-100
#define swrUI_HandleSliderClick_ADDR (0x0041a750)      // mouse hit-test on a slider's end caps -> HandleSliderKey
#define swrUI_BroadcastToWindowsRecurse_ADDR (0x0041aa40) // recursive worker for swrUI_BroadcastToWindows
#define swrUI_BuildEditSelectionSprites_ADDR (0x0041aa90) // 3-patch selection-highlight frame for an edit field
#define swrUI_CreateRaceResultRow_ADDR (0x0041abb0)    // factory for a race-result row widget (-> RaceResultRowProc)
#define swrUI_RaceResultRowProc_ADDR (0x0041ac00)  // race standings/results row
#define swrUI_DrawRaceResultRow_ADDR (0x0041ac30)
#define swrUI_LayoutRadioGroup_ADDR (0x0041af00)      // build a horizontal N-cell segmented frame; returns cell label positions
#define swrUI_NewPanel_ADDR (0x0041b260)              // class 8: a 9-slice framed panel
#define swrUI_ClearListSelection_ADDR (0x0041b300)    // deselect all list items
#define swrUI_IsFocusable_ADDR (0x0041b380)           // is the element navigable (visible+enabled, or a list item)
#define swrUI_NextFocusable_ADDR (0x0041b3c0)         // next focusable sibling (forward)
#define swrUI_PrevFocusable_ADDR (0x0041b3f0)         // previous focusable sibling (backward)
#define swrUI_FocusFirstOnNav_ADDR (0x0041b420)       // focus the page's first element on a nav key (none focused)
#define swrUI_RefreshPageButtons_ADDR (0x0041b470)    // refresh a page's OK (id 2) + Back (id 4) buttons
#define swrUI_SortListItems_ADDR (0x0041b4d0)         // reorder list items by their assigned index
#define swrUI_FindCheckedGroupItem_ADDR (0x0041b590)
#define swrUI_GetByValue_ADDR (0x0041b5e0)
#define swrUI_ApplyFocusColor_ADDR (0x0041b630)
#define swrUI_ProcessPendingClose_ADDR (0x0041b690)   // free a deferred element + completion callback (msg 0x64)
#define swrUI_Menu_MpSessionType_ADDR (0x0041ead0)
#define swrUI_Menu_MpCreateGame_ADDR (0x0041ede0)
#define swrUI_Menu_MpJoinGame_ADDR (0x0041f330)
#define swrUI_Menu_MpRaceSetup_ADDR (0x0041fc70)
#define swrUI_Menu_MpRacerList_ADDR (0x004206b0)
#define swrUI_Front_LoadTrackFromId_ADDR (0x00420930)
#define swrUI_Front_HandleCircuits_ADDR (0x0043b0b0)
#define swrUI_Front_TextMenu_ADDR (0x0043fce0)
#define swrUI_Front_MenuAxisHorizontal_ADDR (0x00440150)
#define swrUI_Front_DrawRecord_ADDR (0x004403e0)
#define swrUI_Front_GetTrackNameFromId_ADDR (0x00440620)
#define swrUI_Front_BeatEverything1stPlace_ADDR (0x00440bc0)
#define swrUI_Front_LoadPlanetModels_ADDR (0x00457C20)
#define swrUI_Front_LoadMapPartModels_ADDR (0x00457CF0)
#define swrUI_Front_LoadUIElements_ADDR (0x00457ed0)
#define swrUI_Front_LoadWindowUIElements_ADDR (0x00457fd0)
#define swrUI_Front_LoadPartsUIElements_ADDR (0x004580e0)
#define swrUI_Front_LoadSelectionsUIElements_ADDR (0x00458250)

// ---- swrUI_Menu_*: F2 page procs for the main-menu / settings screens (0x401-0x403) ----
int swrUI_Menu_Main(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2);
int swrUI_Menu_SettingsHub(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2);
int swrUI_Menu_VideoSettings(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2);
int swrUI_Menu_AudioSettings(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2);
int swrUI_Menu_ForceFeedback(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2);

// Settings sub-screens:
int swrUI_Menu_SaveLoadConfig(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2); // config-profile save/load (window 0x2730)
int swrUI_Menu_ReservedSettings(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2); // reserved/advanced settings (window 0x1c)
// Multiplayer menu page procs (session setup + the hangar MP nav-overlay windows 0x81-0x89):
int swrUI_Menu_MpSessionType(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2); // host vs join + track-change permission
int swrUI_Menu_MpCreateGame(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2); // host/create game (window 0x186aa)
int swrUI_Menu_MpJoinGame(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2);   // join a game + name entry (window 0x186ab)
int swrUI_Menu_MpRaceSetup(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2); // track preview + start, host-gated
int swrUI_Menu_MpRacerList(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2);
int swrUI_Menu_MpSelectVehicle(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2); // window 0x81: sets SELECT_VEHICLE + RacerPick
int swrUI_Menu_MpSelectPlanet(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2); // window 0x82: sets SELECT_PLANET
// Thin MP hangar nav-overlay handlers (windows 0x83-0x89; reparent to container 0x30d51, feed nav input):
int swrUI_Menu_MpPage83(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2);
int swrUI_Menu_MpPage84(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2);
int swrUI_Menu_MpPage85(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2);
int swrUI_Menu_MpPage86(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2);
int swrUI_Menu_MpPage88(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2);
int swrUI_Menu_MpPage89(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2);
void swrUI_UpdateMouseState(void);
void swrUI_PushMenuPage(int pageId);
void swrUI_PopMenuPage(void);

// ---- Menu page stack + page builders + element layout/state (UI-range mapping) ----

void swrUI_BroadcastToWindows(int forward2, int forward3);
void swrUI_BroadcastToWindowsRecurse(swrUI_unk* node, int forward2, int forward3);
int swrUI_IsPrevPage(int id, int flag);
void swrUI_AddNavButton(swrUI_unk* page, int id, int x, int y, int kind);
void swrUI_AddOkButton(swrUI_unk* page, int x, int y);
void swrUI_AddRestoreButton(swrUI_unk* page, int x, int y);
void swrUI_AddDefaultButton(swrUI_unk* page, int x, int y);
void swrUI_RefreshRoot(void);
void swrUI_AlignElementTo(swrUI_unk* a, swrUI_unk* b, unsigned int edgeFlags);
void swrUI_CenterElement(swrUI_unk* ui, int centerX, int centerY);
void swrUI_EnableElement(swrUI_unk* ui);
void swrUI_DisableElement(swrUI_unk* ui);
void swrUI_ResetPageStack(void);
int swrUI_GetPageStackDepth(void);
swrUI_unk* swrUI_GetCurrentPage(void);
void swrUI_ReparentElement(swrUI_unk* parent, swrUI_unk* element);
void swrUI_BuildAuxPages(void);
int swrUI_AddSprite(swrUI_unk* ui, int index, int spriteId, int* rect, int flag, int flag2);
swrUI_unk* swrUI_NewWindow(swrUI_unk* parent, int* rect, int id, swrUI_unk_F2* f2);
swrUI_unk* swrUI_NewLabel(swrUI_unk* parent, int id, int font, char* text, int x, int y, int flags, int param8);
swrUI_unk* swrUI_NewButton(swrUI_unk* parent, int id, int font, char* text, int x, int y, int width, int height, int flags, int param10);
void swrUI_ShowConfirmDialog(swrUI_unk* parent, int id1, int id2, void* unk, char* message, char* yesLabel, char* noLabel, int param8, int param9);
void swrUI_SetSize(swrUI_unk* ui, int width, int height);
void swrUI_SetPos(swrUI_unk* ui, int x, int y);
// Class 3: a positioned/sized screen-text element (text applied via swrUI_RunCallbacksScreenText).
swrUI_unk* swrUI_NewScreenText(swrUI_unk* parent, int id, int index, char* text, int unk5, int x, int y, int width, int height, int unk10, int flags, int sizeUnk);
// Class 7: a sprite element bound to a rect with a user F2 callback (e.g. a clickable icon).
swrUI_unk* swrUI_NewSpriteElement(swrUI_unk* parent, int id, int* rect, int spriteId, int spriteFlag, swrUI_unk_F2* f2, int sizeUnk);
// Class 0xa: text framed by border sprites (0xfa3 left / 0xfa4 right).
swrUI_unk* swrUI_NewFramedText(swrUI_unk* parent, int id, int index, char* text, int x, int y, int width, int height, int flags, int flags2);
// Class 0xb: a 3-slice ("3-patch") sprite box; style (0x10000/0x20000/0x40000/0x80000) picks the sprite set.
swrUI_unk* swrUI_New3PatchBox(swrUI_unk* parent, int id, int index, char* text, int x, int y, int width, int style, int center, int flags, int sizeUnk);
// Modal dialog: title label + word-wrapped message + up to 3 buttons, screen-centered (x/y == -1 centers). swrUI_ShowConfirmDialog wraps this.
swrUI_unk* swrUI_NewDialog(swrUI_unk* parent, int x, int y, char* title, char* message, char* button1, char* button2, char* button3, swrUI_unk_F2* f2);
// Word-wrap a string to the element's bbox width and draw it line by line (splits on spaces).
void swrUI_DrawWrappedText(swrUI_unk* ui, char* text, int flag);
swrUI_unk* swrUI_HitTest(swrUI_unk* root, int cursor_x, int cursor_y);
void swrUI_ProcessMouse(void);
int swrUI_DefaultElementProc(swrUI_unk* ui, unsigned int msg, void* param, int param2);
void swrUI_OnSetElementSize(swrUI_unk* ui, int width, int height);
void swrUI_OnSetElementPos(swrUI_unk* ui, int x, int y);

// ---- Per-class F1 element procs (the "F1 callback" set at the top of this file) ----
// Each widget class registers one of these via swrUI_New; all tail-call swrUI_DefaultElementProc.

int swrUI_LabelProc(swrUI_unk* ui, unsigned int msg, void* param, int param2);
int swrUI_ButtonProc(swrUI_unk* ui, unsigned int msg, void* param, int param2);
int swrUI_ScreenTextProc(swrUI_unk* ui, unsigned int msg, void* param, int param2);
int swrUI_ListProc(swrUI_unk* ui, unsigned int msg, void* param, int param2);
int swrUI_TextEntryProc(swrUI_unk* ui, unsigned int msg, void* param, int param2);
int swrUI_NumberFieldProc(swrUI_unk* ui, unsigned int msg, void* param, int param2);
int swrUI_DialogProc(swrUI_unk* ui, unsigned int msg, void* param, int param2);
int swrUI_FramedTextProc(swrUI_unk* ui, unsigned int msg, void* param, int param2);
int swrUI_3PatchBoxProc(swrUI_unk* ui, unsigned int msg, void* param, int param2);
int swrUI_RaceResultRowProc(swrUI_unk* ui, unsigned int msg, void* param, int param2);
swrUI_unk* swrUI_CreateRaceResultRow(int id); // factory: new race-result row widget bound to RaceResultRowProc

// ---- swrUI element internals (draw / measure / hit-test / state; used by the procs above) ----

// Prefix a font/style code then emit a swrText entry at (x, y) (the UI text-draw primitive).
void swrUI_DrawText(int font, int x, int y, int color0, int color1, int color2, int color3, char* text, int unk9, int unk10, int disabled);
// Align text within bbox (0x10000 center-x / 0x20000 center-y / 0x40000 center / 0x80000 right; 0x100000/0x200000 indent) then swrUI_DrawText.
void swrUI_DrawTextAligned(int font, char* text, short* bbox, unsigned int alignFlags, int color0, int color1, int color2, int color3, int unk9, int unk10, int unk11);
// Write a padded text bbox: width + 0x13, height + 0x1d.
void swrUI_GetPaddedTextBBox(int* bbox_out, char* text, int font);
// Size a 1-3 button row from its labels; writes the row bbox and returns the uniform button width.
unsigned int swrUI_GetButtonRowBBox(int* bbox_out, char* label1, char* label2, char* label3, int font);
// Sum glyph advance widths over substring [start, end) of text.
int swrUI_GetSubstringWidth(char* text, int font, unsigned int start, int end);
// Hit-test a point against the element's bbox (+0x24).
int swrUI_ElementContainsPoint(swrUI_unk* ui, int x, int y);
// True when ui is the focused element.
int swrUI_IsElementFocused(swrUI_unk* ui);
// Recompute the element's display color from its state flags, then refresh highlight sprites.
void swrUI_UpdateElementColor(swrUI_unk* ui);
// Set/clear the highlight bit; optionally refresh color and fire the hover callback (1000/1001).
void swrUI_SetHighlightState(int mode, swrUI_unk* ui, int highlighted, int fireCallback, int refreshColor);
// Apply the 2-state (focused vs default) element color.
void swrUI_ApplyFocusColor(swrUI_unk* ui);
// Set/clear the checked bit and check/radio sprite; fires callback 5000 on change.
void swrUI_SetChecked(swrUI_unk* ui, unsigned int checked);
// Toggle the checked state.
void swrUI_ToggleChecked(swrUI_unk* ui);
// Return the currently-checked item in the radio group, or NULL.
swrUI_unk* swrUI_FindCheckedGroupItem(swrUI_unk* ui);
// Uncheck every checked item in the radio group (single-select enforce).
void swrUI_ClearGroupChecked(swrUI_unk* ui);
// Per-sprite-slot setters (up to 20 slots per element).
void swrUI_SetSpriteOffset(swrUI_unk* ui, int slot, int offsetX, int offsetY);
void swrUI_SetSpriteColor(swrUI_unk* ui, int slot, uint8_t r, uint8_t g, uint8_t b, uint8_t a);
// Build the selection/highlight bracket sprites around an element.
void swrUI_BuildHighlightSprites(swrUI_unk* ui, int highlighted);
// Count selectable (visible + enabled) child items.
int swrUI_CountSelectableItems(swrUI_unk* ui);
// Draw one racer's standings/results row (position, names, lap/final/total).
void swrUI_DrawRaceResultRow(swrUI_unk* row);

// 0041ac00 swrUI_fun_unk(swrUI_unk* ui_unk, int p2, int p3, int p4)

// 0x004206b0 swrUI_fun_unk2(int p1, int p2, int p3, int p4)

// 0x00416d90

// 0x0043b880 Planet before race screen

// 0x0043ec10 Strong SHOP Candidate

void swrUI_UpdateProgressBar(int progressPercent);

void swrUI_ResetProgressBar(void);

swrUI_unk* swrUI_GetUI1(void);

int swrUI_GetValue(swrUI_unk* ui);

int swrUI_RunCallbacksScreenText(swrUI_unk* ui, char* screenText, int bool_unk);
char* swrUI_GetAllocatedString(swrUI_unk* ui, char* str_out, int len);
void swrUI_SetColorUnk(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a);
void swrUI_SetColorUnk4(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a);
void swrUI_SetColorUnk3(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a);
void swrUI_SetColorUnk5(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a);
void swrUI_SetColorUnk2(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a);

swrUI_unk* swrUI_GetById(swrUI_unk* ui, int id);

void swrUI_SetSelected(swrUI_unk* ui, int bSelected);

int swrUI_RunCallbacks2(swrUI_unk* ui, int bool_unk);

void swrUI_SetUI5(swrUI_unk* ui);

swrUI_unk* swrUI_GetUI4(void);

swrUI_unk* swrUI_GetUI5(void);

swrUI_unk* swrUI_GetUI6(void);

void swrUI_ClearUI5(void);

int swrUI_HandleKeyEvent(int virtual_key_code, int pressed);

int swrUI_RunCallbacks(swrUI_unk* ui, int forward1, int forward2, int forward3);

int swrUI_ReplaceIndex(swrUI_unk* ui, int new_index);

void swrUI_SetBBox(swrUI_unk* ui, int x, int y, int x2, int y2);

void swrUI_Enqueue(swrUI_unk* ui1, swrUI_unk* toEnqueue);

int swrUI_HandleKeyEvent2(void* forward2, int);
swrUI_unk* swrUI_New(swrUI_unk* ui, int id, int new_index, char* mondo_text, int flag, int size_unk2, int size_unk1, swrUI_unk_F1* f1, swrUI_unk_F2* f2);

void swrUI_ClearAllSprites(swrUI_unk* ui);

char* swrUI_replaceAllocatedStr(char* str, char* mondo_text);

swrUI_unk* swrUI_GetByValue(swrUI_unk* ui, int value);

void swrUI_Front_LoadTrackFromId(swrRace_TRACK trackId, char* buffer, size_t len);

void swrUI_Front_HandleCircuits(swrObjHang* hang);

void swrUI_Front_TextMenu(swrObjHang* hang, int posX, int posY, int param_4, int param_5, int param_6, char* screenText);

void swrUI_Front_MenuAxisHorizontal(void* pUnused, short posY);

void swrUI_Front_DrawRecord(swrObjHang* hang, int param_2, int param_3, float param_4, char param_5);

char* swrUI_Front_GetTrackNameFromId(int trackId);

bool swrUI_Front_BeatEverything1stPlace(swrObjHang* hang);

void swrUI_Front_LoadPlanetModels();
void swrUI_Front_LoadMapPartModels();
void swrUI_Front_LoadUIElements(void);
void swrUI_Front_LoadWindowUIElements(void);
void swrUI_Front_LoadPartsUIElements(void);
void swrUI_Front_LoadSelectionsUIElements(void);

// Initialize the UI system: allocate the element hash table, zero the element arrays, install
// the default element proc, and run the one-time CPU-speed calibration loop. Called at boot.
int swrUI_Initialize(void);

// ---- List-widget item management (swrUI_NewList items are class 0xc) ----

void swrUI_SetMaxLength(swrUI_unk* ui, int maxLength);
swrUI_unk* swrUI_FindChildByText(swrUI_unk* list, char* text);
int swrUI_GetSelectedIndex(swrUI_unk* list);
swrUI_unk* swrUI_GetSelectableItem(swrUI_unk* list, int index);
swrUI_unk* swrUI_GetSelectedItem(swrUI_unk* list);
void swrUI_RefreshListSelection(swrUI_unk* list);
void swrUI_SelectListItem(swrUI_unk* item, int bSelect);
void swrUI_RestoreListSelection(swrUI_unk* list);
swrUI_unk* swrUI_AddListItem(swrUI_unk* list, char* text, int value, int id, int param5);
swrUI_unk* swrUI_AddListElement(swrUI_unk* list, swrUI_unk* element);
void swrUI_SetListHighlightColor(swrUI_unk* list, uint8_t r, uint8_t g, uint8_t b, uint8_t a);
void swrUI_ApplyListColors(swrUI_unk* list);
void swrUI_RefreshListLayout(swrUI_unk* list);

// ---- Element lifecycle + accessors ----

void swrUI_FreeElement(swrUI_unk* element);
void swrUI_UnlinkElement(swrUI_unk* element);
void swrUI_ClearElementRefs(swrUI_unk* element);
swrUI_unk* swrUI_FindByClass(swrUI_unk* root, int classId);
void swrUI_SetValueText(swrUI_unk* ui, char* text, int value);
char* swrUI_GetValueText(swrUI_unk* ui, char* out, int len);
int swrUI_SetSlotValue(swrUI_unk* ui, int index, int value);
int swrUI_IsElementVisible(swrUI_unk* ui);
void swrUI_SetUI4(swrUI_unk* ui);
void swrUI_SetSpriteFlag(swrUI_unk* ui, int slot, int enabled);

// ---- Event dispatch / render / focus-navigation / timers / caret (UI runtime) ----
// Message codes: 0xd focus-change, 0xe layout, 9 draw, 0x10 destroy, 0x45 timer-fire,
// 0x46 page-enter, 0x47 page-leave, 0x48 transition, 0x4a window-broadcast.

void swrUI_RenderTree(swrUI_unk* node);
void swrUI_RenderElementSprites(swrUI_unk* ui);
void swrUI_StartPageTransition(swrUI_unk* page, int mode);
int swrUI_StepPageTransition(swrUI_unk* element);
void swrUI_SetFocusedElement(swrUI_unk* element);
void swrUI_FocusElement(swrUI_unk* element, int moveCursor);
int swrUI_IsFocusable(swrUI_unk* element);
swrUI_unk* swrUI_NextFocusable(swrUI_unk* element);
swrUI_unk* swrUI_PrevFocusable(swrUI_unk* element);
void swrUI_NavigateFocus(swrUI_unk* element, int vk);
void swrUI_FocusFirstOnNav(int vk);
void swrUI_ProcessNavAxis(void);
void swrUI_QuantizeNavAxis(float x, float y, int* outX, int* outY);
swrUI_unk* swrUI_GetFirstSibling(swrUI_unk* element);
swrUI_unk* swrUI_GetLastSibling(swrUI_unk* element);
void swrUI_AddTimer(swrUI_unk* target, int interval, int param);
void swrUI_RemoveTimer(int param);
void swrUI_UpdateTimers(void);
void swrUI_DrawCaret(void);
void swrUI_SetCaretActive(int active);
void swrUI_SetCaretRect(int x, int y, int w, int h);
void swrUI_ProcessPendingClose(void);

// ---- Panels, list ops, text-entry editing, lifecycle (UI-range mapping) ----

void swrUI_Shutdown(void);
swrUI_unk* swrUI_NewPanel(swrUI_unk* parent, int id, int* rect, int kind);
void swrUI_BuildPanelFrame(swrUI_unk* ui, int kind, int param3);
void swrUI_SetSpriteRect(swrUI_unk* ui, int slot, int* rect);
void swrUI_HandleTextEntryKey(swrUI_unk* ui, int key);
void swrUI_ClearListSelection(swrUI_unk* list);
void swrUI_SortListItems(swrUI_unk* list);
void swrUI_RefreshPageButtons(swrUI_unk* page, int backArg, int okArg);

// ---- Value / slider widgets + radio-group layout ----

int swrUI_GetNumberValue(swrUI_unk* ui);
void swrUI_SetNumberValue(swrUI_unk* ui, int value);
void swrUI_SetSliderValue(swrUI_unk* ui, int percent);
void swrUI_SetValue(swrUI_unk* ui, int value);
int swrUI_GetSlotValue(swrUI_unk* ui, int index);
void swrUI_BuildSliderSprites(swrUI_unk* slider, int state);
void swrUI_HandleSliderKey(swrUI_unk* slider, unsigned int key);        // +/- adjust slider value, clamped 0-100
void swrUI_HandleSliderClick(swrUI_unk* slider, int mouseX, int mouseY); // hit-test slider end caps -> HandleSliderKey
void swrUI_GetFrameTextureDim(int flags, int* outWidth, int* outHeight); // window-frame sprite dims chosen by flag bits
void swrUI_RandomizeSpriteAlpha(swrUI_unk* element);                     // random alpha over an element's sprite range
void swrUI_BuildEditSelectionSprites(int a1, swrUI_unk* ui, int* rect);  // 3-patch selection-highlight frame for an edit field
int swrUI_LayoutRadioGroup(swrUI_unk* elem, int y, unsigned int minWidth, int count, int* outPositions);

#endif // SWRUI_H
