# Controller Config Roadmap

Harden SWE1R's controller-configuration page (the joystick/mouse/keyboard binding menus,
binding capture, and profile save/load). Local planning doc.

The page is `swrControl_MappingsMenu` @0x402250 + the `swrConfig_Build{Joystick,Mouse,Keyboard}Menu`
builders + `swrConfig_RefreshMappingMenu` @0x40b740, feeding the binding tables
(joystick @0x4d5fc0 / mouse @0x4d6518 / keyboard @0x4d6828, 12-byte entries
`{u32 flags; i32 input; i32 action}`, 0xff-flags-byte terminated; counts int[3] @0x4d5e20).
Profiles live at `.\data\config\<name>\<name>_control.map`.

## Shipped (delta layer, built + deployed, pending playtest)

All in `dinput_hook/game_deltas/stdControl_delta.c` + hooks in `renderer_hook.cpp`, plus the
friendly-names prototype in `gamepad_button_names_delta.cpp`.

- **A** - `swrControl_FindKeyName` (0x407d90) NULL-deref crash when re-binding a control that is
  already mapped. Delta returns "" only at the two CaptureBinding sites; NULL preserved for the
  save path.
- **B** - hot-plug joystick detection flakiness (consistent detect/enable flags + fall back to
  device 0 when the saved-GUID match misses).
- **C** - config loader `stdConfFile_readAndApplyConf` (0x406470) reimplemented to SKIP an
  unparseable entry instead of `ClearBindings`-wiping the whole device.
- **D** - `swrControl_ClearBindings` (0x407800) reimplemented to write the 0xff terminator after
  zeroing, so `WriteMappings` can never walk off an empty table (the "thousands of junk lines" root).
- **E** - binding-conflict modal (`swrUI_ShowConfirmDialog` 0x4145b0) hangs (re-entrant loop);
  scoped to CaptureBinding's two conflict sites, it now returns "proceed" -> accept the conflict.
- **Overflow guard** - the loader caps per-device adds at 64 so a corrupt config can't overflow
  one binding table into the next.
- **Friendly gamepad button names** (separate PR) - Xbox A/B/X/Y labels for joystick buttons in
  the menu when an XInput pad is connected; display-only (save path stays numeric).

## Audit backlog (2026-07-14 audit; catalogued, verified against decompile)

### Tier 1 - safety / data-loss (SHIPPED into the robustness set, built + deployed, pending playtest)

- **[SHIPPED] #2 mouse sensitivity divide-by-zero.** `swrControl_ApplyAxisConfig` (0x407630)
  `SetMouseRange(1.0f / Sensitivity[1], ...)` @0x40766f, no zero guard. `Sensitivity[1]` (mouse,
  @0xec8784) is 0 when the loaded config has no mouse `SENSITIVITY` line -> INF/NaN range.
  Fix: clamp `sensitivity[]` to the neutral 1.0 default in the loader reimpl (covers the Initialize
  path; the menu slider already clamps).
- **[SHIPPED] #3 false "Saved settings!".** `swrUI_Menu_SaveLoadConfig` (0x401af0) create path
  ignores `stdFileUtil_MkDir` + `WriteMappings`/Video/Audio/FF returns and always shows the success
  toast -> silent data loss on read-only dir / disk full / bad name. Fix: check returns, show an
  error toast on failure.
- **[SHIPPED] #4 unsanitized profile name.** Same function uses the 24-char text-entry name
  verbatim as a folder+filename for MkDir/Write/DelTree (no filter for `\ / .. :` / reserved names),
  and does an unbounded `sprintf(&buf128, "%s", selectedItem->name)` @0x401ba6 (a disk-placed
  >=128-char config folder overflows the stack). Fix: whitelist `[A-Za-z0-9 _-]`, reject reserved
  names, bounded copies. (Traversal is self-harm in a single-player game; the crash needs an
  externally placed folder -> lower real-world severity, but cheap to fix in the same branch.)

### Tier 2 - plausible / lower severity (follow-ups)

- **#1 format-string hazard** - menu labels/titles built via `sprintf(buf, swrText_Translate(str))`
  (the translated string is the printf format). Safe in vanilla EN (uses `~s`/`~c` color tokens,
  no `%`), but a `%` in any EFIGS/mod translation -> stack over-read/crash. Fix: `sprintf(buf,"%s",s)`.
  Route to the localization effort (LOCALIZATION_ROADMAP).
- **#5 input capacity [DEFERRED - needs read-path work + playtest].** NOT a "raise the scan cap"
  fix: `stdControl_ReadJoysticks` (0x486340) reads a DIJOYSTATE but stores only 6 axes (drops the 2
  sliders) and reads only 16 buttons (`uVar10 < 0x10`), stepping 6 axes / 32 key-slots per device.
  So joystick axes 7-8 (sliders / HOTAS throttle) and buttons 17+ are never read regardless of the
  scan caps in `ScanPressedButtons`/`FindMovedAxis`. Supporting them means widening the read loops +
  per-device axis storage (6-wide) -- core input internals, real regression risk, must be playtested.
- **#8 POV/HAT capture [DEFERRED - needs scan index map + playtest].** The POV hat IS read (into key
  indices 0x110+ by ReadJoysticks) so a hat bound via config works in-race, but `ScanPressedButtons`
  only walks the button region `(devIdx+8)*0x20 + [0..31]`, not the POV index range -- so the hat
  can't be captured in the menu. Fix = scan the POV sub-range too; touches the input index map.
- **#6** no `RefreshMappingMenu` after a successful capture (delete path refreshes) -> stale
  combined Roll-L/R row.
- **[SHIPPED] #7** out-of-table button ids showed "(null)" in `FormatBinding` (buttons >=20, past
  the HAT entries). The display hook now returns the 1-based number as a fallback (display only; the
  save path keeps NULL). In gamepad_button_names_delta.cpp alongside the friendly-names override.
  (Axis fallback not done -- the axis label is letters, awkward as a number; low value without #5.)
- **#9** `FindMovedAxis` axis-detect deadzone is 0.5 (must deflect past 50%) -- refuses some
  sticks/pedals (PLAUSIBLE UX).
- **#10** no device-id validation in Scan/FindMovedAxis (OOB read if ever called with a bad device)
  (PLAUSIBLE).
- **#11** remove-profile leaves a stale selection pointer (mitigated by re-fetch) (PLAUSIBLE).
- **#12** `ReplaceMapping` (0x4078a0) swallows `AddMapping`'s failure -> a rebind that fails to
  parse silently no-ops while the UI reports success.
- **#13** load path `GetAllocatedString` into an exact-fit 128-byte buffer -- possible off-by-one
  (PLAUSIBLE).

### Tier 3 - latent / cleanup

- **#14** `AddMapping` (0x4078e0) custom-table (cid not 0/1/2) append path corrupts count/terminator
  (no caller today).
- **#15** `RemoveMapping` (0x407500) `whichone` is 1-based (0 matches nothing).
- **#16** `FindMapping` (0x4079f0) dual-purpose param1 + accidental byte-mask correctness (0x104->0x04).
- **#17** `ApplyAxisConfig` ignores the mouse 3rd axis.
- **#18** `ScanPressedButtons` keyboard bitmask mode always returns 0xffff (latent).
- **#19** `WriteMappings` calls `CloseWrite` on the open-failure branch (double-close smell).

### Cleared (checked, not bugs)

`WriteMappings` per-row `Printf` does push all 4 column args (decompiler dropped one); the
Save/Load title `~sLOAD/SAVE` uses a `~s` color token, not `%s`; `sprintf(buf, wuRegistry_lpClass)`
is a clear-buffer idiom (empty string @0x4d55cc); and Add/Remove/Replace DO keep the terminator +
count consistent (corruption was isolated to `ClearBindings` = Fix D).

## Flexible-binding wishlist (in-game menu path)

- **[SHIPPED, unplaytested - HIGH-RISK] #2 axis direction as a button binding.**
  `capture_binding_delta.cpp` hooks `swrControl_CaptureBinding` and reimplements the button-action
  path (bAnalogCapture==0) so the "press a button" prompt also watches `FindMovedAxis`; pushing a
  stick/trigger binds `dir -> ReplaceMapping(...,1,dir,axis)` = the 0x14/0x24 range trigger. Axis-
  type actions delegate to the original. Uses a "wait for all-released, then capture" prime instead
  of the vanilla edge globals, and skips the conflict modal (accept silently, matching Fix E).
  PLAYTEST FOCUS: button binding is core -- verify a normal button still binds, ESC cancels, the
  bound row shows the right text, and pushing an axis binds it (row shows "+/-<axis> AXIS").
- **[SHIPPED via capture prompt] #3 clear a binding.** Vanilla has a `param_2==0x14 ->
  RemoveMapping + "Deleted!"` on-row path, but it didn't clear joystick bindings (deep UI dispatch;
  and RemoveMapping matches by type so a button-row delete can't remove an axis-range binding from
  feature #2 -- flags 0x04|0x10 lack bit 0x08). Reliable fix in capture_binding_delta.cpp: while
  rebinding a button-action row, press DEL to clear -- removes BOTH the button and axis binding for
  that action+slot, sets the "---" marker. LIMITATION: only button-action rows (I own their capture);
  axis-action rows (TURN/PITCH/throttle/roll/brake) delegate to vanilla and have no clear yet. The
  vanilla on-row Delete dispatch (why it skips joystick) is still un-traced.
- **[SHIPPED] "remove BUTTON word".** Displayed joystick bindings dropped the "BUTTON " prefix (row
  reads "A" not "BUTTON A") by hooking swrText_Translate of the "BUTTON %s" key (0x4b3ed0) to return
  "%s". Menu formatter + post-capture text both affected; config format + all other text untouched.
- **[DEFERRED - hand-laid layout, needs playtest loop] #1 multiple bindings per function.** The
  `SetMappingRowText` `slot` param + flat binding tables already support it; needs extra list rows
  added to the hand-laid `Build*Menu` builders (joystick/mouse show only slot 1; keyboard already
  shows 2) + `Refresh` calls + per-row capture/clear. Untestable blind.
- **[DEFERRED - hand-laid layout, needs playtest loop] #4 flip any axis.** flip array is 6-wide
  (`joyFlip[6]`); menu exposes only X/Y/Z checkboxes (0x55/0x56/0x57) via `LayoutRadioGroup(count)`
  gated on `DAT_00ec887c & 4`. Add RX/RY/RZ checkboxes + `LayoutRadioGroup(6)` + Refresh SetChecked
  + MappingsMenu toggle cases. Untestable blind.

## Unified controls table (wishlist #1, in progress -- branch `feature/controls-unified-table`)

Replace each page's two lists ("Button Settings" + "Axis Settings") with ONE table: one row per
function, three columns (bind each function up to 3x), duplicate rows removed. Scaffold landed in
`dinput_hook/game_deltas/controls_unified_table_delta.cpp`, gated behind `ENABLE_UNIFIED_CONTROLS`
(default 0 -- flip via `-DENABLE_UNIFIED_CONTROLS=1`). Session decision: **preserve analog per-row**
(Turn/Pitch/Throttle keep `bAnalogCapture=1` so proportional steering isn't lost; digital actions
use the axis-aware capture delta). Starting page: **mouse**.

How the engine already supports it (no engine change needed, pure menu layout):
- A menu row is a horizontal group of `swrUI_NewScreenText` widgets. The first carries the label +
  the slot-1 value; each extra label-less cell is a positioned column whose value
  `RefreshMappingMenu` fills via `SetMappingRowText(..., slot=N)`.
- The keyboard page already renders 3 columns (directional rows `0x40`-`0x4b`, slots 1/2/3) --
  it's the layout template (`swrConfig_BuildKeyboardMenu` @0x40dd10 has the column x/width math).
- `SetMappingRowText`'s last arg is the slot; it no-ops on a missing widget id (guards the null
  from `swrUI_GetById`), so filling not-yet-laid-out columns is safe.

Three functions to touch (all hand-laid -> playtest loop, untestable blind):
1. `swrConfig_BuildMouseMenu` @0x40d2c0 -- **the hard part, still TODO**: merge the two lists into
   one, dedup, and create the col-2/col-3 cells (ids from `UNIFIED_CELL_ID_BASE`). Scaffold
   currently delegates to vanilla (page renders; extra columns absent) while the other two halves
   are validated.
2. `swrConfig_RefreshMappingMenu` @0x40b740 -- fills slots 2/3 (implemented in scaffold).
3. `swrControl_MappingsMenu` @0x402250 -- routes a click on a col-2/3 cell to
   `CaptureBinding(slot)` with the row's analog flag (implemented in scaffold). The vanilla col-1
   cells and all other widgets delegate to the stock handler.

Capture keying gotcha: the fnStr passed to `CaptureBinding`/`ReplaceMapping` is the *localized
action-name string* (ParseFunctionName resolves it), so the rebuild must reuse the SAME `STR_*`
strings vanilla `MappingsMenu` uses (catalogued in the scaffold), not the menu display labels.

Open dedup questions (resolve on-screen):
- Brake and Roll appear as BOTH digital button rows and analog axis rows in vanilla. Scaffold lists
  each once; whether a button-only brake/roll stays separately bindable is a UX call.
- Roll's analog row manages ROLL_LEFT+ROLL_RIGHT as a pair (`MappingsMenu` special-cases the clear
  path) -- the merged row must preserve that pairing.

Incremental plan: (a) prove dispatch+refresh with columns injected into the vanilla layout; (b)
merge the two lists + dedup into a single reimplemented builder; (c) repeat for joystick. Then
promote off the flag once the layout is validated.

## PR grouping

1. **Binding robustness PR** (the A-E + overflow set) + Tier-1 **#2 / #3 / #4**.
2. **Input capacity PR** - #5, #7, #8 (bind more buttons/axes + numeric fallback for un-named inputs).
3. **Gamepad button names PR** (the friendly-names prototype).
4. **Localization** - #1 (route to LOCALIZATION_ROADMAP).
5. **Backlog** - the remaining Tier-2/Tier-3 items.
