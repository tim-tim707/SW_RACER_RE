SDF Font Profiles
=================

A "profile" is a named preset that captures all 5 SDF font slots at once (which font
each uses, plus weight, italic/shear, scale, offset, line height, letter spacing and
shadow). Each profile is a single .ini file in this folder -- so a profile is one file
you can share: send it to a friend and they drop it in their own
  <game>/assets/fonts/profiles/
folder to use it.

The crisp-text feature must be ON (Graphics Settings -> "Crisp text (SDF)").

Creating a profile (easiest)
----------------------------
1. Open the debug menu (F5) -> Render -> "SDF Fonts".
2. Tune the slots however you like.
3. Type a name in the "new profile name" box and click "Save As".
That writes <name>.ini here. Use the "Profile" dropdown to switch between saved
profiles; "Save" overwrites the active one, "Delete" removes it, "Reset all to
default" returns every slot to the built-in look.

Sharing
-------
- Send the profile's .ini file. The recipient drops it in this folder and picks it in
  the dropdown (use "Refresh" if the game was already running).
- If the profile uses a CUSTOM font (not the bundled ones), share that .ttf/.otf too --
  put it in assets/fonts/. The mod stores the font path in the profile; if that exact
  path is missing on another machine it falls back to assets/fonts/<same filename>, so
  fonts kept in assets/fonts/ travel with the profile.
- Bundled fonts (DejaVuSans.ttf, Anton-Regular.ttf) are always present, so profiles
  built only from those work everywhere with no extra files.

File format (for hand-editing)
------------------------------
[profile]
name=My Profile          ; display name (informational)

[slot_0]                 ; one section per slot, slot_0 .. slot_4
file=                    ; TTF/OTF path; empty = built-in default (DejaVu/Anton by role)
shear=0                  ; faux-italic slant, 0 = upright (~0.2 = the built-in italic)
weight=0.08              ; SDF weight bias; >0 heavier, <0 thinner
scale=1                  ; size multiplier vs the vanilla cap height
offset_x=0               ; pen nudge, fraction of cap (right = +)
offset_y=0               ; pen nudge, fraction of cap (down = +)
line_height=1            ; multiplier on the line advance (the ~n code)
letter_spacing=0         ; extra advance after each glyph, fraction of em
shadow_off=0             ; 1 = never draw the drop shadow (overrides the ~s code)
shadow_dx=1              ; shadow offset X, design units
shadow_dy=1              ; shadow offset Y, design units
; ... repeat [slot_1] .. [slot_4]

Which slot is which: slot 2 is the big in-race number/time face (reached by ~f1/~f3);
the others are body/menu text. Open the panel to see each slot's ~f codes and role.

Example: one font everywhere (e.g. a total-conversion look)
-----------------------------------------------------------
Point every slot at the same font file and give it uniform settings. Copy an example
below into <name>.ini and set the file= lines to your font (place it in assets/fonts/):

  [profile]
  name=Aurabesh
  [slot_0]
  file=assets/fonts/Aurabesh.ttf
  shear=0
  weight=0
  scale=1
  ; (repeat slot_1..slot_4 with the same file=)
