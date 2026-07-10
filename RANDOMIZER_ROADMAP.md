# SW_RACER_RE — Profile Randomizer Roadmap

**Status:** design (2026-07-10). Living document. Owner: lightningpirate.

Goal: a **per-profile randomizer** — the player opts in when creating a profile, picks which
categories to shuffle, and that randomization is **locked to the profile for its lifetime**
(like a seeded run in any randomizer). The profile *name is the seed*, so runs are reproducible
and shareable ("make a profile named `Watto` and race my seed").

Like the modding, modes/modifiers, replay, and character work, this is a **delta on understood
behavior**: it lives entirely in the `dinput_hook/` Microsoft Detours layer, **not** in `src/`.
The faithful `src/Swr` reimpls stay byte-clean; `dinput_hook/` owns the seed derivation, the
per-profile config sidecar, the shuffle streams, the creation-time snapshot, and the ImGui
config panel. Keeping the sim untouched also protects the run-verification story
(`VERIFICATION_ROADMAP.md`) and leaves the vanilla `tgfd.dat` format unmodified.

> **Addresses/offsets below come from the Ghidra DB + source exploration (2026-07-10) and MUST
> be reconfirmed against the live DB at implementation time** — the Steam EXE `.text` is
> SteamStub-encrypted on disk, so verify via Ghidra disasm or runtime (Cheat Engine), not file
> bytes. Effort tags: **S** < ~half day, **M** ~1-2 sessions, **L** multi-session.

---

## 1. The core realization — the name is the seed, no save-format change

The obvious instinct is to store a random seed *in* the profile. The save format fights that:
`tgfd.dat` is a fixed **0xFD4-byte** blob, CRC32-protected (`swrRace_ComputeSaveChecksum` @
`0x0044e440`, magic `0x10003`), and each profile is a fixed **0x50-byte** slot with only ~5
genuinely-unused bytes. A real seed field would mean bumping the magic, recomputing the CRC, and
writing a save-migration path — invasive, and it breaks vanilla-save compatibility.

**So we don't store a seed. We derive it.** Every profile already has one immutable identity:
`profileName` (slot offset `0x00`, 32 bytes, set once at creation and never changed). Therefore:

```
profile_seed = hash(profileName)      // FNV-1a / xxHash over the 32-byte name field
```

- **Zero save-format change** — vanilla `tgfd.dat` layout untouched; a profile with the
  randomizer off is byte-for-byte a normal profile.
- **Reproducible + shareable** — same name ⇒ same seed ⇒ same randomization.
- **Survives sidecar loss** — the seed is recoverable from the name alone.

The player's *choices* (which categories are on) can't be recovered from the name, so they live
in a **delta-layer sidecar** keyed by name: an INI file `data/player/randomizer.ini` with one
section per profile (matches the layer's existing `Get/WritePrivateProfile` config convention and
sits next to the real `tgfd.dat`, without touching it; no JSON dependency). The sidecar
is written **once, at profile creation, then treated as read-only** for that profile.

---

## 2. Config is chosen once at creation and locked

This mirrors a normal randomizer: you pick settings, generate the seed, and that's your run.
There is **no** in-race retoggling. The player cannot change a profile's ruleset after it exists;
to try a different mix they create a new profile.

**Master toggle default = OFF.** With the master off we write **no sidecar** (or an all-off one),
so the profile is a completely vanilla profile with zero footprint. Randomization is strictly
opt-in.

### Two application classes (implementation detail, invisible to the player)

Everything the randomizer touches divides by *where the randomized value physically has to live*.
Both are frozen at creation; the split is purely mechanical.

| Class | Mechanism | Why | Examples |
|---|---|---|---|
| **A — baked into the save** | write randomized values into the profile once, at the creation hook | these are persistent state the game itself mutates + reads from the save | starting unlocks, starting truguts |
| **B — re-derived each race** | delta re-lays the deterministic shuffle at race start from the frozen seed+config | these are runtime tables the game reloads/overwrites every race, so a one-time write wouldn't stick | pod-stat shuffle, AI difficulty, track order, character-pod binding |

Class B is *not* re-rolled — the seed + config are frozen, so the shuffle is byte-identical every
race. It just has to be re-applied because the game rebuilds those tables per race.

### Independent sub-streams so categories are orthogonal

Do **not** consume one linear RNG in order — then adding/removing a category shifts every
downstream result. Give each category its own stream keyed by name:

```
rng_pods    = PRNG(profile_seed ^ hash("pods"))
rng_ai      = PRNG(profile_seed ^ hash("ai"))
rng_tracks  = PRNG(profile_seed ^ hash("tracks"))
rng_roster  = PRNG(profile_seed ^ hash("roster"))
rng_start   = PRNG(profile_seed ^ hash("start"))
```

Use a **dedicated PRNG**, never the game's `swrUtils_Rand` (@ `0x0050cb7c`) — that state is
consumed every frame by particles/effects/Elmo timing, so borrowing it desyncs effects and makes
results non-reproducible.

---

## 3. Category catalog

Each category is one checkbox in the config panel and one sub-stream. Addresses/status from the
2026-07-10 exploration.

| Category | Class | Data / hook seam | Effort | Status / notes |
|---|---|---|---|---|
| **AI difficulty** | B | write `swrRace_AILevel` @ `0x004c707c` + `ai_spread` @ `0x004c7080` per race (set once at track load by `InitAISettingsForTrack` @ `0x004667e0`, read per-frame, never cached) | **S** | **Lowest-effort, immediately observable — Phase 1 MVP category.** Can go per-racer asymmetric later. |
| **Starting unlocks / money** | A | randomize `podracers_unlocked` (profile `+0x34`) / `race_unlocked` (`+0x25`) / `truguts` (`+0x38`) at the creation hook `swrRace_GenerateDefaultDataSAV` @ `0x0043ea00` | **S-M** | Must guarantee at least one drivable pod is unlocked, or the profile is soft-locked. |
| **Track order** | B | shuffle circuit->track map `g_aTrackIDs[28]` @ `0x004c0018` | **S-M** | Path already exists via `tracks_delta.c`. Shuffle within-circuit (safe) vs global (needs care re: unlock gating). |
| **Pod handling stats** | B | permute the 23-entry `PodHandlingData[23]` @ `0x004c2bb0` (stride `0x3c`) — reorder existing entries, apply at `swrObjHang_BuildRosterSinglePlayer` @ `0x0045b947` | **M** | Reordering existing entries, **not** inflation — does not depend on the `CHARACTERS_ROADMAP.md` roster-inflation work. "Anakin's pod now handles like Sebulba's." |
| **Character <-> pod binding** | B | shuffle `pod_modelID` / `pod_alt_modelID` in `swrRacer_PodData[23]` @ `0x004c2700` (stride `0x34`) | **M** | Cosmetic/model remap; verify puppet + engine/cockpit xform table (`0x004c7088`, stride `0x6c`) stays consistent per entry. |
| **Shop / upgrade prices** | — | **not RE'd** — no price table located as of 2026-07-10 | **BLOCKED** | Unblock requires reversing the hangar shop pricing. Deferred. |

---

## 4. Config UI — contextual auto-popup at profile creation

A **native in-game toggle** on the name-entry screen is expensive: those front-end screens
(`swrObjHang_UpdateEnterName` @ `0x004367c0`, profile-select page `0x2736` @ `0x00401340`) are
opaque monolithic binary procs — not reimplemented, hardcoded 640x480 widget layout, complex
focus/input routing, and no delta-layer precedent for *adding* a widget to an existing page.
That's a multi-session carve for a checkbox. **Documented here as a future/stretch item, not a
blocker.**

Instead, use the **ImGui overlay** — which `imgui_Update()` (`imgui_utils.cpp`) draws every frame
with **no game-state gate**, so it already works over the front-end menus, not just in-race.

**Contextual behavior:** watch the hangar state machine (`swrObjHang_F0` @ `0x00457620`, current-
screen field) each frame; when it enters the new-profile / name-entry screen, **auto-show** a
focused **Randomizer** window — independent of the global F5 debug toggle (small carve: let this
one window render even when `show_imgui` is false). Layout:

```
Randomizer
[ ] Randomize this profile            <- master toggle, default OFF (unchecked = vanilla profile)
    -----------------------------------  (revealed only when master is checked)
    [x] Pod handling stats
    [x] AI difficulty
    [x] Track order
    [ ] Character <-> pod
    [x] Starting unlocks / money
    Seed:  "Watto"  ->  0x8F2A31C7     <- live from the name being typed
```

- **Live seed preview** — the panel is up while the player types the name, and the text-entry
  widget buffer (page `0x2736`) is readable, so show the derived seed updating keystroke-by-
  keystroke. Makes the name=seed relationship obvious and shareable.
- When a profile with a saved sidecar is *loaded* (not created), the panel shows its locked
  config read-only (grayed out) so the player can see the ruleset + seed for that run.

### The creation snapshot

On the creation seam `swrRace_GenerateDefaultDataSAV` @ `0x0043ea00`, snapshot **the panel's
current config + the final entered name** into the `[<profileName>]` section of
`data/player/randomizer.ini`, then:

1. Apply Class-A randomizations directly into the fresh profile before it is written.
2. Mark the sidecar read-only for this profile.

On profile *load* (`swrRace_CopyProfileFromSave` @ `0x0044e500` / `swrRace_InitGameData` @
`0x00421810`), read the sidecar, rebuild the seed from the name, and arm the Class-B appliers.

---

## 5. Faithfulness + run verification

The randomizer is a `dinput_hook/` delta; the reimplemented sim (`.text`) is untouched, so a
randomized race is still running the original physics. **But a randomized profile is not a
canonical run.** Any profile with the master toggle on (or any category active) must be flagged
**non-canonical** to the run-verification layer (`VERIFICATION_ROADMAP.md`) so it can never
masquerade as a clean speedrun. The sidecar's presence + a config hash is the natural flag; fold
it into whatever descriptor/hash the verification and modes/modifiers layers already define
(`MODES_MODIFIERS_ROADMAP.md` §2 RulesetDescriptor is the obvious home).

---

## 6. Phases

### Phase 1 — MVP: prove the whole pipeline end-to-end (**M**)
Smallest slice that exercises seed + sidecar + one Class-B applier:
1. `hash(profileName)` seed derivation + dedicated PRNG with named sub-streams.
2. Sidecar load/save (`data/player/randomizer.ini`, section per profile); creation snapshot at
   `swrRace_GenerateDefaultDataSAV`; read-only load at profile load.
3. **AI difficulty** category only (lowest-effort, immediately visible).
4. ImGui **Randomizer** panel: master toggle + AI checkbox + live seed preview. (F5-accessible
   first; contextual auto-popup can land in the same phase or Phase 2.)
5. Non-canonical flag wired to the verification layer.

### Phase 2 — contextual UI + more Class-B categories (**M**)
1. Auto-popup on the new-profile screen (hangar state watch + independent render path).
2. Read-only display when loading an existing randomized profile.
3. Add **track order** and **pod handling stats** categories.

### Phase 3 — Class-A + remaining categories (**M-L**)
1. **Starting unlocks / money** (Class A, creation-time write; guard against soft-lock).
2. **Character <-> pod binding**.
3. Per-racer asymmetric AI (stretch on the AI category).

### Future / stretch (not blocking)
- **Native in-game toggle** on the name-entry screen (carve `swrObjHang_UpdateEnterName` /
  inject a widget) — revisit if `UI_ROADMAP.md` matures a clean widget-injection seam.
- **Shop / upgrade price** randomization — blocked on reversing the hangar pricing.
- Seed sharing / import codes; preset "seed packs."

---

## 7. Open questions / risks

- **Soft-lock guard (Class A):** starting-unlock randomization must always leave >=1 drivable pod
  and a reachable first track. Needs an explicit invariant + test.
- **Track-order vs unlock gating:** global track shuffle must not place a locked track first, or
  gate progression on something unreachable. Within-circuit shuffle is the safe default.
- **Hash choice:** pick a stable, well-distributed 32-bit hash (FNV-1a is simplest); freeze it —
  changing the hash function silently changes everyone's seed. Treat it as a versioned constant.
- **Name edge cases:** trailing spaces / case / non-ASCII in `profileName` — normalize before
  hashing, and document the normalization as part of the frozen seed definition.
- **Independent-render carve:** confirm letting one ImGui window draw while `show_imgui` is false
  doesn't fight the existing debug-UI panel registry (`DEBUG_UI_ROADMAP.md`).
