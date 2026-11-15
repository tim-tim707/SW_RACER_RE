#pragma once

#include "ui_transform.h"

#include <cstdint>

// UI clusters: groups of directly drawn sprites + text (the in-race HUD, and front-end panels such as
// the pod stat table) that move together as one unit, each with its own screen anchor and group
// transform. A HUD element's cluster is resolved from the EXE call site that
// placed it (swrSprite_SetPos / SetDim / swrText_CreateTextEntry1), not from its sprite id or design x:
// the game reuses those across screens, while each call site is a fixed, unique identity.
enum HudCluster {
    HUD_CLUSTER_NONE = 0,     // not an in-race HUD element; takes the plain UI centering
    HUD_CLUSTER_CENTER,       // centered HUD elements (banners, messages, timer columns in 2P)
    HUD_CLUSTER_LAP,          // header lap holder, its connector, "#/#" + LAP (top-left)
    HUD_CLUSTER_TIME,         // header time holder, its connector, lap/total time (top-center)
    HUD_CLUSTER_POSITION,     // header position holder, "#/#" + POS (top-right)
    HUD_CLUSTER_HEADER_RULE,  // header top rule + blue gradient, spanning the full window width
    HUD_CLUSTER_RING_LEFT,    // progress-ring HUD mode: left rail and the top/bottom rails
    HUD_CLUSTER_RING_RIGHT,   // progress-ring HUD mode: right rail
    HUD_CLUSTER_METER,        // right-side meter bars beside the radar
    HUD_CLUSTER_RADAR,        // minimap gradient backing (the dots ride swrObjJdge_minimapAnchorX)
    HUD_CLUSTER_SPEEDOMETER,  // speed dial, readout frame, speed + BOOST text (bottom-right)
    HUD_CLUSTER_ENGINE,       // engine damage readout + warnings (bottom-left)
    HUD_CLUSTER_STAT_TABLE,   // pod stat table: vehicle select, Watto's shop, junkyard (bottom)
    HUD_CLUSTER_SCREEN_HEADER, // front-end screen title + left/right carousel arrows (top)
    HUD_CLUSTER_COUNT
};

// How a HUD element's width follows its cluster when the screen is wider than 4:3.
enum HudSpan {
    HUD_SPAN_NONE = 0,     // authored width
    HUD_SPAN_WINDOW,       // the full window width (header backing)
    HUD_SPAN_CONNECTOR,    // lengthened to bridge the widened gap between header holders
    HUD_SPAN_EDGE_TO_EDGE, // left-anchored, lengthened to reach the right-anchored edge
};

struct HudElement {
    HudCluster cluster;
    HudSpan span;
};

// Cluster + span for the element placed from this EXE call site (a return address). {NONE, NONE} for
// an element in no cluster.
HudElement ui_hud_element_at(uintptr_t call_site);

// The cluster's group transform in framebuffer px (its anchor shift composed with the active layer).
// Identity when res-independence is off.
UiXform ui_hud_cluster_xform(HudCluster cluster);

// Width delta (design units at scale s) for a span, or the absolute width for HUD_SPAN_WINDOW.
float ui_hud_span_width(HudSpan span, float authored_width, float s);

// Text wrappers that re-emit through swrText_CreateTextEntry1 (swrText_CreateTimeEntry's delta) hide
// the game's call site behind their own; they publish the outer site for the duration of the call so
// the text sink resolves the right element.
struct UiHudForwardedSite {
    explicit UiHudForwardedSite(uintptr_t site);
    ~UiHudForwardedSite();
    uintptr_t previous;
};

// The call site the text sink should resolve: the forwarded outer site if one is active, else ret.
uintptr_t ui_hud_text_site(uintptr_t ret);
