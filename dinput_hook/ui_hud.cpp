#include "ui_hud.h"

#include <Swr/swrObj.h>
#include <Swr/swrRace.h>
#include <Swr/swrUI.h>
#include <globals.h>

namespace {

struct HudClusterDef {
    UiAnchorH h;
    UiAnchorV v;
};

// Vertical anchors only move anything when the 2D box is shorter than the window (UI scale < 1, or a
// screen taller than 4:3).
constexpr HudClusterDef kClusters[HUD_CLUSTER_COUNT] = {
    /* NONE        */ {UI_H_CENTER, UI_V_MIDDLE},
    /* CENTER      */ {UI_H_CENTER, UI_V_MIDDLE},
    /* LAP         */ {UI_H_LEFT, UI_V_TOP},
    /* TIME        */ {UI_H_CENTER, UI_V_TOP},
    /* POSITION    */ {UI_H_RIGHT, UI_V_TOP},
    /* HEADER_RULE */ {UI_H_LEFT, UI_V_TOP},
    /* RING_LEFT   */ {UI_H_LEFT, UI_V_MIDDLE},
    /* RING_RIGHT  */ {UI_H_RIGHT, UI_V_MIDDLE},
    /* METER       */ {UI_H_RIGHT, UI_V_MIDDLE},
    /* RADAR       */ {UI_H_RIGHT, UI_V_TOP},
    /* SPEEDOMETER */ {UI_H_RIGHT, UI_V_BOTTOM},
    /* ENGINE      */ {UI_H_LEFT, UI_V_BOTTOM},
    /* STAT_TABLE  */ {UI_H_CENTER, UI_V_BOTTOM},
    /* SCREEN_HEADER */ {UI_H_CENTER, UI_V_TOP},
};

// HUD functions whose every element belongs to one cluster unless a call site below says otherwise.
// Each range runs to the start of the next function in the EXE.
struct HudFunctionRange {
    uintptr_t start;
    uintptr_t end;
    HudCluster cluster;
};

constexpr HudFunctionRange kFunctions[] = {
    {swrObjJdge_DrawSpeedDialHud_Maybe_ADDR, swrObjJdge_DrawHudBar_ADDR, HUD_CLUSTER_SPEEDOMETER},
    {swrObjJdge_LayoutHudFrameSprites_Maybe_ADDR, swrRace_InRaceTimer_ADDR, HUD_CLUSTER_CENTER},
    {swrRace_InRaceTimer_ADDR, swrObjJdge_DrawSplitDivider_ADDR, HUD_CLUSTER_CENTER},
    {swrRace_InRaceEngineUI_ADDR, swrRace_InRaceEndStatistics_ADDR, HUD_CLUSTER_ENGINE},
    {swrRace_VehicleStatisticsSubMenu_ADDR, swrRace_SetupStatsMenuLighting_ADDR,
     HUD_CLUSTER_STAT_TABLE},
    // Carousel arrows + frame: vehicle select, Watto's shop, junkyard, course select, course info.
    {swrUI_Front_MenuAxisHorizontal_ADDR, 0x004403d6, HUD_CLUSTER_SCREEN_HEADER},
};

// Return address of each call that places an element of a mixed-cluster HUD function.
struct HudSite {
    uintptr_t site;
    HudCluster cluster;
    HudSpan span;
};

constexpr HudSite kSites[] = {
    // swrRace_SelectVehicle: screen title + pilot name under it.
    {0x00435968, HUD_CLUSTER_SCREEN_HEADER, HUD_SPAN_NONE},
    {0x004359d5, HUD_CLUSTER_SCREEN_HEADER, HUD_SPAN_NONE},

    // swrObjJdge_DrawSpeedDialHud_Maybe: the centered text under the dial (x 0xa0).
    {0x00460107, HUD_CLUSTER_CENTER, HUD_SPAN_NONE},

    // swrObjJdge_LayoutHudFrameSprites_Maybe, header (lap / time / position holders + backing).
    {0x00460424, HUD_CLUSTER_HEADER_RULE, HUD_SPAN_NONE},    // SetPos dial_time_wire_rgb_1 (rule)
    {0x00460438, HUD_CLUSTER_HEADER_RULE, HUD_SPAN_WINDOW},  // SetDim rule
    {0x00460470, HUD_CLUSTER_HEADER_RULE, HUD_SPAN_NONE},    // SetPos ej_fadel_rgb_0 (gradient)
    {0x00460484, HUD_CLUSTER_HEADER_RULE, HUD_SPAN_WINDOW},  // SetDim gradient
    {0x004604b0, HUD_CLUSTER_LAP, HUD_SPAN_NONE},            // SetPos dial_lap_pos_rgb_0
    {0x004604dc, HUD_CLUSTER_LAP, HUD_SPAN_NONE},            // SetPos dial_top_h_wire_rgb_0
    {0x004604f0, HUD_CLUSTER_LAP, HUD_SPAN_CONNECTOR},       // SetDim lap->time connector
    {0x0046051c, HUD_CLUSTER_TIME, HUD_SPAN_NONE},           // SetPos dial_time_wire_rgb_0
    {0x0046054b, HUD_CLUSTER_TIME, HUD_SPAN_NONE},           // SetPos dial_top_h_wire_rgb_1
    {0x0046055f, HUD_CLUSTER_TIME, HUD_SPAN_CONNECTOR},      // SetDim time->pos connector
    {0x0046058e, HUD_CLUSTER_POSITION, HUD_SPAN_NONE},       // SetPos dial_lap_pos_rgb_1
    // Same function, progress-ring HUD mode: top/bottom rails run between the side rails.
    {0x004605c0, HUD_CLUSTER_RING_LEFT, HUD_SPAN_NONE},      // SetPos dial_time_wire_rgb_2
    {0x004605d4, HUD_CLUSTER_RING_LEFT, HUD_SPAN_EDGE_TO_EDGE},
    {0x00460600, HUD_CLUSTER_RING_LEFT, HUD_SPAN_NONE},      // SetPos dial_time_wire_rgb_1
    {0x00460614, HUD_CLUSTER_RING_LEFT, HUD_SPAN_EDGE_TO_EDGE},
    {0x0046073b, HUD_CLUSTER_RING_LEFT, HUD_SPAN_NONE},      // SetPos dial_trakmid_wire_rgb_0
    {0x0046077e, HUD_CLUSTER_RING_RIGHT, HUD_SPAN_NONE},     // SetPos dial_trakmid_wire_rgb_1
    {0x004607c4, HUD_CLUSTER_METER, HUD_SPAN_NONE},          // SetPos dial_traktop_wire_rgb_0
    // Same function, speedometer readout frame, meter bars, radar backing.
    {0x0046068e, HUD_CLUSTER_SPEEDOMETER, HUD_SPAN_NONE},    // SetPos dial_speed_edge_blue_rgb_0
    {0x004606c0, HUD_CLUSTER_SPEEDOMETER, HUD_SPAN_NONE},    // SetPos dial_speed_mid_blue
    {0x00460706, HUD_CLUSTER_SPEEDOMETER, HUD_SPAN_NONE},    // SetPos dial_speed_edge_blue_rgb_1
    {0x00460855, HUD_CLUSTER_METER, HUD_SPAN_NONE},          // SetPos dial_trakmid_wire_rgb_0
    {0x004608af, HUD_CLUSTER_METER, HUD_SPAN_NONE},          // SetPos dial_traktop_wire_rgb_0
    {0x00460908, HUD_CLUSTER_RADAR, HUD_SPAN_NONE},          // SetPos ej_fadel_rgb_1

    // swrRace_InRaceTimer text.
    {0x00460a89, HUD_CLUSTER_SPEEDOMETER, HUD_SPAN_NONE},    // digital speed readout
    {0x00460bd8, HUD_CLUSTER_TIME, HUD_SPAN_NONE},           // last lap time
    {0x00460c04, HUD_CLUSTER_TIME, HUD_SPAN_NONE},           // "LAP TIME"
    {0x00460c5d, HUD_CLUSTER_TIME, HUD_SPAN_NONE},           // "New Record"
    {0x00460e70, HUD_CLUSTER_TIME, HUD_SPAN_NONE},           // total time
    {0x00460e9f, HUD_CLUSTER_TIME, HUD_SPAN_NONE},           // "TIME"
    {0x00460f67, HUD_CLUSTER_LAP, HUD_SPAN_NONE},            // lap "#/#" (final-lap flash)
    {0x00460fbe, HUD_CLUSTER_LAP, HUD_SPAN_NONE},            // lap "#/#"
    {0x00460ff0, HUD_CLUSTER_LAP, HUD_SPAN_NONE},            // "LAP"
    {0x00461056, HUD_CLUSTER_POSITION, HUD_SPAN_NONE},       // position "#/#"
    {0x0046107a, HUD_CLUSTER_POSITION, HUD_SPAN_NONE},       // "POS"
};

uintptr_t g_forwarded_site = 0;

} // namespace

HudElement ui_hud_element_at(uintptr_t call_site) {
    for (const HudSite &s : kSites) {
        if (s.site == call_site)
            return {s.cluster, s.span};
    }
    for (const HudFunctionRange &f : kFunctions) {
        if (call_site >= f.start && call_site < f.end)
            return {f.cluster, HUD_SPAN_NONE};
    }
    return {HUD_CLUSTER_NONE, HUD_SPAN_NONE};
}

UiXform ui_hud_cluster_xform(HudCluster cluster) {
    UiXform x = ui_xform_identity();
    // The 2D UI box is centered by one centering offset per axis; a left/top anchor undoes it, a
    // right/bottom anchor doubles it to reach the real far edge.
    const float off = ui_center_offset_px();
    switch (kClusters[cluster].h) {
    case UI_H_LEFT:
        x.tx = 0.0f;
        break;
    case UI_H_RIGHT:
        x.tx = 2.0f * off;
        break;
    default:
        x.tx = off;
        break;
    }
    const float off_y = ui_center_offset_y_px();
    switch (kClusters[cluster].v) {
    case UI_V_TOP:
        x.ty = 0.0f;
        break;
    case UI_V_BOTTOM:
        x.ty = 2.0f * off_y;
        break;
    default:
        x.ty = off_y;
        break;
    }
    return ui_xform_compose(ui_layer_current(), x);
}

float ui_hud_span_width(HudSpan span, float authored_width, float s) {
    if (s <= 0.0f)
        return authored_width;
    const float off = ui_center_offset_px();
    switch (span) {
    case HUD_SPAN_WINDOW:
        return (swrDisplay_screenWidth > 0) ? (float) swrDisplay_screenWidth / s : authored_width;
    case HUD_SPAN_CONNECTOR:
        // Bridging the full holder motion overshoots the holder art; half of it was tuned by eye.
        return authored_width + 0.5f * off / s;
    case HUD_SPAN_EDGE_TO_EDGE:
        return authored_width + 2.0f * off / s;
    default:
        return authored_width;
    }
}

UiHudForwardedSite::UiHudForwardedSite(uintptr_t site) : previous(g_forwarded_site) {
    g_forwarded_site = site;
}

UiHudForwardedSite::~UiHudForwardedSite() {
    g_forwarded_site = previous;
}

uintptr_t ui_hud_text_site(uintptr_t ret) {
    return g_forwarded_site ? g_forwarded_site : ret;
}
