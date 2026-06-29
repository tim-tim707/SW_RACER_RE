#ifndef SWR_MAIN_H
#define SWR_MAIN_H

#define Main_Startup_ADDR (0x00423cc0)
#define Main_Shutdown_ADDR (0x004240d0)

#define Main_ShutdownError_ADDR (0x00424150)

#define Main_ParseCmdLine_ADDR (0x00424430)

// Boot init tail (called from Main_Startup).
#define Main_StartupSoundAndControl_ADDR (0x00411361)
#define Main_InitAudioInput_ADDR (0x004112e1)

// Per-frame loop helpers (driven by swrMain2_GuiAdvance).
#define swrMain_ProcessDebugKeys_ADDR (0x004104f0)
#define swrMain_UpdateNetworkTick_ADDR (0x0041c1d0)
#define swrMain_GuiAdvance_ADDR (0x00424140)
#define swrMain_UpdateInRaceLoopSfx_ADDR (0x00426920)
#define swrMain_RunFrame_ADDR (0x00445980)

int Main_Startup(char* cmdline);
void Main_Shutdown(void);

// Dispatches the per-frame GUI advance through the function pointer.
void swrMain_GuiAdvance(void);

void Main_ShutdownError(void);
int Main_ParseCmdLine(char* cmdline);

// Start the audio and input services: swrSound_Startup + swrControl_Startup.
void Main_StartupSoundAndControl(void);
// Init the sound critical section, then start the audio/input services. Tail of Main_Startup.
int Main_InitAudioInput(void);

// Per-frame core tick: phase 1 (== 1 or 0) updates the world (swrModel_UpdateAnimations,
// swrEvent_CallAllF0..F3, swrViewport_UpdateCameras, gated by the pause state); phase 2
// (== 2 or 0) renders (HUD occlusion sample + swrPlayerHUD_RenderAllViewports). flags == 0
// in the render phase also draws the extra full-screen pass.
void swrMain_RunFrame(short flags, short phase);
// Per-frame debug/cheat hotkey handler (FPS toggle, unlock-all, force-feedback/mouse/joystick
// toggles, the Mars Guo / Bullseye racer swaps).
void swrMain_ProcessDebugKeys(void);
// Per-frame network update pacer (gated by Main_nut_delay_ms; drives swrMultiplayer_InRace).
void swrMain_UpdateNetworkTick(void);


// Keeps the in-race looping sound effects alive each tick.
void swrMain_UpdateInRaceLoopSfx(void);
#endif // SWR_MAIN_H
