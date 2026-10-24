#pragma once

// Rumble for DualShock 4 / DualSense pads over USB. Windows' stock HID driver gives these pads no
// DirectInput force feedback and they are not XInput devices, so the XInput rumble bridge never
// reaches them; this writes the motor levels straight into the pad's HID output report.
// Bluetooth is not driven: its output report flips the pad into its extended report mode, which
// the stock driver (and so DirectInput input) can't read.

#if ENABLE_XINPUT_RUMBLE

// left = low-frequency (heavy) motor, right = high-frequency motor, both 0..1 -- the XInput
// convention. Call every frame; writes only when the levels change, never blocks.
void sony_pad_rumble_set(float left, float right);

#endif
