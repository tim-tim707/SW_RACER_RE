# From Ghidra: Window -> Script Manager -> Create New Script (Python) -> paste this -> Run
#
# Creates function objects at addresses where Ghidra disassembled the bytes as
# code but never promoted them to a function. The decompiler shows such call
# targets as "func_0x........", and they cannot be renamed or given a prototype
# (e.g. via the GhidraMCP bridge) until a function exists at the entry point.
#
# This is the create-only counterpart to ImportHeaderInfos.py: it leaves each
# new function with Ghidra's default FUN_<addr> name so the name can be chosen
# and applied separately. Edit ADDRESSES below to add more. Re-running is safe;
# addresses already inside a function are skipped.

from ghidra.app.cmd.disassemble import DisassembleCommand

# Hex address strings that need a function created.
# Seeded with the camera-man (swrObjcMan) dispatch cluster.
ADDRESSES = [
    "0x00453e00",  # camera-mode dispatch (calls the chase / death camera handlers)
    "0x00454060",  # called by swrObjcMan_F3
    "0x00451020",  # called by swrObjcMan_F0
    "0x00451a80",  # called by swrObjcMan_F2
    "0x004525d0",  # DoPreRaceSweepEnd (per annodue)
]

fm = currentProgram.getFunctionManager()
created = 0
skipped = 0
failed = 0

for hexaddr in ADDRESSES:
    addr = toAddr(hexaddr)
    if addr is None:
        print("Bad address: {}".format(hexaddr))
        failed += 1
        continue

    existing = fm.getFunctionContaining(addr)
    if existing is not None:
        print("Skip {}: already inside {} @ {}".format(
            hexaddr, existing.getName(), existing.getEntryPoint()))
        skipped += 1
        continue

    # Ensure the bytes are disassembled as code before creating the function.
    if getInstructionAt(addr) is None:
        DisassembleCommand(addr, None, True).applyTo(currentProgram, monitor)

    func = createFunction(addr, None)  # None -> default FUN_<addr> name
    if func is not None:
        print("Created {} @ {}".format(func.getName(), func.getEntryPoint()))
        created += 1
    else:
        print("FAILED at {} (not code, or not a valid function entry?)".format(hexaddr))
        failed += 1

print("\nDone. created={} skipped={} failed={}".format(created, skipped, failed))
