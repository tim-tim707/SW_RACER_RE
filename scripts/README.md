# Documentation
## Project

`python GenerateGlobalHeaderFromSymbols.py`
Read `data_symbols.syms` to generate a C header containing globals variables with optional default values.
The global header are generated from the templates in `src/templates/` and saved in `src/generated`.
This should be done automatically by the build system.

`python GenerateHooks.py`
Also used by the build system and a template in `src/templates` in order to generate a C file
that will hook every function annotated with HOOK so that it uses our re-implementation instead of the
original game function.

`python parseCT.py`
Parses CheatEngine table to output addresses and names in plain text.

## Ghidra

Inside Ghidra `ImportDataSymbols.py`
Import `data_symbols.syms` into Ghidra to add global variable names and references.

Symmetrically, inside Ghidra `ExportGlobalVariables.py` is used to output every global variable known to Ghidra

`python scripts\Ghidra\CheckHeaderDuplicates.py`
Checks for function definition duplicates in order to clean them up when interfacing with Ghidra

`python scripts/Ghidra/check_data_symbols_dups.py`
Check for duplicates in addresses in the symbols and globals definitions

`python scripts\Ghidra\GenerateMasterHeader.py`
Concatenate all headers in src/ for use in Ghidra.
This is a convenience in order not to include headers one by one in Ghidra.

Inside Ghidra `ImportHeaderInfos.py`
Read a header file (can be the header generated above) and import the functions at correct addresses
into Ghidra.

Inside Ghidra `ExportFunctionList.py` will export all the functions known by Ghidra

`python scripts\Ghidra\CalculateProgress.py`
Compute how many functions have associated identified function names.
This is done through a three step process
1) Run `GenerateMasterHeader.py` to create master_header.h with all identified files
2) Run `ExportFunctionList.py` within Ghidra to extract all function names
3) Run `CalculateProgress.py` script to calculate progress

## Ida
TODO
