# Export all global variables known to Ghidra

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import TaskMonitor

SWR_DATA_ADDR_ = 0x004AC000
SWR_INTERESTING_DATA_END = 0x00ecd618

symbol_table = currentProgram.getSymbolTable()
global_namespace = currentProgram.getGlobalNamespace()
symbols = symbol_table.getSymbols(global_namespace)

lines = []
for symbol in symbols:
    if symbol.getSymbolType() == SymbolType.LABEL:
        name = symbol.getName()
        address = symbol.getAddress()
        int_address = int(str(address), 16)

        data = getDataAt(address)
        if data:
            data_type = data.getDataType()
            if int_address >= SWR_DATA_ADDR_ and int_address <= SWR_INTERESTING_DATA_END:
                # print("{} 0x{} {}".format(name, address, data_type.getName()))
                lines.append((int_address, "{} 0x{} {}".format(name, address, data_type.getName())))
        else:
            if int_address >= SWR_DATA_ADDR_ and int_address <= SWR_INTERESTING_DATA_END:
                # print("{} 0x{} UNKNOWN_DATA_TYPE".format(name, address))
                lines.append((int_address, "{} 0x{} UNKNOWN_DATA_TYPE".format(name, address)))

lines = sorted(lines, key=lambda tup: tup[0])

for _, line in lines:
    print(line)
