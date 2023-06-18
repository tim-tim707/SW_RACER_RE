OFFSET = "09C140" # swr main file offset
# OFFSET = "000B26" window main file offset

CODE = None

with open("dump.txt", "r", encoding='ascii') as file:
    CODE = file.read()

cleaned = CODE.replace('\n', '')
cleaned = cleaned.replace(' ', '')
cleaned = cleaned.replace('\r', '')
cleaned = cleaned.replace('\t', '')

size = '{:04X}'.format(int(len(cleaned) / 2))

with open("../swr_patch.ips", "wb") as file:
    patch = "5041544348" + OFFSET + size + cleaned + "454F46"

    file.write(bytes.fromhex(patch))

print("swr_patch.ips generated. Apply it to the SWEP1RCR.exe copy you want to mod")
