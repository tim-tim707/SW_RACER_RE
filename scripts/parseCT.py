# This script is used to parse Cheat Engine CT tables to gather global variables
import sys
import xml.etree.ElementTree as ET

def main():
    # if (len(sys.argv) < 2):
    #     print("Missing Cheat Engine table to parse as first argument")
    #     sys.exit(1)
    # filepath = sys.argv[1]
    filepath = ".\modules\swe1r-decomp\SWEP1RCR.CT"
    tree = ET.parse(filepath)
    root = tree.getroot()
    print(root.tag)
    print(root.attrib)
    for child in root.iter('CheatEntry'):
        description = None
        address = None
        for c in child.iter():
            if (c.tag == 'Description' and c.text is not None):
                description = c.text
            if (c.tag == 'Address' and c.text is not None):
                address = c.text
        if (address is not None and description is not None):
            print(address + ": " + description)

if __name__ == "__main__":
    main()
