# Process the functions CSV output by Ghidra to create some progress statistics

# Usage: python scripts\ParseFunctionsCSV.py functions.csv

import os
import sys
import csv

def main(args):
    if len(args) != 2:
        print("Expected one argument as the csv file to parse.")
        print("Usage: python scripts\ParseFunctionsCSV.py functions.csv")
        exit(1)
    nb_functions = 0
    nb_annotated = 0
    with open(args[1]) as file:
        for row in csv.reader(file, delimiter=","):
            nb_functions += 1
            if (not str.startswith(row[0], "FUN_")):
                nb_annotated += 1
    print(f"Annotated functions {nb_annotated} out of {nb_functions}: {nb_annotated / nb_functions * 100:.2f}%")

if __name__ == "__main__":
    main(sys.argv)
