#!/bin/sh
python ./create_symbols.py $@
gcc dummy.c -o not_stripped.elf
gcc dummy.c -s -o stripped.elf
