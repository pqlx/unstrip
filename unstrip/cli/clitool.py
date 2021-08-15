from typing import List
import sys
import argparse


from unstrip import Unstrip
from unstrip.symbols import IDASymbolSource, TextSymbolSource

def process_args(args):
    parser = argparse.ArgumentParser()

    parser.add_argument('--symidb', help="Path to IDB (IDA database) to fetch symbols from.")
    parser.add_argument('--symtxt', help="Path to text file describing symbols")
    parser.add_argument('--outfile', '-o', help="Path to write resulting executable to (defaults to '_unstripped' suffix).") 
    parser.add_argument('infile', help="Path to excutable that needs to be unstripped.")
    return parser, parser.parse_args(args)

def start_cli(args_: List[str]):
    
    parser, args = process_args(args_)

    if args.symidb:
        s = IDASymbolSource(args.symidb)
    elif args.symtxt:
        s = TextSymbolSource(text_path=args.symtxt)
    else:
        parser.print_help(sys.stderr)
        exit(-1)
    
    symbols = s.get_function_symbols()
    if len(symbols) == 0:
        sys.stderr.write("No symbols found..\n")
        exit(-1)

    old_path = args.infile
    new_path = args.outfile or old_path + '_unstripped'

    u = Unstrip(old_path, symbols=symbols)

    u.add_back_symbols(new_path)
