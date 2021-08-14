from typing import List
import sys
import argparse


from unstrip import Unstrip
from unstrip.symbols import IDASymbolSource

def process_args(args):
    parser = argparse.ArgumentParser()

    parser.add_argument('--idb', help="Path to IDB (IDA database) to fetch symbols from.")
    parser.add_argument('--outfile', '-o', help="Path to write resulting executable to (defaults to '_unstripped' suffix).") 
    parser.add_argument('infile', help="Path to excutable that needs to be unstripped.")
    return parser, parser.parse_args(args)

def start_cli(args_: List[str]):
    
    parser, args = process_args(args_)

    if args.idb:
        s = IDASymbolSource(args.idb)
    else:
        parser.print_help(sys.stderr)
        exit(-1)
    
    symbols = s.get_function_symbols()
    
    old_path = args.infile
    new_path = args.outfile or old_path + '_unstripped'

    u = Unstrip(old_path, symbols=symbols)

    u.add_back_symbols(new_path)
