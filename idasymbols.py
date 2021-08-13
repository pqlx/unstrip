from typing import List
import idb
from idb.idapython import FLAGS

from symbol import Symbol, SymbolType

def get_ida_symbols(path) -> List[Symbol]:
    
    idasymbols = []
    with idb.from_file(path) as db:
        api = idb.IDAPython(db)
        for ea in api.idautils.Functions():
        
            flags = api.idc.GetFlags(ea)
            if (flags >> 14) & 1 and flags & 0xf0 != 0xf0:
                idasymbols.append((ea, api.idc.GetFunctionName(ea)))
    
    symbols = []

    for idasymbol in idasymbols:

        sym = Symbol(name=idasymbol[1].encode(), type_=SymbolType.FUNCTION, value=idasymbol[0], section_idx=4)
        symbols.append(sym)

    return symbols

if __name__ == "__main__":
    import sys
    get_ida_symbols(sys.argv[1])
