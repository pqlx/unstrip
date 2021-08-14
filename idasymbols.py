from typing import List
import idb
from idb.idapython import FLAGS

from symbol import Symbol, SymbolType, BindType


def ida_flags_is_user_name(flags):
    """Returns whether the flags denote an user-defined function symbol"""
    
    # I found this by trial and error, it seems to work, at least on 7.5
    return ((flags >> 14) & 1) and (flags & 0xf0 != 0xf0)

def ida_func_get_size(idc, ea):
    return idc.GetFunctionAttr(ea, idc.FUNCATTR_END) - idc.GetFunctionAttr(ea, idc.FUNCATTR_START)

def get_ida_symbols(path) -> List[Symbol]:
    
    symbols = []
    with idb.from_file(path) as db:
        api = idb.IDAPython(db)
        for ea in api.idautils.Functions():
            
            flags = api.idc.GetFlags(ea)
            
            if not ida_flags_is_user_name(flags):
                continue
            
            func_name = api.idc.GetFunctionName(ea).encode()
            func_size = ida_func_get_size(api.idc, ea)            
            
            sym = Symbol(
                    name=func_name,
                    size=func_size,
                    bind=BindType.GLOBAL, # All the symbol we're gonna find here are global
                    type_=SymbolType.FUNCTION,
                    value=ea,
                    section_idx=14)

            symbols.append(sym)
    
    return symbols

if __name__ == "__main__":
    import sys
    get_ida_symbols(sys.argv[1])
