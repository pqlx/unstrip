from typing import Union, List
import idb
from idb.idapython import FLAGS

from unstrip.symbols import Symbol, SymbolType, BindType
from unstrip.symbols.symbolsource import SymbolSource

class IDASymbolSource(SymbolSource):
    
    idb_path: str

    def __init__(self, idb_path: Union[str, 'pathlib.Path']):
        
        super().__init__()

        self.idb_path = str(idb_path)
    
    @staticmethod
    def _func_get_size(idc, ea: int):
        return idc.GetFunctionAttr(ea, idc.FUNCATTR_END) - idc.GetFunctionAttr(ea, idc.FUNCATTR_START)
    
    @staticmethod
    def _flags_is_user_name(flags: int):
        """Returns whether the flags denote an user-defined function symbol"""
    
        # I found this by trial and error. it seems to work, at least on 7.5
        return ((flags >> 14) & 1) and (flags & 0xf0 != 0xf0)


    def get_function_symbols(self) -> List[Symbol]:
    
        symbols = []
        with idb.from_file(self.idb_path) as db:
            api = idb.IDAPython(db)
            for ea in api.idautils.Functions():
                
                flags = api.idc.GetFlags(ea)
                
                if not self._flags_is_user_name(flags):
                    continue
                
                func_name = api.idc.GetFunctionName(ea).encode()
                func_size = self._func_get_size(api.idc, ea)            
                
                sym = Symbol(
                        name=func_name,
                        size=func_size,
                        bind=BindType.GLOBAL, # All the symbol we're gonna find here are global
                        type_=SymbolType.FUNCTION,
                        value=ea,
                        section_idx=14)

                symbols.append(sym)
        
        return symbols
