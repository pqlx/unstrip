from typing import Optional, List, Union

from dataclasses import dataclass
from enum import Enum

from elftools.construct.lib import Container
from elftools.common.utils import struct_parse

class SymbolType(Enum):
    FUNCTION = 'STT_FUNC'
    VARIABLE = 'STT_OBJECT'
    NOTYPE   = 'STT_NOTYPE'

class VisibilityType(Enum):
    DEFAULT = 'STV_DEFAULT'

class BindType(Enum):
    LOCAL = 'STB_LOCAL'
    GLOBAL = 'STB_GLOBAL'

@dataclass
class Symbol:
    name: Optional[bytes]=None
    type_: Optional[SymbolType]=None
    value: Optional[int]=None
    section_idx: Optional[int]=None
    size: int = 0
    visibility: Union[VisibilityType, int] = VisibilityType.DEFAULT
    bind: Union[BindType, int] = BindType.GLOBAL

    def serialize(self, helper, strtab_list, initial_size):

        def enum_union_val(var: Union[Enum, int]):
            if isinstance(var, Enum):
                return var.value
            return var

        c = Container()
        c['st_name'] = self.calculate_strtab_idx(strtab_list, initial_size) if self.name else 0
        c['st_value'] = self.value
        c['st_size'] = self.size
        c['st_info'] = Container()
        c['st_info']['bind'] = enum_union_val(self.bind)
        c['st_info']['type'] = enum_union_val(self.type_)
        c['st_other'] = Container()
        c['st_other']['visibility'] = enum_union_val(self.visibility)
        c['st_shndx'] = helper.va_to_section_idx(self.value) if not self.section_idx else self.section_idx
        
        return helper.file.structs.Elf_Sym.build(c) 

    def calculate_strtab_idx(self, strings: List[str], initial_size: int):

        idx = strings.index(self.name)
         
        return sum(map(len, strings[:idx])) + idx + initial_size
