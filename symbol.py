from typing import Optional, List

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
    name: Optional[bytes]
    type_: SymbolType
    value: int
    section_idx: Optional[int]=None
    size: int = 0
    visibility: VisibilityType = VisibilityType.DEFAULT
    bind: BindType = BindType.GLOBAL

    def serialize(self, helper, strtab_list, initial_size):
        c = Container()
        c['st_name'] = self.calculate_strtab_idx(strtab_list, initial_size) if self.name else 0
        c['st_value'] = self.value
        c['st_size'] = self.size
        c['st_info'] = Container()
        c['st_info']['bind'] = self.bind.value
        c['st_info']['type'] = self.type_.value
        c['st_other'] = Container()
        c['st_other']['visibility'] = self.visibility.value
        c['st_shndx'] = helper.va_to_section_idx(self.value) if not self.section_idx else self.section_idx
        
        return helper.file.structs.Elf_Sym.build(c) 

    def calculate_strtab_idx(self, strings: List[str], initial_size: int):

        idx = strings.index(self.name)
         
        return sum(map(len, strings[:idx])) + idx + initial_size
