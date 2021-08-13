from typing import List
import functools

from elf import ELFHelper, NewELF
from idasymbols import get_ida_symbols
from symbol import Symbol, SymbolType


class Unstrip:

    path: str
    new_path: str
    _symbols: List[Symbol]

    
    def __init__(self, path: str, symbols: List[Symbol]=None, new_path=None):
        self.path = path
        self.new_path = new_path or path + '_unstrip'
        self.helper = ELFHelper(path)
        
        if symbols:
            self.set_symbols(symbols) 
    
    def set_symbols(self, symbols):
        self._symbols = symbols
        
        if 'new_symbols_strtab' in self.__dict__:
            del self.__dict__['new_symbols_strtab']

    def create_elf_append(self, symtab=None, strtab=None):

        elf = NewELF(self.path, self.new_path, helper=self.helper)
        
        new_symtab_begin = elf.file_size()

        if symtab:
            elf.memcpy(-1, symtab["sh_offset"], symtab["sh_size"])
        
        initial_strtab_size = strtab["sh_size"] if strtab else 0
        
        serialized_symbols = self.serialize_symbols(self.new_symbols_strtab, initial_size=initial_strtab_size)

        elf.append(serialized_symbols)

        new_strtab_begin = elf.file_size()

        if symtab:
            elf.memcpy(-1, strtab["sh_offset"], strtab["sh_size"])
        
        elf.append(b'\x00'.join(self.new_symbols_strtab) + b"\x00")
        
        return (elf, new_symtab_begin, new_strtab_begin)

    def add_syms_to_existing(self, symtab):

        strtab = symtab.stringtable
        
        symtab_growth = len(self._symbols) * self.helper.file.structs.Elf_Sym.sizeof()
         
        # Combined size of all strings + 1 char per entry for null termination
        strtab_growth = sum(map(len, self.new_symbols_strtab)) + len(self.new_symbols_strtab)
        
        elf, new_symtab_begin, new_strtab_begin = self.create_elf_append(symtab=symtab, strtab=strtab)
        
        symtab_hdr = symtab.header.copy()
        strtab_hdr = strtab.header.copy()
        
        symtab_hdr['sh_size'] += symtab_growth
        symtab_hdr['sh_offset'] = new_symtab_begin

        strtab_hdr['sh_size'] += strtab_growth
        strtab_hdr['sh_offset'] = new_strtab_begin
        
        shdr = self.helper.file.structs.Elf_Shdr

        elf.write_struct_at(self.helper.section_to_entry_addr(symtab), shdr, symtab_hdr) 
        elf.write_struct_at(self.helper.section_to_entry_addr(strtab), shdr, strtab_hdr) 
        
        # clear out old ones
        elf.memset(b'\x00', symtab['sh_offset'], symtab['sh_size'])
        elf.memset(b'\x00', strtab['sh_offset'], strtab['sh_size'])



    def add_back_symbols(self):
         
        symtab_idx, symtab = self.helper.locate_symtab()
        
        if symtab:
            self.add_syms_to_existing(symtab)
        else:
            self.add_new_symtab(strtab_list)

    def calc_section_growth(self):
         
        symtab_growth = len(self._symbols) * self.helper.file.structs.Elf_Sym.sizeof()
        
        # Combined size of all strings + 1 char per entry for null termination
        strtab_growth = sum(map(len, self.new_symbols_strtab)) + len(self.new_symbols_strtab)
        
        return symtab_growth, strtab_growth
    
    def serialize_symbols(self, strtab_list, initial_size):
        return b''.join([symbol.serialize(self.helper.file, strtab_list, initial_size) for symbol in self._symbols])
    
    @property
    @functools.cache
    def new_symbols_strtab(self):
        return list(set(map(lambda x: x.name, self._symbols)))
 
if __name__ == "__main__":
    a = Unstrip("./example_bins/test_unstripped", new_path='./bruh')
    
    symbols = get_ida_symbols('./example_bins/test_stripped_ida.i64')

    a.set_symbols(symbols)

    a.add_back_symbols()
