from typing import List
from elf import ELFHelper, NewELF

from pwn import hexdump
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

    def add_back_symbols(self):

        symtab_idx, symtab = self.helper.locate_symtab()
        strtab = symtab.stringtable
        strtab_idx = self.helper.section_to_entry_idx(strtab)
        

        strtab_list = list(set(map(lambda x: x.name, self._symbols)))
        
        symtab_growth, strtab_growth = self.calc_section_growth(symtab, strtab_list)
        
        w = NewELF(self.path, self.new_path, helper=self.helper)
        
        new_symtab_begin = w.file_size()
        
        # copy existing symtab
        w.memcpy(-1, symtab["sh_offset"], symtab["sh_size"])
        
        # append our own
        w.append(self.serialize_symbols(strtab_list, initial_size=strtab['sh_size']))
        
        new_strtab_begin = w.file_size()
        
        w.memcpy(-1, strtab["sh_offset"], strtab["sh_size"])
        
        w.append(b'\x00'.join(strtab_list) + b"\x00")
        
        # change section headers accordingly
        
        symtab_hdr = self.helper.file._get_section_header(symtab_idx)
        strtab_hdr = self.helper.file._get_section_header(strtab_idx)
        
        symtab_hdr['sh_size'] += symtab_growth
        symtab_hdr['sh_offset'] = new_symtab_begin

        strtab_hdr['sh_size'] += strtab_growth
        strtab_hdr['sh_offset'] = new_strtab_begin
        
        w.write_struct_at(self.helper.section_to_entry_addr(symtab), self.helper.file.structs.Elf_Shdr, symtab_hdr) 
        w.write_struct_at(self.helper.section_to_entry_addr(strtab), self.helper.file.structs.Elf_Shdr, strtab_hdr) 
        
        # clear out old ones
        w.memset(b'\x00', symtab['sh_offset'], symtab['sh_size'])
        w.memset(b'\x00', strtab['sh_offset'], strtab['sh_size'])

    def calc_section_growth(self, symtab, strtab_list):
         
        symtab_growth = len(self._symbols) * self.helper.file.structs.Elf_Sym.sizeof()
        
        # Combined size of all strings + 1 char per entry for null termination
        strtab_growth = sum(map(len, strtab_list)) + len(strtab_list)
        
        return symtab_growth, strtab_growth
    
    def serialize_symbols(self, strtab_list, initial_size):
        return b''.join([symbol.serialize(self.helper.file, strtab_list, initial_size) for symbol in self._symbols])

if __name__ == "__main__":
    a = Unstrip("./example_bins/test_unstripped", new_path='./bruh')
    
    symbols = [Symbol(b'aaa', SymbolType.FUNCTION, 0xdeadbeef, 5)] * 18

    a.set_symbols(symbols)

    a.add_back_symbols()
