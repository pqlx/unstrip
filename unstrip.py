from typing import List
import functools

from elftools.construct.lib import Container

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

    def new_elf_append_syms(self, new_elf, old_symtab=None, old_strtab=None):

        has_old = bool(old_symtab and old_strtab) 

        new_symtab_begin = new_elf.file_size()

        if has_old:
            new_elf.memcpy(-1, old_symtab["sh_offset"], old_symtab["sh_size"])
        
        initial_strtab_size = old_strtab["sh_size"] if old_strtab else 1 # one after mandatory first null byte
        
        serialized_symbols = self.serialize_symbols(initial_size=initial_strtab_size)
        
        if not has_old:
            # add a null symbol (required)
            serialized_symbols = (b"\x00" * self.helper.file.structs.Elf_Sym.sizeof()) + serialized_symbols 

        new_elf.append(serialized_symbols)

        new_strtab_begin = self.new_elf_append_string_table(new_elf, self.new_symbols_strtab, old_strtab)

        return (new_symtab_begin, new_strtab_begin)
    
    
    def new_elf_append_string_table(self, new_elf, strings: List[str], old_strtab=None):
        
        new_strtab_begin = new_elf.file_size()
        
        
        symtab_raw = b"\x00".join(strings) + b"\x00"

        if old_strtab:
            new_elf.memcpy(-1, old_strtab['sh_offset'], old_strtab['sh_size'])
        
        else:
            symtab_raw = b"\x00" + symtab_raw

        new_elf.append(symtab_raw)
        
        return new_strtab_begin

    def new_elf_append_section_table(self, new_elf):
        
        has_section_table = self.helper.file['e_shoff'] != 0
        
        # Address of the new section table 
        new_section_table_addr = new_elf.file_size()

        if has_section_table:
            new_elf.memcpy(-1, self.helper.file['e_shoff'], self.helper.file['e_shnum'] * self.helper.file['e_shentsize'])
        
        
        # Address of the headers we're gonna fill in shortly
        # same as new_section_table_addr if file didn't have section table
        new_section_header_addr = new_elf.file_size()
    

        # if there's no section table yet we also have to add a shstrtab, else we just change the existing one
        to_add = 2 if has_section_table else 3
        
        # Append two dummy section headers 
        new_elf.append(b"\x00" * (to_add * self.helper.file['e_shentsize']))
        
        return (new_section_table_addr, new_section_header_addr)

    
    def add_syms_to_existing(self, symtab):
        """
        Add new symbols to an ELF if there is already a symbol table present
        """
        strtab = symtab.stringtable
        
        symtab_growth, strtab_growth = self.calc_section_size_diffs()
                
        elf = NewELF(self.path, self.new_path, helper=self.helper)
        
        # Start by appending the new symtab and strtab to the end of the ELF
        new_symtab_begin, new_strtab_begin = self.new_elf_append_syms(elf, old_symtab=symtab, old_strtab=strtab)
        

        # Then change the section headers to point to our new symtab and strtab
        symtab_hdr = symtab.header.copy()
        strtab_hdr = strtab.header.copy()
        
        symtab_hdr['sh_size'] += symtab_growth
        symtab_hdr['sh_offset'] = new_symtab_begin

        strtab_hdr['sh_size'] += strtab_growth
        strtab_hdr['sh_offset'] = new_strtab_begin
        
        shdr = self.helper.file.structs.Elf_Shdr
        
        # Write them to the new ELF
        elf.write_struct_at(self.helper.section_to_entry_addr(symtab), shdr, symtab_hdr) 
        elf.write_struct_at(self.helper.section_to_entry_addr(strtab), shdr, strtab_hdr) 
        
        # clear out old ones
        elf.memset(b'\x00', symtab['sh_offset'], symtab['sh_size'])
        elf.memset(b'\x00', strtab['sh_offset'], strtab['sh_size'])

    
    def add_new_syms(self):
        """
        Add symbols to an ELF that doesn't contain a symbol table yet, or no section table at all
        """

        elf = NewELF(self.path, self.new_path, helper=self.helper)
         
        # Then append the new symtab and strtab
        new_symtab_begin, new_strtab_begin = self.new_elf_append_syms(elf, old_symtab=None, old_strtab=None)
        
        # Determine if there was already a section string table present in the old section table
        # (if there was one in the first place). If so, we can reuse this entry
        if self.helper.file['e_shstrndx']:
            old_shstrtab = self.helper.file.get_section(self.helper.file['e_shstrndx'])
            old_shstrtab_size = old_shstrtab['sh_size']
        else:
            old_shstrtab = None
            old_shstrtab_size = 0
        
        # New strings to add to the section string table
        new_strings = [b".symtab", b".strtab"]
        
        if not old_shstrtab:
            new_strings = [b".shstrtab"] + new_strings
            
        
        # Now, append the new section string table
        new_shstrtab_begin = self.new_elf_append_string_table(elf, new_strings, old_shstrtab)

        sizes = self.calc_section_size_diffs()
        
        def new_string_offset(string):
            return b"\x00".join(new_strings).index(string)
        
        # Craft the new headers of all the sections we altered
        symtab_hdr = self.create_new_section_header(
                sh_name=(old_shstrtab_size + new_string_offset(b".symtab")),
                sh_type='SHT_SYMTAB',
                sh_flags=0,
                sh_addr=0,
                sh_offset=new_symtab_begin,
                sh_size=sizes[0] + self.helper.file.structs.Elf_Sym.sizeof(),
                sh_link=self.helper.file.header['e_shnum'] + 1,
                sh_info=1, 
                sh_addralign=8, 
                sh_entsize=self.helper.file.structs.Elf_Sym.sizeof())

        strtab_hdr = self.create_new_section_header(
                sh_name=(old_shstrtab_size + new_string_offset(b".strtab")),
                sh_type='SHT_STRTAB',
                sh_flags=0,
                sh_addr=0,
                sh_offset=new_strtab_begin,
                sh_size=sizes[1],
                sh_link=0,
                sh_info=0,
                sh_addralign=0,
                sh_entsize=0)
        
        shstrtab_hdr = self.create_new_section_header(
               sh_name=(old_shstrtab['sh_name'] if old_shstrtab else 0),
               sh_type='SHT_STRTAB',
               sh_flags=0,
               sh_addr=0,
               sh_offset=new_shstrtab_begin,
               sh_size=old_shstrtab_size + len(b"\x00".join(new_strings)) + 1,
               sh_link=0,
               sh_info=0,
               sh_addralign=0,
               sh_entsize=0)
            

        # Start by appending a new section header table
        section_table_addr, section_header_addr = self.new_elf_append_section_table(elf)
        

        shdr = self.helper.file.structs.Elf_Shdr
        

        # Write the new symtab and strtab headers
        elf.write_struct_at(section_header_addr, shdr, symtab_hdr)
        elf.write_struct_at(section_header_addr + shdr.sizeof(), shdr, strtab_hdr)
        
        shstrtab_offset = section_table_addr + self.helper.section_to_entry_idx(old_shstrtab) * shdr.sizeof() if old_shstrtab else section_header_addr + 2 * shdr.sizeof()
        
        # Write the new shstrtab headers
        elf.write_struct_at(shstrtab_offset, shdr, shstrtab_hdr)
        


        # We also need to change the actual ELF header
        elf_header = self.helper.file.header.copy()

        elf_header['e_shoff'] = section_table_addr
        elf_header['e_shnum'] += (2 if old_shstrtab else 3)
        elf_header['e_shstrndx'] = (self.helper.section_to_entry_idx(old_shstrtab) if old_shstrtab else (elf_header['e_shnum'] - 1))
        
        # Write the new one (always at pos 0)
        elf.write_struct_at(0, self.helper.file.structs.Elf_Ehdr, elf_header)
        
        
        if self.helper.file['e_shoff'] != 0:
            # Finally, zero the old section headers
            elf.memset(b"\x00", self.helper.file['e_shoff'], self.helper.file['e_shnum'] * self.helper.file['e_shentsize'])

    def add_back_symbols(self):
         
        symtab = self.helper.locate_symtab()
        
        if symtab:
            self.add_syms_to_existing(symtab)
        else:
            self.add_new_syms()
    

    def calc_section_size_diffs(self):
        symtab_growth = len(self._symbols) * self.helper.file.structs.Elf_Sym.sizeof()
         
        # Combined size of all strings + 1 char per entry for null termination
        strtab_growth = sum(map(len, self.new_symbols_strtab)) + len(self.new_symbols_strtab)
        
        return symtab_growth, strtab_growth


    def create_new_section_header(self, 
            sh_name=None,
            sh_type=None,
            sh_flags=0,
            sh_addr=0,
            sh_offset=None,
            sh_size=None,
            sh_link=None,
            sh_info=None,
            sh_addralign=None,
            sh_entsize=None):
        
        def wrapper(**kwargs):

            c = Container()
            for k,v in kwargs.items():
                c[k] = v

            return c

        return wrapper(
                sh_name=sh_name, 
                sh_type=sh_type,
                sh_flags=sh_flags,
                sh_addr=sh_addr,
                sh_offset=sh_offset,
                sh_size=sh_size,
                sh_link=sh_link,
                sh_info=sh_info,
                sh_addralign=sh_addralign,
                sh_entsize=sh_entsize)
        

    def serialize_symbols(self, initial_size):
        return b''.join([symbol.serialize(self.helper.file, self.new_symbols_strtab, initial_size) for symbol in self._symbols])
    
    @property
    @functools.cache
    def new_symbols_strtab(self):
        return list(set(map(lambda x: x.name, self._symbols)))
 
if __name__ == "__main__":
    a = Unstrip("./example_bins/test_stripped", new_path='./bruh')
    
    symbols = get_ida_symbols('./example_bins/test_stripped_ida.i64')

    a.set_symbols(symbols)

    a.add_back_symbols()
