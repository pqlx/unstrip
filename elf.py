from typing import List

import logging
import shutil
import os

from elftools.elf.elffile import ELFFile

logger = logging.getLogger(__name__)

class ELFHelper:
    '''
    Class used to gather all info we need in order to add our symbols.
    PyElf doesn't support write operations, this class is meant for reading exclusively
    '''

    def __init__(self, path: str):
        self.handle = open(path, 'rb')
        self.file = ELFFile(self.handle)

    def locate_symtab(self):
        
        result = None
        for section in self.file.iter_sections():
            if section['sh_type'] == 'SHT_SYMTAB':
                
                if not result:
                    logger.warn('Multiple sections of type SHT_SYMTAB found. Using the last one')
                
                if section.name != '.symtab':
                    logger.warn("Symbol table section is not called '.symtab'")

                result = section
        
        return result

    def section_idx_to_entry_addr(self, idx: int):
        return self.file['e_shoff'] + idx * self.file['e_shentsize']
   
    def section_to_entry_addr(self, section):
        return self.section_idx_to_entry_addr(self.section_to_entry_idx(section))

    def section_to_entry_idx(self, section):

        for i, fsection in enumerate(self.file.iter_sections()):
            if fsection['sh_offset'] == section['sh_offset']:
                return i
        
        return None

class NewELF:
    
    orig_path: str
    new_path: str
    helper: ELFHelper

    def __init__(self, orig_path: str, new_path: str, helper: ELFHelper=None):
        self.orig_path = orig_path
        self.new_path = new_path
        self.helper = helper or ELFHelper(orig_path) 
        
        self._do_copy()
          
    def preserve_handle(func):
        
        def new_func(self, *args, **kwargs):
            old_pos = self.handle.tell()
            result = func(self, *args, **kwargs)
            self.handle.seek(old_pos)
            
            return result
        return new_func
    
    
    @preserve_handle 
    def memset(self, byte: bytes, pos: int, n: int, bsize: int = 0x400):
       
        self.handle.seek(pos)

        n_writes = n // bsize
        residue = n % bsize
        
        to_write = byte * bsize
        
        for _ in range(n_writes):
            self.handle.write(to_write)

        self.handle.write(to_write[:residue])
        self.handle.flush()
    
    
    @preserve_handle
    def memcpy(self, dest: int, src: int, n: int):
       
        self.handle.seek(src)
        data = self.handle.read(n)

        if dest == -1:
            self.handle.seek(0, os.SEEK_END)
        else:
            self.handle.seek(dest)
        
        self.handle.write(data)
        self.handle.flush()

    @preserve_handle
    def file_size(self):
        self.handle.seek(0, os.SEEK_END)
        return self.handle.tell()

    def clearsection(self, section):
        
        self.memset(b"\x00", section['sh_offset'], section['sh_size'])
    
    @preserve_handle
    def write_struct_at(self, address: int, struct, container):
        to_write = struct.build(container)
        
        self.handle.seek(address)
        self.handle.write(to_write)

        self.handle.flush()
    
    @preserve_handle
    def append(self, data: bytes):

        self.handle.seek(0, os.SEEK_END)
        self.handle.write(data)
        self.handle.flush()

        return self.handle.tell()
    
    @preserve_handle
    def read_at(self, address, n):
        self.handle.seek(address)
        return self.handle.read(n)

    def _do_copy(self):
        shutil.copy(self.orig_path, self.new_path)

        self.handle = open(self.new_path, 'rb+') 
