import struct
from .. import utils
import IPython


class ELFHeader(object):
    def __init__(self, project):
        self.magic = b'\x7fELF'
        self.header = {'e_type': 0,
                       'e_machine': 0,
                       'e_version': 0,
                       'e_entry': 0,
                       'e_phoff': 0,
                       'e_shoff': 0,
                       'e_flags': 0,
                       'e_ehsize': 0,
                       'e_phentsize': 0,
                       'e_phnum': 0,
                       'e_shentsize': 0,
                       'e_shnum': 0,
                       'e_shstrndx': 0}

        self.bits = project.arch.bits

        self.unpack_str = '<' + 'x'*16 + 'HHL'
        if self.bits == 32:
            self.header_size = 0x34
            self.unpack_str += 'L'*3
        elif self.bits == 64:
            self.header_size = 0x40
            self.unpack_str += 'Q'*3

        self.unpack_str += 'L' + 'H'*6

    @property
    def e_type(self):
        return self.header['e_type']

    @e_type.setter
    def e_type(self, val):
        assert val in [0, 1, 2, 3, 4, 0xfe00, 0xfeff, 0xff00, 0xffff]
        self.header['e_type'] = val

    @property
    def e_machine(self):
        return self.header['e_machine']

    @e_machine.setter
    def e_machine(self, val):
        assert val in [0, 2, 3, 8, 0x14, 0x16, 0x28,
                       0x2A, 0x32, 0x3E, 0xB7, 0xF3]
        self.header['e_machine'] = val

    @property
    def e_version(self):
        return self.header['e_version']

    @e_version.setter
    def e_version(self, val):
        self.header['e_version'] = val

    @property
    def e_entry(self):
        return self.header['e_entry']

    @e_entry.setter
    def e_entry(self, val):
        self.header['e_entry'] = val

    @property
    def e_phoff(self):
        return self.header['e_phoff']

    @e_phoff.setter
    def e_phoff(self, val):
        self.header['e_phoff'] = val

    @property
    def e_shoff(self):
        return self.header['e_shoff']

    @e_shoff.setter
    def e_shoff(self, val):
        self.header['e_shoff'] = val

    @property
    def e_flags(self):
        return self.header['e_flags']

    @e_flags.setter
    def e_flags(self, val):
        self.header['e_flags'] = val

    @property
    def e_ehsize(self):
        return self.header['e_ehsize']

    @e_ehsize.setter
    def e_ehsize(self, val):
        self.header['e_ehsize'] = val

    @property
    def e_phentsize(self):
        return self.header['e_phentsize']

    @e_phentsize.setter
    def e_phentsize(self, val):
        if self.bits == 32:
            assert val == 0x20
        elif self.bits == 64:
            assert val == 0x38
        self.header['e_phentsize'] = val

    @property
    def e_phnum(self):
        return self.header['e_phnum']

    @e_phnum.setter
    def e_phnum(self, val):
        assert val != 0
        self.header['e_phnum'] = val

    @property
    def e_shentsize(self):
        return self.header['e_shentsize']

    @e_shentsize.setter
    def e_shentsize(self, val):
        self.header['e_shentsize'] = val

    @property
    def e_shnum(self):
        return self.header['e_shnum']

    @e_shnum.setter
    def e_shnum(self, val):
        self.header['e_shnum'] = val

    @property
    def e_shstrndx(self):
        return self.header['e_shstrndx']

    @e_shstrndx.setter
    def e_shstrndx(self, val):
        self.header['e_shstrndx'] = val

    def raw(self):
        # Skip the first 16 magic bytes
        pack_str = self.unpack_str.replace('x', '')
        return struct.pack(pack_str, self.e_type, self.e_machine,
                           self.e_version, self.e_entry, self.e_phoff,
                           self.e_shoff, self.e_flags, self.e_ehsize,
                           self.e_phentsize, self.e_phnum, self.e_shentsize,
                           self.e_shnum, self.e_shstrndx)

    def parse_header(self, buf):
        '''
        Parse the ELF header which should be in buf
        '''
        assert buf[:4] == self.magic
        assert len(buf) > self.header_size

        '''
        The ELF header for x86 and x64 follow the same order of entries
        '''
        (self.e_type, self.e_machine, self.e_version, self.e_entry,
         self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize,
         self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum,
         self.e_shstrndx) = struct.unpack(self.unpack_str,
                                          buf[:self.header_size])

        return self.header_size


class SegmentHeader(object):
    def __init__(self, project):
        self.header = {'p_type': 0,
                       'p_flags': 0,
                       'p_offset': 0,
                       'p_vaddr': 0,
                       'p_paddr': 0,
                       'p_filesz': 0,
                       'p_memsz': 0,
                       'p_align': 0}

        self.pt_types = {0: 'NULL',
                         1: 'LOAD',
                         2: 'DYNAMIC',
                         3: 'INTERP',
                         4: 'NOTE',
                         5: 'SHLIB',
                         6: 'PHDR',
                         0x60000000: 'LOOS',
                         0x6FFFFFFF: 'HIOS',
                         0x6474e550: 'GNU_EH_FRAME',
                         0x6474e551: 'GNU_STACK',
                         0x6474e552: 'GNU_RELRO',
                         0x70000000: 'LOPROC',
                         0x7FFFFFFF: 'HIPROC'}

        self.bits = project.arch.bits

        self.unpack_str = '<' + 'L'
        if self.bits == 32:
            self.header_size = 0x20
            self.unpack_str += 'L' * 7
        elif self.bits == 64:
            self.header_size = 0x38
            self.unpack_str += 'L' + 'Q'*6

    @property
    def p_type(self):
        return self.header['p_type']

    @p_type.setter
    def p_type(self, val):
        assert val in self.pt_types
        self.header['p_type'] = val

    @property
    def p_flags(self):
        return self.header['p_flags']

    @p_flags.setter
    def p_flags(self, val):
        self.header['p_flags'] = val

    @property
    def p_offset(self):
        return self.header['p_offset']

    @p_offset.setter
    def p_offset(self, val):
        self.header['p_offset'] = val

    @property
    def p_vaddr(self):
        return self.header['p_vaddr']

    @p_vaddr.setter
    def p_vaddr(self, val):
        self.header['p_vaddr'] = val

    @property
    def p_paddr(self):
        return self.header['p_paddr']

    @p_paddr.setter
    def p_paddr(self, val):
        self.header['p_paddr'] = val

    @property
    def p_filesz(self):
        return self.header['p_filesz']

    @p_filesz.setter
    def p_filesz(self, val):
        self.header['p_filesz'] = val

    @property
    def p_memsz(self):
        return self.header['p_memsz']

    @p_memsz.setter
    def p_memsz(self, val):
        self.header['p_memsz'] = val

    @property
    def p_align(self):
        return self.header['p_align']

    @p_align.setter
    def p_align(self, val):
        self.header['p_align'] = val

    def dbg_repr(self, off, x):
        print("---")
        print("Loc:" + hex(off + self.header_size * x))
        print("Type: %s" % self.pt_types[self.p_type])
        print("Permissions: %s" % utils.pflags_to_perms(self.p_flags))
        print("Memory: 0x%x + 0x%x" % (self.p_vaddr, self.p_memsz))
        print("File: 0x%x + 0x%x" % (self.p_offset, self.p_filesz))
        print(map(hex, (self.p_type, self.p_offset, self.p_vaddr, self.p_paddr,
                        self.p_filesz, self.p_memsz, self.p_flags,
                        self.p_align)))

    def parse_header(self, buf):
        assert len(buf) > self.header_size

        if self.bits == 32:
            (self.p_type, self.p_offset, self.p_vaddr, self.p_paddr,
             self.p_filesz, self.p_memsz, self.p_flags,
             self.p_align) = struct.unpack(self.unpack_str,
                                           buf[:self.header_size])
        elif self.bits == 64:
            (self.p_type, self.p_flags, self.p_offset, self.p_vaddr,
             self.p_paddr, self.p_filesz, self.p_memsz,
             self.p_align) = struct.unpack(self.unpack_str,
                                           buf[:self.header_size])

        return self.header_size

    def raw(self):
        # Here the packing and unpacking are done with the same strings
        if self.bits == 32:
            return struct.pack(self.unpack_str, self.p_type, self.p_offset,
                               self.p_vaddr, self.p_paddr, self.p_filesz,
                               self.p_memsz, self.p_flags, self.p_align)
        elif self.bits == 64:
            return struct.pack(self.unpack_str, self.p_type, self.p_flags,
                               self.p_offset, self.p_vaddr, self.p_paddr,
                               self.p_filesz, self.p_memsz, self.p_align)
