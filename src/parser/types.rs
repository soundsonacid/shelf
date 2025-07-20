use std::ops::Range;

use crate::parser::constants::*;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ElfIdent {
    /// must always be 0x7FELF
    pub ei_mag: [u8; 4],
    /// identifies architecture for the binary
    /// ELFCLASSNONE: Invalid
    /// ELFCLASS32: 32-bit architecture
    /// ELFCLASS64: 64-bit architecture
    pub ei_class: u8,
    /// data encoding of processor-specific data in file
    /// ELFDATANONE: Unknown
    /// ELFDATA2LSB: 2's complement LE
    /// ELFDATA2MSB: 2's complement BE
    pub ei_data: u8,
    /// version number of elf spec
    /// EV_NONE: Invalid
    /// EV_CURRENT: current version
    pub ei_version: u8,
    /// os & abi to which object is targeted
    pub ei_osabi: u8,
    /// version of abi to which object is targeted
    /// used to distinguish between incompatible versions of an abi
    /// dependent on abi identified in ei_osabi
    pub ei_abiversion: u8,
    /// padding
    pub ei_pad: [u8; 7],
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Elf64Ehdr {
    pub e_ident: ElfIdent,
    /// identifies the object file type
    /// ET_NONE: an unknown type
    /// ET_REL: a relocatable file
    /// ET_EXEC: an executable file
    /// ET_DYN: a shared object
    /// ET_CORE: a core file
    pub e_type: u16,
    /// specifies the required architecture for an individual file
    pub e_machine: u16,
    /// identifies the file version
    /// EV_NONE: invalid version
    /// EV_CURRENT: current version
    pub e_version: u32,
    /// gives the virtual address to which the system first transfers control,
    /// thus starting the process if this file has no entrypoint, this field
    /// is zero
    pub e_entry: u64,
    /// holds the program header table's file offset in bytes
    /// if this file has no program header table, this field is zero
    pub e_phoff: u64,
    /// holds the section header table's file offset in bytes
    /// if this file has no section header table, this field is zero
    pub e_shoff: u64,
    /// holds processor specific flags associated with the file.  no flags have
    /// yet been defined
    pub e_flags: u32,
    /// holds the elf header's size in bytes
    pub e_ehsize: u16,
    /// holds the size in bytes of one entry in the program header table, all
    /// entries are the same size
    pub e_phentsize: u16,
    /// holds the number of entries in the program header table
    /// e_phentsize * e_phnum = ph table size in bytes
    /// if there is no program header, this field is zero
    /// if the len of the program header table gte 0xffff (PN_XUM), this field
    /// is PN_XUM and the real len is held in the sh_info member of the
    /// initial entry in the section header table otherwise, sh_info is zero
    pub e_phnum: u16,
    /// holds the size in bytes of one section header. all entries are the same
    /// size
    pub e_shentsize: u16,
    /// holds the number of entries in the section header table
    /// e_shentsize & e_shnum = sh table size in bytes
    /// if there is no section header table, this field is zero
    /// if the len of the section header table gte 0xff00 (SHN_LORESERVE), this
    /// field is zero and the real len is held in the sh_size member of the
    /// initial entry in the section header table otherwise sh_size is zero
    pub e_shnum: u16,
    /// holds the section header table index of the entry associated with the
    /// section name string table if this file has no section name string
    /// table, this field is SHN_UNDEF if the index of section name string
    /// table section gte 0xff00 (SHN_LORESERVE), this field is 0xffff
    /// (SHN_XINDEX) and the real index of the section name string table is
    /// held in the sh_link member of the initial entry in the section header
    /// table otherwise sh_link is zero
    pub e_shstrndx: u16,
}

impl Elf64Ehdr {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.e_ident.ei_mag != MAGIC {
            anyhow::bail!("Invalid magic")
        }

        if self.e_ident.ei_class != ELFCLASS64 {
            anyhow::bail!("Invalid elidentf class")
        }

        if self.e_ident.ei_data != ELFDATA2LSB {
            anyhow::bail!("Invalid ident endianness")
        }

        if self.e_ident.ei_version != EV_CURRENT as u8 {
            anyhow::bail!("Invalid ident version")
        }

        if self.e_phentsize != std::mem::size_of::<Elf64PHdr>() as u16 {
            anyhow::bail!("Invalid program header size")
        }

        if self.e_shentsize != std::mem::size_of::<Elf64Shdr>() as u16 {
            anyhow::bail!("Invalid section header size")
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Elf64PHdr {
    /// indicates what kind of segment this array's element describes
    /// or how to interpret the array element's information
    pub p_type: u32,
    /// holds a bit mask of flags relevant to the segment
    /// PF_X: executable segment
    /// PF_W: writable segment
    /// PF_R: readable segment
    /// text segments commonly hold PF_X & PF_R, data commonly hold PF_W & PF_R
    pub p_flags: u32,
    /// holds the offset from the beginning of the file at which the first byte
    /// of the segment resides
    pub p_offset: u64,
    /// holds the virtual address at which the first byte of the segment resides
    /// in memory
    pub p_vaddr: u64,
    /// on systems for which physical addressing is relevant, this field is
    /// reserved for the segment's physical address
    pub p_paddr: u64,
    /// holds the number of bytes in the file image of the segment (may be zero)
    pub p_filesz: u64,
    /// holds the number of bytes in the memory image of the segment (may be
    /// zero)
    pub p_memsz: u64,
    /// holds the value to which the segments are aligned in memory and in the
    /// file values of zero and one mean no alignment is required
    /// otherwise, p_align should be a positive power of two integer
    /// and p_vaddr should = p_offset, % p_align
    pub p_align: u64,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Elf64Shdr {
    /// specifies the name of a section
    /// its value is an index into the section header string table section
    pub sh_name: u32,
    /// categorizes the section's contents & semantics
    pub sh_type: u32,
    /// sections support one-bit flags that describe misc. attributes
    /// SHF_WRITE: section contains data that should be writable execution
    /// SHF_ALLOC: section occupies memory during execution
    /// SHF_EXECINSTR: section contains executable machine instructions
    /// SHF_MASKPROC: all bits are reserved for processor-specific semantics
    pub sh_flags: u64,
    /// if this section appears in the memory image of a process,
    /// this holds the address at which the section's first byte should reside
    /// otherwise zero
    pub sh_addr: u64,
    /// holds the byte offset from the beginning of the file to the first byte
    /// in the section SHT_NOBITS occupies no space in the file, and this
    /// locates the conceptual placement in the file
    pub sh_offset: u64,
    /// holds the section's size in bytes
    /// unless the sh_type is SHT_NOBITS, the section occupies sh_size bytes in
    /// the file
    pub sh_size: u64,
    /// holds a section header table index link
    pub sh_link: u32,
    pub sh_info: u32,
    /// some sections have address alignment constraints
    /// if a section holds a doubleword, the system must ensure doubleword
    /// alignment for the entire section sh_addr must be congruent to zero,
    /// module the value of sh_addralign only zero and positive integral
    /// powers of two are allowed
    pub sh_addralign: u64,
    /// some sections hold a table of fixed-sized entries, such as a symbol
    /// table for such a section, this member gives the size in bytes of
    /// each entry contains zero if the section does not hold a table of
    /// fixed size entries
    pub sh_entsize: u64,
}

impl Elf64Shdr {
    pub fn range(&self) -> Range<usize> {
        let start = self.sh_offset as usize;
        let len = self.sh_size as usize;
        start..start + len
    }

    pub fn should_alloc(&self) -> bool {
        (self.sh_flags & SHF_ALLOC) != 0
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Elf64Sym {
    /// holds an index in the object file's symbol string table, which holds
    /// character repr's of symbol names. if the value is nonzero it
    /// corresponds to a string table index
    pub st_name: u32,
    /// specifes the symbol's type & binding attributes
    pub st_info: u8,
    /// defines the symbol visibility
    pub st_other: u8,
    /// every symbol table entry is "defined" in relation to another section
    /// this holds the relevant section header table index
    pub st_shndx: u16,
    /// value of the associated symbol
    pub st_value: u64,
    /// holds the associated size of the symbol, or zero if the symbol has no
    /// size or an unknown size
    pub st_size: u64,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Elf64Rel {
    /// gives the relocation at which to apply the relocation action
    /// for a relocatable file, the value is the byte offset from the beginning
    /// of the section to the storage unit affected for an executable or a
    /// .so, the value is the virtual address of the storage unit affects
    pub r_offset: u64,
    /// gives the symbol table index with respect to which the relocation must
    /// be made and the type of relocation to apply
    pub r_info: u64,
}
