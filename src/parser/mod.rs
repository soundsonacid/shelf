use std::collections::HashMap;

use anyhow::Result;

use crate::parser::{constants::*, types::{Elf64Ehdr, Elf64PHdr, Elf64Shdr, Elf64Sym, ElfIdent}};

pub mod types;
pub mod constants;

fn read_u8(bytes: &[u8], off: &mut usize) -> Result<u8> {
    let value = bytes[*off];
    *off += 1;
    Ok(value)
}

fn read_u16(bytes: &[u8], off: &mut usize) -> Result<u16> {
    let value = u16::from_le_bytes(bytes[*off..*off + 2].try_into()?);
    *off += 2;
    Ok(value)
}

fn read_u32(bytes: &[u8], off: &mut usize) -> Result<u32> {
    let value = u32::from_le_bytes(bytes[*off..*off + 4].try_into()?);
    *off += 4;
    Ok(value)
}

fn read_u64(bytes: &[u8], off: &mut usize) -> Result<u64> {
    let value = u64::from_le_bytes(bytes[*off..*off + 8].try_into()?);
    *off += 8;
    Ok(value)
}

fn read<const N: usize>(bytes: &[u8], off: &mut usize) -> Result<[u8; N]> {
    let value: [u8; N] = bytes[*off..*off + N].try_into()?;
    *off += N;
    Ok(value)
}

pub struct Elf {}

impl Elf {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut off = 0;
        let header = Self::parse_header(bytes, &mut off)?;

        header.validate()?;

        let mut p_hdr_table = Vec::with_capacity(header.e_phnum as usize);

        off = header.e_phoff as usize;
        for _ in 0..header.e_phnum as usize {
            p_hdr_table.push(Self::parse_program_header(bytes, &mut off)?)
        }

        let mut s_hdr_table = Vec::with_capacity(header.e_shnum as usize);

        off = header.e_shoff as usize;
        for _ in 0..header.e_shnum as usize {
            s_hdr_table.push(Self::parse_section_header(bytes, &mut off)?)
        }

        let named_section_headers = Self::parse_section_header_names(bytes, &header, &s_hdr_table)?;

        let named_symbols = Self::parse_symtab(bytes, &named_section_headers, SYMTAB, STRTAB)?;
        let named_dynsym = Self::parse_symtab(bytes, &named_section_headers, DYNSYM, DYNSTR)?;

        dbg!(&named_section_headers);
        dbg!(&named_symbols);
        dbg!(&named_dynsym);

        todo!("finish elf parsing")
    }

    fn parse_header(bytes: &[u8], off: &mut usize) -> Result<Elf64Ehdr> {
        Ok(Elf64Ehdr {
            e_ident: Self::parse_ident(bytes, off)?,
            e_type: read_u16(bytes, off)?,
            e_machine: read_u16(bytes, off)?,
            e_version: read_u32(bytes, off)?,
            e_entry: read_u64(bytes, off)?,
            e_phoff: read_u64(bytes, off)?,
            e_shoff: read_u64(bytes, off)?,
            e_flags: read_u32(bytes, off)?,
            e_ehsize: read_u16(bytes, off)?,
            e_phentsize: read_u16(bytes, off)?,
            e_phnum: read_u16(bytes, off)?,
            e_shentsize: read_u16(bytes, off)?,
            e_shnum: read_u16(bytes, off)?,
            e_shstrndx: read_u16(bytes, off)?,
        })
    }

    fn parse_ident(bytes: &[u8], off: &mut usize) -> Result<ElfIdent> {
        Ok(ElfIdent {
            ei_mag: read::<4>(bytes, off)?,
            ei_class: read_u8(bytes, off)?,
            ei_data: read_u8(bytes, off)?,
            ei_version: read_u8(bytes, off)?,
            ei_osabi: read_u8(bytes, off)?,
            ei_abiversion: read_u8(bytes, off)?,
            ei_pad: read::<7>(bytes, off)?,
        })
    }

    fn parse_program_header(bytes: &[u8], off: &mut usize) -> Result<Elf64PHdr> {
        Ok(Elf64PHdr {
            p_type: read_u32(bytes, off)?,
            p_flags: read_u32(bytes, off)?,
            p_offset: read_u64(bytes, off)?,
            p_vaddr: read_u64(bytes, off)?,
            p_paddr: read_u64(bytes, off)?,
            p_filesz: read_u64(bytes, off)?,
            p_memsz: read_u64(bytes, off)?,
            p_align: read_u64(bytes, off)?,
        })
    }

    fn parse_section_header(bytes: &[u8], off: &mut usize) -> Result<Elf64Shdr> {
        Ok(Elf64Shdr {
            sh_name: read_u32(bytes, off)?,
            sh_type: read_u32(bytes, off)?,
            sh_flags: read_u64(bytes, off)?,
            sh_addr: read_u64(bytes, off)?,
            sh_offset: read_u64(bytes, off)?,
            sh_size: read_u64(bytes, off)?,
            sh_link: read_u32(bytes, off)?,
            sh_info: read_u32(bytes, off)?,
            sh_addralign: read_u64(bytes, off)?,
            sh_entsize: read_u64(bytes, off)?,
        })
    }

    fn parse_section_header_names(bytes: &[u8], hdr: &Elf64Ehdr, s_hdr_table: &[Elf64Shdr]) -> Result<HashMap<String, Elf64Shdr>> {
        let shstrtab_idx = hdr.e_shstrndx;
        let shstrtab_hdr = s_hdr_table[shstrtab_idx as usize];
        let off = shstrtab_hdr.sh_offset as usize;
        let len = shstrtab_hdr.sh_size as usize;
        let range = off..off + len;
        let bytes = bytes.get(range).unwrap();

        // parse the data of the section header string table into null-terminated strings
        let mut string_map = HashMap::new();
        let mut offset = 0;

        for chunk in bytes.split(|&b| b == 0) {
            string_map.insert(offset, std::str::from_utf8(chunk)?);
            offset += chunk.len() + 1; // +1 for the null byte
        }

        let mut named_section_headers = HashMap::new();

        for hdr in s_hdr_table {
            let name = (*string_map.get(&(hdr.sh_name as usize)).unwrap()).to_owned();
            named_section_headers.insert(name, *hdr);
        }

        Ok(named_section_headers)
    }

    fn parse_symtab(bytes: &[u8], named_section_headers: &HashMap<String, Elf64Shdr>, sym: &str, name: &str) -> Result<HashMap<String, Elf64Sym>> {
        let symtab_shdr = named_section_headers.get(&sym.to_owned()).unwrap();

        let off = symtab_shdr.sh_offset as usize;
        let len = symtab_shdr.sh_size as usize;
        let range = off..off + len;
        let symtab_bytes = bytes.get(range).unwrap();
        let size = std::mem::size_of::<Elf64Sym>();
        assert!(bytes.len().is_multiple_of(size));

        let num_symbols = symtab_bytes.len() / size;
        let mut symbols = Vec::with_capacity(num_symbols);

        for i in 0..num_symbols {
            let mut off = 0;
            let range = (size * i)..(size * (i + 1));
            let bytes = symtab_bytes.get(range).unwrap();
            symbols.push(Elf64Sym {
                st_name: read_u32(bytes, &mut off)?,
                st_info: read_u8(bytes, &mut off)?,
                st_other: read_u8(bytes, &mut off)?,
                st_shndx: read_u16(bytes, &mut off)?,
                st_value: read_u64(bytes, &mut off)?,
                st_size: read_u64(bytes, &mut off)?,
            })
        }

        let symstr_tab = named_section_headers.get(&name.to_owned()).unwrap();
        let off = symstr_tab.sh_offset as usize;
        let len = symstr_tab.sh_size as usize;
        let range = off..off + len;
        let bytes = bytes.get(range).unwrap();

        // parse the data of the string table into null-terminated strings
        let mut string_map = HashMap::new();
        let mut offset = 0;

        for chunk in bytes.split(|&b| b == 0) {
            string_map.insert(offset, std::str::from_utf8(chunk)?);
            offset += chunk.len() + 1; // +1 for the null byte
        }

        let mut named_symbols = HashMap::new();

        for symbol in symbols {
            let name = (*string_map.get(&(symbol.st_name as usize)).unwrap()).to_owned();
            named_symbols.insert(name, symbol);
        }

        Ok(named_symbols)
    }
}
