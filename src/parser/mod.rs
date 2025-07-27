use anyhow::{Result, anyhow};

use crate::parser::constants::*;
use crate::parser::types::{Elf64Ehdr, Elf64PHdr, Elf64Rel, Elf64Shdr, Elf64Sym, ElfIdent};

pub mod constants;
pub mod types;

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

pub struct Elf {
    pub bytes: Vec<u8>,
    pub program_header_table: Vec<Elf64PHdr>,
    pub section_header_names: Vec<String>,
    pub section_header_table: Vec<Elf64Shdr>,
    pub symbol_names_section_header: Option<Elf64Shdr>,
    pub symbols_section_header: Option<Elf64Shdr>,
    pub symbols: Option<Vec<Elf64Sym>>,
    pub dynamic_symbols_names_section_header: Option<Elf64Shdr>,
    pub dynamic_symbols_section_header: Option<Elf64Shdr>,
    pub dynamic_symbols: Option<Vec<Elf64Sym>>,
    pub dynamic_relocations_table: Option<Elf64Shdr>,
    pub dynamic_relocations: Option<Vec<Elf64Rel>>,
}

impl Elf {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut off = 0;
        let header = Self::parse_header(bytes, &mut off)?;

        header.validate()?;

        let mut phoff = header.e_phoff as usize;
        let phnum = header.e_phnum as usize;
        let program_header_table = Self::parse_header_table(bytes, &mut phoff, phnum, Self::parse_program_header)?;

        let mut shoff = header.e_shoff as usize;
        let shnum = header.e_shnum as usize;
        let section_header_table = Self::parse_header_table(bytes, &mut shoff, shnum, Self::parse_section_header)?;

        let section_header_names = Self::parse_section_header_names(bytes, header.e_shstrndx as usize, &section_header_table)?;

        let dynamic_relocations_table = Self::find_section_header(&section_header_names, &section_header_table, REL_DYN);
        let dynamic_symbols_names_section_header = Self::find_section_header(&section_header_names, &section_header_table, DYNSTR);
        let symbol_names_section_header = Self::find_section_header(&section_header_names, &section_header_table, STRTAB);
        let dynamic_symbols_section_header = Self::find_section_header(&section_header_names, &section_header_table, DYNSYM);
        let symbols_section_header = Self::find_section_header(&section_header_names, &section_header_table, SYMTAB);

        let mut elf = Self {
            bytes: bytes.to_owned(),
            program_header_table,
            section_header_names,
            section_header_table,
            symbol_names_section_header,
            symbols_section_header,
            symbols: None,
            dynamic_symbols_names_section_header,
            dynamic_symbols_section_header,
            dynamic_symbols: None,
            dynamic_relocations: None,
            dynamic_relocations_table,
        };

        elf.parse_symbol_tables()?;
        elf.parse_relocations()?;

        Ok(elf)
    }

    fn find_section_header(section_header_names: &[String], section_header_table: &[Elf64Shdr], section: &str) -> Option<Elf64Shdr> {
        section_header_names
            .iter()
            .position(|s| s == section)
            .map(|pos| section_header_table[pos])
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

    fn parse_header_table<T>(bytes: &[u8], off: &mut usize, num: usize, parse: impl Fn(&[u8], &mut usize) -> Result<T>) -> Result<Vec<T>> {
        let mut headers = Vec::with_capacity(num);
        for _ in 0..num {
            headers.push(parse(bytes, off)?);
        }

        Ok(headers)
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

    fn parse_section_header_names(elf_bytes: &[u8], string_table_index: usize, section_header_table: &[Elf64Shdr]) -> Result<Vec<String>> {
        let string_table_header = section_header_table[string_table_index];
        let range = string_table_header.range();
        let string_table_bytes = &elf_bytes[range];

        let parse_header_name = |header: &Elf64Shdr| -> Result<String> {
            let start = header.sh_name as usize;
            let end = string_table_bytes[start..]
                .iter()
                .position(|i| *i == 0)
                .ok_or(anyhow!("Failed to parse name"))?;
            Ok(std::str::from_utf8(&string_table_bytes[start..start + end]).map(str::to_owned)?)
        };

        section_header_table.iter().map(parse_header_name).collect()
    }

    fn parse_symbol_tables(&mut self) -> Result<()> {
        let parse_symbol = |bytes: &[u8], off: &mut usize| -> Result<Elf64Sym> {
            Ok(Elf64Sym {
                st_name: read_u32(bytes, off)?,
                st_info: read_u8(bytes, off)?,
                st_other: read_u8(bytes, off)?,
                st_shndx: read_u16(bytes, off)?,
                st_value: read_u64(bytes, off)?,
                st_size: read_u64(bytes, off)?,
            })
        };

        let parse_table = |table: &'static str| -> Option<Vec<Elf64Sym>> {
            let table_range = match table {
                _ if table == SYMTAB => self.symbols_section_header?.range(),
                _ if table == DYNSYM => self.dynamic_symbols_section_header?.range(),
                _ => panic!("Invalid section header name table"),
            };
            let symbols_bytes = &self.bytes[table_range];

            symbols_bytes
                .chunks_exact(std::mem::size_of::<Elf64Sym>())
                .map(|b| parse_symbol(b, &mut 0).ok())
                .collect::<Option<Vec<_>>>()
        };

        let symbols = parse_table(SYMTAB);
        let dynamic_symbols = parse_table(DYNSYM);

        self.symbols = symbols;
        self.dynamic_symbols = dynamic_symbols;

        Ok(())
    }

    fn parse_relocations(&mut self) -> Result<()> {
        let parse_relocation = |bytes: &[u8], off: &mut usize| -> Result<Elf64Rel> {
            Ok(Elf64Rel {
                r_offset: read_u64(bytes, off)?,
                r_info: read_u64(bytes, off)?,
            })
        };

        let dynamic_relocations = if let Some(dynamic_relocations) = self.dynamic_relocations_table {
            let start = dynamic_relocations.sh_offset as usize;
            let len = dynamic_relocations.sh_size as usize;
            let range = start..start + len;
            let bytes = &self.bytes[range];
            let chunks = bytes.chunks(std::mem::size_of::<Elf64Rel>());

            Some(
                chunks
                    .map(|chunk| parse_relocation(chunk, &mut 0).unwrap())
                    .collect(),
            )
        } else {
            None
        };

        self.dynamic_relocations = dynamic_relocations;

        Ok(())
    }

    pub fn section_names(&self) -> &[String] {
        &self.section_header_names
    }

    pub fn get_symbol_name(&self, name_table: &str, symbol: &Elf64Sym) -> String {
        let name_table = match name_table {
            _ if name_table == DYNSTR => self.dynamic_symbols_names_section_header.unwrap(),
            _ if name_table == STRTAB => self.symbol_names_section_header.unwrap(),
            _ => panic!("Invalid section header name table"),
        };
        let name_offset = name_table.sh_offset + symbol.st_name as u64;
        let slice = &self.bytes[name_offset as usize..];
        let end = slice.iter().position(|b| *b == 0).unwrap();
        str::from_utf8(&slice[..end]).unwrap().to_owned()
    }
}
