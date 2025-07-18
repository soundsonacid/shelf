use std::collections::HashMap;

use anyhow::{Result, anyhow};

use crate::parser::constants::*;
use crate::parser::types::{Elf64Ehdr, Elf64PHdr, Elf64Shdr, Elf64Sym, ElfIdent};

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

#[derive(Default)]
pub struct Elf {
    pub bytes: Vec<u8>,
    pub program_header_table: Vec<Elf64PHdr>,
    pub named_section_headers: HashMap<String, Elf64Shdr>,
    pub named_symbols: Option<HashMap<String, Elf64Sym>>,
    pub named_dynsym: Option<HashMap<String, Elf64Sym>>,
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

        let named_section_headers = Self::parse_section_header_names(bytes, header.e_shstrndx as usize, &section_header_table)?;

        let mut elf = Self { bytes: bytes.to_owned(), program_header_table, named_section_headers, ..Default::default() };

        elf.parse_symbol_tables()?;
        Ok(elf)
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

    fn parse_section_header_names(elf_bytes: &[u8], string_table_index: usize, section_header_table: &[Elf64Shdr]) -> Result<HashMap<String, Elf64Shdr>> {
        let string_table_header = section_header_table[string_table_index];
        let range = string_table_header.range();
        let string_table_bytes = elf_bytes.get(range).ok_or(anyhow!("Invalid range"))?;

        let parse_header_name = |header: &Elf64Shdr| -> Result<String> {
            let start = header.sh_name as usize;
            let end = string_table_bytes[start..]
                .iter()
                .position(|i| *i == 0)
                .ok_or(anyhow!("Failed to parse name"))?;
            Ok(std::str::from_utf8(&string_table_bytes[start..start + end]).map(|s| s.to_owned())?)
        };

        section_header_table
            .iter()
            .map(|header| {
                let name = parse_header_name(header)?;
                Ok((name, *header))
            })
            .collect()
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

        let parse_symbol_name = |symbol: &Elf64Sym, name_table_bytes: &[u8]| -> Result<String> {
            let start = symbol.st_name as usize;
            let end = name_table_bytes[start..]
                .iter()
                .position(|i| *i == 0)
                .ok_or(anyhow!("Failed to parse name"))?;
            Ok(std::str::from_utf8(&name_table_bytes[start..start + end]).map(|s| s.to_owned())?)
        };

        macro_rules! parse_symbol_table {
            ($self:ident, $table:ident, $names:ident, $field:ident) => {
                let table_range = self
                    .get_section_header($table)
                    .expect("Invalid symbol table name")
                    .range();
                let symbols_bytes = self
                    .bytes
                    .get(table_range)
                    .ok_or(anyhow!("Invalid range"))?;

                let symbols = symbols_bytes
                    .chunks_exact(std::mem::size_of::<Elf64Sym>())
                    .map(|b| parse_symbol(b, &mut 0))
                    .collect::<Result<Vec<_>>>()?;

                let name_range = self
                    .get_section_header($names)
                    .expect("Invalid symbol table name")
                    .range();
                let names_bytes = self.bytes.get(name_range).ok_or(anyhow!("Invalid range"))?;

                let named_symbols = symbols
                    .iter()
                    .map(|symbol| {
                        let name = parse_symbol_name(symbol, names_bytes)?;
                        Ok((name, *symbol))
                    })
                    .collect::<Result<HashMap<_, _>>>()?;

                self.$field = Some(named_symbols);
            };
        }

        parse_symbol_table!(self, SYMTAB, STRTAB, named_symbols);
        parse_symbol_table!(self, DYNSYM, DYNSTR, named_dynsym);

        Ok(())
    }

    pub fn get_symbol(&self, symbol: &str) -> Option<&Elf64Sym> {
        if let Some(symtab) = self.named_symbols.as_ref()
            && let Some(symbol) = symtab.get(symbol)
        {
            return Some(symbol);
        }

        if let Some(dynsym) = self.named_dynsym.as_ref()
            && let Some(symbol) = dynsym.get(symbol)
        {
            return Some(symbol);
        }

        None
    }

    pub fn get_section_header(&self, name: &str) -> Option<&Elf64Shdr> {
        self.named_section_headers.get(name)
    }
}
