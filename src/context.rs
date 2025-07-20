use std::collections::BTreeMap;

use crate::config::{Config, SBPFVersion};
use crate::instruction::constants::IXN_SIZE_U64;
use crate::instruction::ixn::{BYTE_LEN_IMMEDIATE, BYTE_OFFSET_IMMEDIATE, BpfRelocationType};
use crate::memory::{Memory, Region};
use crate::parser::Elf;
use crate::parser::constants::{DYNSTR, TEXT};
use crate::vm::Vm;

pub type Functions<T> = BTreeMap<u32, T>;

/// Syscall function without context
pub type Syscall = fn(*mut Vm, u64, u64, u64, u64, u64);

#[allow(clippy::large_enum_variant)]
pub enum ExecutableProgram {
    Elf(Elf),
    Jit, // todo...
}

pub struct ExecutionContext {
    pub program: ExecutableProgram,
    pub memory: Memory,
    pub syscalls: Functions<Syscall>,
    pub funcs: Functions</* st_value */ u64>,
    pub config: Config,
}

impl ExecutionContext {
    pub fn new_from_elf(elf: Elf, config: Option<Config>) -> Self {
        let regions = elf
            .section_names()
            .iter()
            .filter_map(|region| Region::from_section(&elf, region))
            .collect::<Vec<_>>();

        // dbg!(&elf.dynamic_relocations);
        // dbg!(&elf.program_header_table);
        // dbg!(&elf.dynamic_symbols);

        let mut funcs: Functions<u64> = BTreeMap::new();
        for symbol in &elf.dynamic_symbols {
            let symbol_name = elf.get_symbol_name(DYNSTR, symbol);
            let name = hash_symbol_name(symbol_name.as_bytes());
            funcs.insert(name, symbol.st_value);
        }

        let program = ExecutableProgram::Elf(elf);

        let mut this = Self { program, memory: Memory::new(regions), syscalls: BTreeMap::new(), funcs, config: config.unwrap_or_default() };
        this.fixup();
        this
    }

    pub fn register_syscall(&mut self, hashed_symbol_name: u32, syscall: Syscall) {
        self.syscalls.insert(hashed_symbol_name, syscall);
    }

    pub fn syscall(&self, syscall: u32) -> Option<&Syscall> {
        self.syscalls.get(&syscall)
    }

    pub fn program_entrypoint(&self) -> u64 {
        *self.funcs.get(&hash_symbol_name(b"entrypoint")).unwrap()
    }

    pub fn program_bytes(&self) -> &[u8] {
        match &self.program {
            ExecutableProgram::Elf(elf) => &elf.bytes,
            ExecutableProgram::Jit => unimplemented!(),
        }
    }

    #[rustfmt::skip]
    fn fixup(&mut self) {
        match &self.program {
            ExecutableProgram::Elf(elf) => {
                if let Some(relocs) = &elf.dynamic_relocations {
                    for reloc in relocs {
                        let addr = reloc.r_offset as usize;
                        let sym = reloc.r_info.wrapping_shr(32);
                        let reloc_type = (reloc.r_info & 0xFFFFFFFF) as u32;
                        // dbg!(&reloc);
                        // dbg!(addr);
                        // dbg!(sym);
                        match reloc_type {
                            _ if reloc_type == BpfRelocationType::R_Bpf_None as u32 => {}
                            _ if reloc_type == BpfRelocationType::R_Bpf_64_64 as u32 => {
                                dbg!("R_Bpf_64_64");
                            }
                            _ if reloc_type == BpfRelocationType::R_Bpf_64_Relative as u32 => {
                                dbg!("R_Bpf_64_Relative");
                            }
                            _ if reloc_type == BpfRelocationType::R_Bpf_64_32 as u32 => {
                                dbg!("R_Bpf_64_32");
                                let symbol = elf.dynamic_symbols[sym as usize];
                                let name = elf.get_symbol_name(DYNSTR, &symbol);

                                // if the symbol is a defined function this is just a regular fn call
                                let key: u32 = if symbol.is_function() && symbol.st_value != 0 {
                                    let text_region = elf.get_section_header(TEXT).unwrap();
                                    let jump_pc = (symbol.st_value - text_region.sh_addr) / IXN_SIZE_U64;

                                    if self.config.below_sbpf_version(SBPFVersion::V3) {
                                        if name == "entrypoint" {
                                            hash_symbol_name(b"entrypoint")
                                        } else {
                                            hash_symbol_name(&(jump_pc as u32).to_le_bytes())
                                        }
                                    } else {
                                        jump_pc as u32
                                    }
                                } else {
                                    // otherwise it's a pre-sbpfv3 syscall
                                    hash_symbol_name(name.as_bytes())
                                };

                                let region = self.memory.find_region_for_addr_mut(addr).unwrap();
                                let relative_addr = (addr - region.addr_start) + BYTE_OFFSET_IMMEDIATE;
                                let range = relative_addr..relative_addr + BYTE_LEN_IMMEDIATE;
                                region.data[range].copy_from_slice(&u32::to_le_bytes(key));
                            }
                            _ => panic!("Unknown relocation type"),
                        }
                    }
                }
            }
            ExecutableProgram::Jit => unimplemented!(),
        }
    }
}

/// Hash a symbol name
///
/// This function is used by both the relocator and the VM to translate symbol
/// names into a 32 bit id used to identify a syscall function.  The 32 bit id
/// is used in the eBPF `call` instruction's imm field.
pub fn hash_symbol_name(name: &[u8]) -> u32 {
    use hash32::Hasher;
    let mut hasher = hash32::Murmur3Hasher::default();
    std::hash::Hash::hash_slice(name, &mut hasher);
    hasher.finish32()
}
