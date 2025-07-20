use std::collections::BTreeMap;

use crate::config::Config;
use crate::instruction::constants::IXN_SIZE_U64;
use crate::memory::{Memory, Region};
use crate::parser::Elf;
use crate::program::ExecutableProgram;
use crate::vm::Vm;

pub type Functions<T> = BTreeMap<u32, T>;

/// Syscall function without context
pub type Syscall = fn(*mut Vm, u64, u64, u64, u64, u64);

pub struct ExecutionContext {
    pub program: ExecutableProgram,
    pub memory: Memory,
    pub syscalls: Functions<Syscall>,
    pub config: Config,
}

impl ExecutionContext {
    pub fn new_from_elf(elf: Elf, config: Option<Config>) -> Self {
        let regions = elf
            .section_names()
            .iter()
            .filter_map(|region| Region::from_section(&elf, region))
            .collect::<Vec<_>>();

        dbg!(&elf.dynamic_relocations);
        dbg!(&elf.program_header_table);
        dbg!(&elf.named_symbols);
        dbg!(&elf.named_dynsym);

        let program = ExecutableProgram::Elf(elf);
        program.fixup();

        Self { program, memory: Memory::new(regions), syscalls: BTreeMap::new(), config: config.unwrap_or_default() }
    }

    pub fn register_syscall(&mut self, hashed_symbol_name: u32, syscall: Syscall) {
        self.syscalls.insert(hashed_symbol_name, syscall);
    }

    pub fn syscall(&self, syscall: u32) -> Option<&Syscall> {
        self.syscalls.get(&syscall)
    }

    pub fn program_bytes(&self) -> &[u8] {
        match &self.program {
            ExecutableProgram::Elf(elf) => &elf.bytes,
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
