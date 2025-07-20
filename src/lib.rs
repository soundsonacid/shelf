#![allow(unreachable_patterns, clippy::match_overlapping_arm)]

use crate::config::Config;
use crate::memory::{Memory, Region};
use crate::parser::Elf;
use crate::vm::Vm;
// shelf
pub mod config;
pub mod instruction;
pub mod memory;
pub mod parser;
pub mod vm;

pub fn execute(elf: Elf, config: Config) -> anyhow::Result<u64> {
    // load all present sections
    let regions = elf
        .section_names()
        .iter()
        .filter_map(|region| Region::from_section(&elf, region))
        .collect::<Vec<_>>();

    let memory = Memory::new(regions);
    let vm = Vm::new(elf, memory, config);
    vm.load_and_execute()
}
