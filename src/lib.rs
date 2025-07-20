#![allow(unreachable_patterns, clippy::match_overlapping_arm)]

pub mod config;
pub mod context;
pub mod instruction;
pub mod memory;
pub mod parser;
pub mod program;
pub mod vm;

// pub fn interpret_elf(elf: Elf, config: Config) -> anyhow::Result<u64> {
//     // load all present sections
// let regions = elf
//     .section_names()
//     .iter()
//     .filter_map(|region| Region::from_section(&elf, region))
//     .collect::<Vec<_>>();

//     let memory = Memory::new(regions);
//     // let
//     // let vm = Vm::new(elf, memory, config);
//     // vm.load_and_execute()

//     Ok(0)
// }
