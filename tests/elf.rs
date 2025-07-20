use std::fs;

use anyhow::Result;
use shelf::config::{Config, SBPFVersion};
use shelf::context::{ExecutionContext, Syscall, hash_symbol_name};
use shelf::parser::Elf;
use shelf::syscall;
use shelf::vm::Vm;

fn test(path: &'static str, expected_result: u64, config: Option<Config>, syscalls: Option<Vec<(&str, Syscall)>>) -> Result<()> {
    let obj = fs::read(path)?;
    let elf = Elf::parse(&obj)?;
    let mut ctx = ExecutionContext::new_from_elf(elf, config);

    if let Some(syscalls) = syscalls {
        syscalls.iter().for_each(|(name, syscall)| {
            ctx.register_syscall(hash_symbol_name(name.as_bytes()), *syscall);
        })
    }
    let vm = Vm::new(ctx);
    let result = vm.load_and_execute()?;
    println!("{path} result: {result}");
    assert_eq!(result, expected_result);

    Ok(())
}

#[test]
fn test_interpret() -> Result<()> {
    test("tests/elfs/rodata_section.so", 42, None, None)?;
    test("tests/elfs/reloc_64_64.so", 0, None, None)?;
    test("tests/elfs/strict_header.so", 42, None, None)?;
    test("tests/elfs/struct_func_pointer.so", 0x102030405060708, None, None)?;
    Ok(())
}

#[test]
fn test_syscall() -> Result<()> {
    // test("tests/elfs/syscall_static.so", 0, None, Some(vec![("log",
    // syscall::syscall_string)]))?;

    let config = Config { enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V0 };
    test("tests/elfs/syscall_reloc_64_32_sbpfv0.so", 0, Some(config), Some(vec![("log", syscall::syscall_string)]))?;
    Ok(())
}
