use std::fs;

use anyhow::Result;
use shelf::config::Config;
use shelf::execute;
use shelf::parser::Elf;

fn test(path: &'static str, expected_result: u64) -> Result<()> {
    let obj = fs::read(path)?;
    let elf = Elf::parse(&obj)?;

    let result = execute(elf, Config::default())?;
    println!("{path} result: {result}");
    assert_eq!(result, expected_result);

    Ok(())
}
#[test]
fn test_rodata_section() -> Result<()> {
    test("tests/elfs/rodata_section.so", 42)
}

#[test]
fn test_reloc_64_64() -> Result<()> {
    test("tests/elfs/reloc_64_64.so", 0)
}

#[test]
fn test_strict_header() -> Result<()> {
    test("tests/elfs/strict_header.so", 42)
}

#[test]
fn test_struct_func_pointer() -> Result<()> {
    test("tests/elfs/struct_func_pointer.so", 0x102030405060708)
}

#[test]
fn test_syscall() -> Result<()> {
    test("tests/elfs/syscall_static.so", 0)
}
