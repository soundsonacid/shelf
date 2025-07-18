use std::fs;

use anyhow::Result;
use shelf::parser::Elf;
use shelf::vm::execute;

#[test]
fn test_elf() -> Result<()> {
    let obj = fs::read("tests/elfs/rodata_section.so")?;
    let elf = Elf::parse(&obj)?;

    let result = execute(elf)?;
    println!("ro_data_section.so result: {result}");
    assert_eq!(result, 42);

    Ok(())
}
