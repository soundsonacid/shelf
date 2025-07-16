use std::fs;
use shelf::parser::Elf;
use anyhow::Result;

#[test]
fn test_elf() -> Result<()> {
    let obj = fs::read("tests/elfs/relative_call.so")?;
    let elf = Elf::parse(&obj)?;

    Ok(())
}
