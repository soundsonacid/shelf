use std::fs;

use anyhow::Result;
use shelf::parser::Elf;
use shelf::vm::execute;

#[test]
fn test_elf() -> Result<()> {
    let obj = fs::read("tests/elfs/rodata_section.so")?;
    let elf = Elf::parse(&obj)?;

    dbg!(&elf.program_header_table);
    dbg!(&elf.named_section_headers);
    dbg!(&elf.named_symbols);
    dbg!(&elf.named_dynsym);

    execute(elf)?;

    Ok(())
}
