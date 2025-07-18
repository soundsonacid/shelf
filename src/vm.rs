use anyhow::Result;

use crate::instruction::ixn::{DecodedIxn, IXN_SIZE, Ixn};
use crate::parser::Elf;
use crate::parser::constants::*;

pub fn execute(elf: Elf) -> Result<()> {
    // load .text section
    // load .rodata section
    // load .bss.stack section
    // load .bss.heap section
    let text_region = Region::from_section(&elf, TEXT);
    let rodata_region = Region::from_section(&elf, RODATA);
    let bss_stack_region = Region::from_section(&elf, BSS_STACK);
    let bss_heap_region = Region::from_section(&elf, BSS_HEAP);

    let memory = Memory::new(vec![text_region, rodata_region, bss_stack_region, bss_heap_region]);
    dbg!(&memory);

    let vm = Vm::new(elf, memory);
    vm.load_and_execute();

    Ok(())
}

#[derive(Debug)]
struct Memory {
    regions: Vec<Region>,
}

impl Memory {
    fn new(regions: Vec<Region>) -> Self {
        Self { regions }
    }

    fn read_bytes_at(&self, addr: usize, len: usize) -> Option<&[u8]> {
        let region = self.find_region_for_addr(addr).unwrap();
        let relative_addr = addr.checked_sub(region.addr_start).unwrap();
        let range = relative_addr..relative_addr + len;
        region.data.get(range)
    }

    fn find_region_for_addr(&self, addr: usize) -> Option<&Region> {
        self.regions
            .iter()
            .find(|r| (r.addr_start..r.addr_start + r.len).contains(&addr))
    }
}

struct Region {
    name: String,
    addr_start: usize,
    len: usize,
    data: Vec<u8>,
}

impl std::fmt::Debug for Region {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Region")
            .field("name", &self.name)
            .field("addr_start", &self.addr_start)
            .field("len", &self.len)
            .finish()
    }
}

impl Region {
    fn from_section(elf: &Elf, section_name: &str) -> Self {
        dbg!(&section_name);
        let section = elf.named_section_headers.get(section_name).unwrap();
        // get the section out of the elf at sh_offset
        let off = section.sh_offset as usize;
        let len = section.sh_size as usize;
        let data = if section.sh_type == SHT_NOBITS {
            Vec::with_capacity(len)
        } else {
            let range = off..off + len;
            elf.bytes.get(range).unwrap().to_owned()
        };

        // when being loaded / executed, the section should be "placed" at sh_addr
        Self { name: section_name.to_owned(), addr_start: section.sh_addr as usize, len, data }
    }
}

struct Vm {
    elf: Elf,
    memory: Memory,
    pc: u64,
    regs: [u64; 11],
}

impl Vm {
    fn new(elf: Elf, memory: Memory) -> Self {
        Self { elf, pc: 0, regs: [0; 11], memory }
    }

    fn load_and_execute(mut self) {
        let entrypoint = self.elf.named_symbols.get("entrypoint").unwrap();
        let text_section_size = self.elf.named_section_headers.get(TEXT).unwrap().sh_size;
        dbg!(&entrypoint);

        // set the program counter to the entrypoint's first instruction
        self.pc = entrypoint.st_value;

        loop {
            self.load_and_execute_next_instruction();
            self.pc += 8;
            if self.pc >= text_section_size {
                break;
            }
        }
    }

    fn load_and_execute_next_instruction(&mut self) {
        if let Some(ixn) = self.read_next_instruction() {
            let decoded_ixn = ixn.decode_ixn();
            self.execute_ixn(decoded_ixn)
        }
    }

    fn read_next_instruction(&mut self) -> Option<Ixn> {
        let ixn_bytes = self
            .memory
            .read_bytes_at(self.pc as usize, IXN_SIZE)?
            .try_into()
            .ok()?;
        Some(Ixn(ixn_bytes))
    }

    fn execute_ixn(&mut self, ixn: DecodedIxn) {
        let executable_ixn = ixn.to_instruction();
        dbg!(executable_ixn);
    }
}
