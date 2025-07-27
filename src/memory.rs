use anyhow::Result;

use crate::instruction::constants::MM_STACK_START;
use crate::parser::Elf;
use crate::parser::constants::*;

#[derive(Debug)]
pub struct Memory {
    regions: Vec<Region>,
}

impl Memory {
    pub fn new(regions: Vec<Region>) -> Self {
        Self { regions }
    }

    pub fn read_bytes_at(&self, addr: usize, len: usize) -> Option<&[u8]> {
        let region = self.find_region_for_addr(addr).unwrap();
        let relative_addr = addr.checked_sub(region.addr_start).unwrap();
        let range = relative_addr..relative_addr + len;
        region.data.get(range)
    }

    pub fn find_region_for_addr(&self, addr: usize) -> Option<&Region> {
        self.regions
            .iter()
            .find(|r| (r.addr_start..r.addr_start + r.len).contains(&addr))
    }

    pub fn find_region_for_addr_mut(&mut self, addr: usize) -> Option<&mut Region> {
        self.regions
            .iter_mut()
            .find(|r| (r.addr_start..r.addr_start + r.len).contains(&addr))
    }

    pub fn stack(&self) -> Option<&Region> {
        self.regions.iter().find(|r| r.name == BSS_STACK)
    }

    pub fn stack_mut(&mut self) -> Option<&mut Region> {
        self.regions.iter_mut().find(|r| r.name == BSS_STACK)
    }

    pub fn check_frame_pointer_bounds(&self, frame_pointer: u64) {
        let stack_len = self.stack().unwrap().len as u64;
        if !(MM_STACK_START <= frame_pointer || frame_pointer >= MM_STACK_START + stack_len) {
            panic!("Stack overflow")
        }
    }

    pub fn translate_vm_addr(&self, vm_addr: usize) -> usize {
        let containing_region = self
            .regions
            .iter()
            .find(|r| r.contains_vm_addr(vm_addr))
            .unwrap();

        vm_addr - containing_region.addr_start
    }
}

pub struct Region {
    pub name: String,
    pub addr_start: usize,
    pub len: usize,
    pub addr_end: usize,
    pub data: Vec<u8>,
}

impl std::fmt::Debug for Region {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Region")
            .field("name", &self.name)
            .field("addr_start", &self.addr_start)
            .field("addr_end", &self.addr_end)
            .field("len", &self.len)
            .finish()
    }
}

impl Region {
    pub fn from_section(elf: &Elf, section_name: &str) -> Option<Self> {
        let section = elf.named_section_headers.get(section_name)?;
        if !section.should_alloc() {
            return None;
        }
        // get the section out of the elf at sh_offset
        let off = section.sh_offset as usize;
        let len = section.sh_size as usize;
        let data = if section.sh_type == SHT_NOBITS {
            vec![0; len]
        } else {
            let range = off..off + len;
            elf.bytes.get(range)?.to_owned()
        };

        let addr_start = section.sh_addr as usize;
        let addr_end = addr_start + len;

        // when being loaded / executed, the section should be "placed" at sh_addr
        Some(Self { name: section_name.to_owned(), addr_start, len, addr_end, data })
    }

    pub fn write_u64(&mut self, addr_start: usize, val: u64) {
        let relative_addr = addr_start - self.addr_start;
        self.data[relative_addr..relative_addr + 8].copy_from_slice(&u64::to_le_bytes(val));
    }

    pub fn read_u64(&self, addr_start: usize) -> Result<u64> {
        let relative_addr = addr_start - self.addr_start;
        Ok(u64::from_le_bytes(self.data[relative_addr..relative_addr + 8].try_into()?))
    }

    pub fn read_bytes(&self, addr_start: usize, len: usize) -> &[u8] {
        let relative_addr = addr_start - self.addr_start;
        &self.data[relative_addr..relative_addr + len]
    }

    pub fn contains_vm_addr(&self, vm_addr: usize) -> bool {
        dbg!(&self.name);
        dbg!(&self.addr_start);
        dbg!(&self.addr_end);
        dbg!(self.addr_start <= vm_addr);
        dbg!(vm_addr <= self.addr_end);
        self.addr_start <= vm_addr && vm_addr <= self.addr_end
    }
}
