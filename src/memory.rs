use std::ops::Range;

use anyhow::Result;

use crate::config::Config;
use crate::instruction::constants::{MM_REGION_SIZE, MM_STACK_START};
use crate::parser::Elf;
use crate::parser::constants::*;

pub enum MemoryMapping {
    Identity(Memory),
    Aligned(AlignedMemory),
}

impl MemoryMapping {
    pub fn new(config: Config, regions: Vec<Region>) -> Self {
        if !config.enable_address_translation {
            return MemoryMapping::Identity(Memory::new(regions));
        }

        if config.aligned_memory_mapping {
            MemoryMapping::Aligned(AlignedMemory::new(regions))
        } else {
            panic!("Unaligned memory is not supported!")
        }
    }

    pub fn read(&self, range: Range<usize>) -> Option<&'static /* for todo typecheck */ [u8]> {
        todo!()
    }

    pub fn write(&mut self, range: Range<usize>, bytes: &[u8]) {}

    pub fn bytecode_start_host_addr(&self) -> usize {
        self.regions()
            .iter()
            .find(|r| r.name == TEXT)
            .map(|r| r.addr_start)
            .unwrap()
    }

    pub fn stack(&self) -> Option<&Region> {
        self.regions().iter().find(|r| r.name == BSS_STACK)
    }

    pub fn stack_mut(&mut self) -> Option<&mut Region> {
        self.regions_mut().iter_mut().find(|r| r.name == BSS_STACK)
    }

    pub fn check_frame_pointer_bounds(&self, frame_pointer: u64) {
        let stack_len = self.stack().unwrap().len as u64;
        if !(MM_STACK_START <= frame_pointer || frame_pointer >= MM_STACK_START + stack_len) {
            panic!("Stack overflow")
        }
    }

    fn regions(&self) -> &[Region] {
        match self {
            MemoryMapping::Aligned(m) => &m.regions,
            MemoryMapping::Identity(m) => &m.regions,
        }
    }

    fn regions_mut(&mut self) -> &mut [Region] {
        match self {
            MemoryMapping::Aligned(m) => &mut m.regions,
            MemoryMapping::Identity(m) => &mut m.regions,
        }
    }
}

#[derive(Debug)]
pub struct Memory {
    regions: Vec<Region>,
}

impl Memory {
    pub fn new(regions: Vec<Region>) -> Self {
        Self { regions }
    }

    pub fn check_nonoverlapping(&self) -> Result<()> {
        let mut sorted_regions: Vec<_> = self.regions.iter().enumerate().collect();
        sorted_regions.sort_by_key(|(_, region)| region.vm_addr);

        for window in sorted_regions.windows(2) {
            let (_, region1) = window[0];
            let (_, region2) = window[1];

            let region1_end = region1.vm_addr + region1.len;

            if region1_end > region2.vm_addr {
                return Err(anyhow::anyhow!(
                    "Memory regions overlap: '{}' at VM address {:#x}-{:#x} overlaps with '{}' at VM address {:#x}-{:#x}",
                    region1.name,
                    region1.vm_addr,
                    region1_end,
                    region2.name,
                    region2.vm_addr,
                    region2.vm_addr + region2.len
                ));
            }
        }

        Ok(())
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

pub struct AlignedMemory {
    regions: Vec<Region>,
}

impl AlignedMemory {
    pub fn new(regions: Vec<Region>) -> Self {
        todo!()
    }
}

#[derive(Clone)]
pub struct Region {
    pub name: String,
    pub addr_start: usize,
    pub vm_addr: usize,
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
    pub fn from_section(elf: &Elf, section_name: &str, i: usize) -> Option<Self> {
        let section = elf.section_header_table[i];
        dbg!(&section_name);
        if !section.should_alloc() {
            dbg!("NOALLOC");
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
        let vm_addr = MM_REGION_SIZE as usize * i;
        // when being loaded / executed, the section should be "placed" at sh_addr
        Some(Self {
            name: section_name.to_owned(),
            addr_start,
            vm_addr,
            len,
            addr_end,
            data,
        })
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
        self.vm_addr <= vm_addr && vm_addr <= self.vm_addr + self.len
    }
}
