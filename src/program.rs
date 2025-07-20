use crate::instruction::ixn::BpfRelocationType;
use crate::parser::Elf;

#[allow(clippy::large_enum_variant)]
pub enum ExecutableProgram {
    Elf(Elf),
    Jit, // todo...
}

impl ExecutableProgram {
    pub fn entrypoint(&self) -> u64 {
        match self {
            ExecutableProgram::Elf(elf) => {
                elf.get_symbol("entrypoint")
                    .expect("Entrypoint must be present!")
                    .st_value
            }
            ExecutableProgram::Jit => unimplemented!(),
        }
    }

    pub fn fixup(&self) {
        match self {
            ExecutableProgram::Elf(elf) => {
                if let Some(relocs) = &elf.dynamic_relocations {
                    for reloc in relocs {
                        let addr = reloc.r_offset;
                        let sym = reloc.r_info.wrapping_shr(32);
                        let reloc_type = (reloc.r_info & 0xFFFFFFFF) as u32;
                        dbg!(&reloc);
                        dbg!(addr);
                        dbg!(sym);
                        match reloc_type {
                            _ if reloc_type == BpfRelocationType::R_Bpf_None as u32 => {}
                            _ if reloc_type == BpfRelocationType::R_Bpf_64_64 as u32 => {}
                            _ if reloc_type == BpfRelocationType::R_Bpf_64_Relative as u32 => {
                                dbg!("R_Bpf_64_Relative");
                            }
                            _ if reloc_type == BpfRelocationType::R_Bpf_64_32 as u32 => {
                                dbg!("R_Bpf_64_32");
                            }
                            _ => panic!("Unknown relocation type"),
                        }
                    }
                }
            }
            ExecutableProgram::Jit => unimplemented!(),
        }
    }
}
