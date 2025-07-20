use crate::parser::Elf;

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
}
