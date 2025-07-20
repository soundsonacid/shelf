use anyhow::Result;

use crate::config::SBPFVersion;
use crate::context::ExecutionContext;
use crate::instruction::constants::{FRAME_PTR_REG, IXN_SIZE, IXN_SIZE_U64};
use crate::instruction::ixn::{DecodedIxn, ExecutableIxn, Ixn};

const REGISTER_SIZE: usize = std::mem::size_of::<usize>();
const POINTER_SIZE: usize = std::mem::size_of::<usize>();

pub struct Vm {
    pub ctx: ExecutionContext,
    pc: u64, // sbpf expresses this as r11 / regs[12]
    regs: [u64; 11],
    state: State,
}

#[derive(Default, Debug)]
enum State {
    #[default]
    Continue,
    Break,
}

impl State {
    fn should_continue(&self) -> bool {
        matches!(self, State::Continue)
    }
}

impl Vm {
    pub fn new(ctx: ExecutionContext) -> Self {
        // dbg!(&ctx.memory);
        let mut regs = [0; 11];
        // set up frame pointer
        regs[FRAME_PTR_REG] = 0x200000000 + 4096;
        Self { ctx, pc: 0, regs, state: State::Continue }
    }

    pub fn load_and_execute(mut self) -> Result<u64> {
        // set the program counter to the address of the entrypoint's first instruction
        self.pc = self.ctx.program_entrypoint();

        while self.state.should_continue() {
            let ixn = self.load_next_instruction().expect("Next ixn");
            self.pc += IXN_SIZE_U64;
            let decoded_ixn = ixn.decode_ixn();
            self.execute_ixn(decoded_ixn)?;
        }

        Ok(self.regs[0])
    }

    fn load_next_instruction(&mut self) -> Option<Ixn> {
        let ixn_bytes = self
            .ctx
            .memory
            .read_bytes_at(self.pc as usize, IXN_SIZE)?
            .try_into()
            .ok()?;
        Some(Ixn(ixn_bytes))
    }

    fn execute_ixn(&mut self, ixn: DecodedIxn) -> Result<()> {
        let executable_ixn = ixn.to_instruction(&self.ctx.config);
        dbg!(&executable_ixn);
        // dbg!(&self.pc);

        match executable_ixn {
            ExecutableIxn::Syscall { imm } => {
                let syscall = self.ctx.syscall(imm as u32).unwrap();
                syscall(self, self.regs[1], self.regs[2], self.regs[3], self.regs[4], self.regs[5])
            }
            ExecutableIxn::Mov32Imm { dst, imm } => {
                self.regs[dst as usize] = imm as u32 as u64;
            }
            ExecutableIxn::Mov64Imm { dst, imm } => {
                self.regs[dst as usize] = imm as u64;
            }
            ExecutableIxn::HorImm { dst, imm } => {
                self.regs[dst as usize] |= (imm as u64).wrapping_shl(32);
            }
            ExecutableIxn::LoadDword { dst, src, off } => {
                let addr = self.regs[src as usize] as usize + off as usize;
                let data = self.ctx.memory.read_bytes_at(addr, 8).unwrap();
                let data = u64::from_le_bytes(data.try_into().unwrap());
                self.regs[dst as usize] = data;
            }
            ExecutableIxn::LoadDwordImm { dst, mut imm } => {
                // load the i32 that replaces the next instruction
                let msh_off = (self.pc + IXN_SIZE_U64) as usize;
                let bytes = &self.ctx.program_bytes()[msh_off..];
                let msh = i32::from_le_bytes(bytes[msh_off..msh_off + 4].try_into()?);
                // combine the imm from the ixn & what we just loaded
                imm = ((imm as u64 & 0xFFFFFFFF) | ((msh as u64).wrapping_shr(32))) as i32;
                self.regs[dst as usize] = imm as u64;
                // bump pc again to skip the second half of the loaded value
                self.pc += IXN_SIZE_U64;
            }
            ExecutableIxn::Call { imm } => {
                // if we are on an sbpf version that does not support static syscalls,
                // and we have a syscall for this function's key (imm) in our syscall registry,
                // invoke the syscall
                if self.ctx.config.below_sbpf_version(SBPFVersion::V3)
                    && let Some(syscall) = self.ctx.syscall(imm as u32)
                {
                    syscall(self, self.regs[1], self.regs[2], self.regs[3], self.regs[4], self.regs[5])
                } else {
                    // otherwise, this is a regular function call, so push a stack frame & jump
                    self.push_stack();
                    let mut temp_pc = self.pc as i32;
                    let jump = imm * IXN_SIZE as i32;
                    temp_pc += jump;
                    self.pc = temp_pc as u64;
                }
            }
            ExecutableIxn::Return => {
                self.pop_stack()?;
            }
            ExecutableIxn::Exit => self.state = State::Break,
            _ => {}
        }

        Ok(())
    }

    fn push_stack(&mut self) {
        let frame_pointer = self.regs[FRAME_PTR_REG];
        self.ctx.memory.check_frame_pointer_bounds(frame_pointer);
        let stack = self.ctx.memory.stack_mut().expect("Stack");
        let mut frame_pointer = (frame_pointer as usize) - (POINTER_SIZE + REGISTER_SIZE + REGISTER_SIZE + REGISTER_SIZE + REGISTER_SIZE);
        self.regs[FRAME_PTR_REG] = frame_pointer as u64; // set frame pointer to new value before mutating
        stack.write_u64(frame_pointer, self.pc); // save pc
        frame_pointer += POINTER_SIZE;
        stack.write_u64(frame_pointer, self.regs[6]); // save r6
        frame_pointer += REGISTER_SIZE;
        stack.write_u64(frame_pointer, self.regs[7]); // save r7
        frame_pointer += REGISTER_SIZE;
        stack.write_u64(frame_pointer, self.regs[8]); // save r8
        frame_pointer += REGISTER_SIZE;
        stack.write_u64(frame_pointer, self.regs[9]); // save r9
    }

    fn pop_stack(&mut self) -> Result<()> {
        let frame_pointer = self.regs[FRAME_PTR_REG];
        self.ctx.memory.check_frame_pointer_bounds(frame_pointer);
        let mut frame_pointer = frame_pointer as usize;
        let stack = self.ctx.memory.stack().expect("Stack");

        if frame_pointer == stack.addr_end {
            // we have reached the top-level return statement and should exit the program
            self.state = State::Break;
            return Ok(());
        }

        let pc = stack.read_u64(frame_pointer)?; // read pc
        self.pc = pc;
        frame_pointer += POINTER_SIZE;
        let r6 = stack.read_u64(frame_pointer)?; // read r6
        self.regs[6] = r6;
        frame_pointer += POINTER_SIZE;
        let r7 = stack.read_u64(frame_pointer)?; // read r7
        self.regs[7] = r7;
        frame_pointer += POINTER_SIZE;
        let r8 = stack.read_u64(frame_pointer)?; // read r8
        self.regs[8] = r8;
        frame_pointer += POINTER_SIZE;
        let r9 = stack.read_u64(frame_pointer)?; // read r9
        self.regs[9] = r9;
        frame_pointer += POINTER_SIZE;
        self.regs[10] = frame_pointer as u64; // set frame pointer to new value after mutating
        Ok(())
    }
}
