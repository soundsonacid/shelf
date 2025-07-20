use anyhow::Result;

use crate::context::ExecutionContext;
use crate::instruction::ixn::{DecodedIxn, ExecutableIxn, IXN_SIZE, Ixn};

const REGISTER_SIZE: usize = std::mem::size_of::<usize>();
const POINTER_SIZE: usize = std::mem::size_of::<usize>();

pub struct Vm {
    pub ctx: ExecutionContext,
    pc: u64,
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
        let mut regs = [0; 11];
        // set up frame pointer
        regs[10] = 0x200000000 + 4096;
        Self { ctx, pc: 0, regs, state: State::Continue }
    }

    pub fn load_and_execute(mut self) -> Result<u64> {
        // set the program counter to the address of the entrypoint's first instruction
        self.pc = self.ctx.program.entrypoint();

        while self.state.should_continue() {
            let ixn = self.load_next_instruction().expect("Next ixn");
            self.pc += 8;
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

        match executable_ixn {
            ExecutableIxn::Syscall { imm } => {
                let syscall = self.ctx.syscall(imm as u32);
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
            ExecutableIxn::Call { imm } => {
                self.push_stack();
                let mut temp_pc = self.pc as i32;
                let jump = imm * IXN_SIZE as i32;
                temp_pc += jump;
                self.pc = temp_pc as u64;
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
        let frame_pointer = self.regs[10] as usize;
        let stack = self
            .ctx
            .memory
            .find_region_for_addr_mut(frame_pointer)
            .expect("Valid stack address");

        let mut frame_pointer = frame_pointer - (POINTER_SIZE + REGISTER_SIZE + REGISTER_SIZE + REGISTER_SIZE + REGISTER_SIZE);

        // set frame pointer to new value before mutating
        self.regs[10] = frame_pointer as u64;

        // save pc
        stack.write_u64(frame_pointer, self.pc);
        frame_pointer += POINTER_SIZE;

        // save r6
        stack.write_u64(frame_pointer, self.regs[6]);
        frame_pointer += REGISTER_SIZE;

        // save r7
        stack.write_u64(frame_pointer, self.regs[7]);
        frame_pointer += REGISTER_SIZE;

        // save r8
        stack.write_u64(frame_pointer, self.regs[8]);
        frame_pointer += REGISTER_SIZE;

        // save r9
        stack.write_u64(frame_pointer, self.regs[9]);
    }

    fn pop_stack(&mut self) -> Result<()> {
        let mut frame_pointer = self.regs[10] as usize;
        let stack = self
            .ctx
            .memory
            .find_region_for_addr(frame_pointer)
            .expect("Valid stack address");

        // we have reached the top-level return statement and should exit the program
        if frame_pointer == stack.addr_end {
            self.state = State::Break;
            return Ok(());
        }

        // read pc
        let pc = stack.read_u64(frame_pointer)?;
        self.pc = pc;
        frame_pointer += POINTER_SIZE;

        // read r6
        let r6 = stack.read_u64(frame_pointer)?;
        self.regs[6] = r6;
        frame_pointer += POINTER_SIZE;

        // read r7
        let r7 = stack.read_u64(frame_pointer)?;
        self.regs[7] = r7;
        frame_pointer += POINTER_SIZE;

        // read r8
        let r8 = stack.read_u64(frame_pointer)?;
        self.regs[8] = r8;
        frame_pointer += POINTER_SIZE;

        // read r9
        let r9 = stack.read_u64(frame_pointer)?;
        self.regs[9] = r9;
        frame_pointer += POINTER_SIZE;

        // set frame pointer to new value after mutating
        self.regs[10] = frame_pointer as u64;
        Ok(())
    }
}
