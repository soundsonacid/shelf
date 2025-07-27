use super::constants::*;
use crate::config::{Config, SBPFVersion};

#[derive(Debug)]
pub struct Ixn(pub [u8; IXN_SIZE]);

// msb                                                        lsb
// +------------------------+----------------+----+----+--------+
// |immediate               |offset          |src |dst |opcode  |
// +------------------------+----------------+----+----+--------+

// From least significant to most significant bit:
//   8 bit opcode
//   4 bit destination register (dst)
//   4 bit source register (src)
//   16 bit offset
//   32 bit immediate (imm)

impl Ixn {
    pub fn decode_ixn(self) -> DecodedIxn {
        let ixn = self.0;
        DecodedIxn {
            opcode: ixn[0],
            dst: ixn[1] & 0x0F,
            src: (ixn[1] >> 4) & 0x0F,
            off: i16::from_le_bytes(ixn[2..4].try_into().unwrap()),
            imm: i32::from_le_bytes(ixn[4..8].try_into().unwrap()),
        }
    }
}

#[derive(Debug)]
pub struct DecodedIxn {
    pub opcode: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExecutableIxn {
    // Load/Store operations
    LoadByte { dst: u8, src: u8, off: i16 },  // ldxb dst, [src + off]
    LoadHalf { dst: u8, src: u8, off: i16 },  // ldxh dst, [src + off]
    LoadWord { dst: u8, src: u8, off: i16 },  // ldxw dst, [src + off]
    LoadDword { dst: u8, src: u8, off: i16 }, // ldxdw dst, [src + off]
    LoadDwordImm { dst: u8, imm: i32 },       // lddw dst, imm

    StoreByte { dst: u8, src: u8, off: i16 },  // stxb [dst + off], src
    StoreHalf { dst: u8, src: u8, off: i16 },  // stxh [dst + off], src
    StoreWord { dst: u8, src: u8, off: i16 },  // stxw [dst + off], src
    StoreDword { dst: u8, src: u8, off: i16 }, // stxdw [dst + off], src

    StoreByteImm { dst: u8, off: i16, imm: i32 },  // stb [dst + off], imm
    StoreHalfImm { dst: u8, off: i16, imm: i32 },  // sth [dst + off], imm
    StoreWordImm { dst: u8, off: i16, imm: i32 },  // stw [dst + off], imm
    StoreDwordImm { dst: u8, off: i16, imm: i32 }, // stdw [dst + off], imm

    // 32-bit ALU operations
    Add32 { dst: u8, src: u8 },      // add32 dst, src
    Add32Imm { dst: u8, imm: i32 },  // add32 dst, imm
    Sub32 { dst: u8, src: u8 },      // sub32 dst, src
    Sub32Imm { dst: u8, imm: i32 },  // sub32 dst, imm
    Mul32 { dst: u8, src: u8 },      // mul32 dst, src
    Mul32Imm { dst: u8, imm: i32 },  // mul32 dst, imm
    Div32 { dst: u8, src: u8 },      // div32 dst, src
    Div32Imm { dst: u8, imm: i32 },  // div32 dst, imm
    Or32 { dst: u8, src: u8 },       // or32 dst, src
    Or32Imm { dst: u8, imm: i32 },   // or32 dst, imm
    And32 { dst: u8, src: u8 },      // and32 dst, src
    And32Imm { dst: u8, imm: i32 },  // and32 dst, imm
    Lsh32 { dst: u8, src: u8 },      // lsh32 dst, src
    Lsh32Imm { dst: u8, imm: i32 },  // lsh32 dst, imm
    Rsh32 { dst: u8, src: u8 },      // rsh32 dst, src
    Rsh32Imm { dst: u8, imm: i32 },  // rsh32 dst, imm
    Neg32 { dst: u8 },               // neg32 dst
    Mod32 { dst: u8, src: u8 },      // mod32 dst, src
    Mod32Imm { dst: u8, imm: i32 },  // mod32 dst, imm
    Xor32 { dst: u8, src: u8 },      // xor32 dst, src
    Xor32Imm { dst: u8, imm: i32 },  // xor32 dst, imm
    Mov32 { dst: u8, src: u8 },      // mov32 dst, src
    Mov32Imm { dst: u8, imm: i32 },  // mov32 dst, imm
    Arsh32 { dst: u8, src: u8 },     // arsh32 dst, src
    Arsh32Imm { dst: u8, imm: i32 }, // arsh32 dst, imm

    // 64-bit ALU operations
    Add64 { dst: u8, src: u8 },      // add64 dst, src
    Add64Imm { dst: u8, imm: i32 },  // add64 dst, imm
    Sub64 { dst: u8, src: u8 },      // sub64 dst, src
    Sub64Imm { dst: u8, imm: i32 },  // sub64 dst, imm
    Mul64 { dst: u8, src: u8 },      // mul64 dst, src
    Mul64Imm { dst: u8, imm: i32 },  // mul64 dst, imm
    Div64 { dst: u8, src: u8 },      // div64 dst, src
    Div64Imm { dst: u8, imm: i32 },  // div64 dst, imm
    Or64 { dst: u8, src: u8 },       // or64 dst, src
    Or64Imm { dst: u8, imm: i32 },   // or64 dst, imm
    And64 { dst: u8, src: u8 },      // and64 dst, src
    And64Imm { dst: u8, imm: i32 },  // and64 dst, imm
    Lsh64 { dst: u8, src: u8 },      // lsh64 dst, src
    Lsh64Imm { dst: u8, imm: i32 },  // lsh64 dst, imm
    Rsh64 { dst: u8, src: u8 },      // rsh64 dst, src
    Rsh64Imm { dst: u8, imm: i32 },  // rsh64 dst, imm
    Neg64 { dst: u8 },               // neg64 dst
    Mod64 { dst: u8, src: u8 },      // mod64 dst, src
    Mod64Imm { dst: u8, imm: i32 },  // mod64 dst, imm
    Xor64 { dst: u8, src: u8 },      // xor64 dst, src
    Xor64Imm { dst: u8, imm: i32 },  // xor64 dst, imm
    Mov64 { dst: u8, src: u8 },      // mov64 dst, src
    Mov64Imm { dst: u8, imm: i32 },  // mov64 dst, imm
    Arsh64 { dst: u8, src: u8 },     // arsh64 dst, src
    Arsh64Imm { dst: u8, imm: i32 }, // arsh64 dst, imm
    HorImm { dst: u8, imm: i32 },    // hor64 dst, imm (dst |= imm << 32)

    // Jump operations
    Ja { off: i16 },                         // ja +off
    Jeq { dst: u8, src: u8, off: i16 },      // jeq dst, src, +off
    JeqImm { dst: u8, imm: i32, off: i16 },  // jeq dst, imm, +off
    Jgt { dst: u8, src: u8, off: i16 },      // jgt dst, src, +off
    JgtImm { dst: u8, imm: i32, off: i16 },  // jgt dst, imm, +off
    Jge { dst: u8, src: u8, off: i16 },      // jge dst, src, +off
    JgeImm { dst: u8, imm: i32, off: i16 },  // jge dst, imm, +off
    Jlt { dst: u8, src: u8, off: i16 },      // jlt dst, src, +off
    JltImm { dst: u8, imm: i32, off: i16 },  // jlt dst, imm, +off
    Jle { dst: u8, src: u8, off: i16 },      // jle dst, src, +off
    JleImm { dst: u8, imm: i32, off: i16 },  // jle dst, imm, +off
    Jset { dst: u8, src: u8, off: i16 },     // jset dst, src, +off
    JsetImm { dst: u8, imm: i32, off: i16 }, // jset dst, imm, +off
    Jne { dst: u8, src: u8, off: i16 },      // jne dst, src, +off
    JneImm { dst: u8, imm: i32, off: i16 },  // jne dst, imm, +off
    Jsgt { dst: u8, src: u8, off: i16 },     // jsgt dst, src, +off (signed)
    JsgtImm { dst: u8, imm: i32, off: i16 }, // jsgt dst, imm, +off (signed)
    Jsge { dst: u8, src: u8, off: i16 },     // jsge dst, src, +off (signed)
    JsgeImm { dst: u8, imm: i32, off: i16 }, // jsge dst, imm, +off (signed)
    Jslt { dst: u8, src: u8, off: i16 },     // jslt dst, src, +off (signed)
    JsltImm { dst: u8, imm: i32, off: i16 }, // jslt dst, imm, +off (signed)
    Jsle { dst: u8, src: u8, off: i16 },     // jsle dst, src, +off (signed)
    JsleImm { dst: u8, imm: i32, off: i16 }, // jsle dst, imm, +off (signed)

    // Special operations
    Call { imm: i32 },            // call imm (helper function)
    CallReg { dst: u8, src: u8 }, // tail call
    Exit,                         // exit (return r0)
    Return,                       // return (SBPFv3)
    Syscall { imm: i32 },         // syscall imm (SBPFv3)

    // Endianness operations
    Le { dst: u8, imm: i32 }, // dst = htole<imm>(dst)
    Be { dst: u8, imm: i32 }, // dst = htobe<imm>(dst)

    // Product/Quotient/Remainder operations
    LMul32 { dst: u8, src: u8 }, // lower 32 bits of multiplication
    LMul32Imm { dst: u8, imm: i32 },
    UDiv32 { dst: u8, src: u8 }, // unsigned division
    UDiv32Imm { dst: u8, imm: i32 },
    URem32 { dst: u8, src: u8 }, // unsigned remainder
    URem32Imm { dst: u8, imm: i32 },
    SDiv32 { dst: u8, src: u8 }, // signed division
    SDiv32Imm { dst: u8, imm: i32 },
    SRem32 { dst: u8, src: u8 }, // signed remainder
    SRem32Imm { dst: u8, imm: i32 },

    LMul64 { dst: u8, src: u8 }, // lower 64 bits of multiplication
    LMul64Imm { dst: u8, imm: i32 },
    UHMul64 { dst: u8, src: u8 }, // upper 64 bits of multiplication
    UHMul64Imm { dst: u8, imm: i32 },
    UDiv64 { dst: u8, src: u8 },
    UDiv64Imm { dst: u8, imm: i32 },
    URem64 { dst: u8, src: u8 },
    URem64Imm { dst: u8, imm: i32 },
    SHMul64 { dst: u8, src: u8 }, // signed high multiplication
    SHMul64Imm { dst: u8, imm: i32 },
    SDiv64 { dst: u8, src: u8 },
    SDiv64Imm { dst: u8, imm: i32 },
    SRem64 { dst: u8, src: u8 },
    SRem64Imm { dst: u8, imm: i32 },
}

impl DecodedIxn {
    pub fn to_instruction(&self, config: &Config) -> ExecutableIxn {
        dbg!(&self);
        match self.opcode {
            // Load operations
            LD_B_REG => ExecutableIxn::LoadByte {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            LD_H_REG => ExecutableIxn::LoadHalf {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            LD_W_REG => ExecutableIxn::LoadWord {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            LD_DW_REG => ExecutableIxn::LoadDword {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },

            LD_1B_REG => ExecutableIxn::LoadByte {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            LD_2B_REG => ExecutableIxn::LoadHalf {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            LD_4B_REG => ExecutableIxn::LoadWord {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            LD_8B_REG => ExecutableIxn::LoadDword {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },

            LD_DW_IMM if config.below_sbpf_version(SBPFVersion::V2) => ExecutableIxn::LoadDwordImm { dst: self.dst, imm: self.imm },

            // Store operations
            ST_B_REG => ExecutableIxn::StoreByte {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            ST_H_REG => ExecutableIxn::StoreHalf {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            ST_W_REG => ExecutableIxn::StoreWord {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            ST_DW_REG => ExecutableIxn::StoreDword {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },

            ST_1B_REG => ExecutableIxn::StoreByte {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            ST_2B_REG => ExecutableIxn::StoreHalf {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            ST_4B_REG => ExecutableIxn::StoreWord {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            ST_8B_REG => ExecutableIxn::StoreDword {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },

            ST_B_IMM => ExecutableIxn::StoreByteImm {
                dst: self.dst,
                off: self.off,
                imm: self.imm,
            },
            ST_H_IMM => ExecutableIxn::StoreHalfImm {
                dst: self.dst,
                off: self.off,
                imm: self.imm,
            },
            ST_W_IMM => ExecutableIxn::StoreWordImm {
                dst: self.dst,
                off: self.off,
                imm: self.imm,
            },
            ST_DW_IMM => ExecutableIxn::StoreDwordImm {
                dst: self.dst,
                off: self.off,
                imm: self.imm,
            },

            ST_1B_IMM => ExecutableIxn::StoreByteImm {
                dst: self.dst,
                off: self.off,
                imm: self.imm,
            },
            ST_2B_IMM => ExecutableIxn::StoreHalfImm {
                dst: self.dst,
                off: self.off,
                imm: self.imm,
            },
            ST_4B_IMM => ExecutableIxn::StoreWordImm {
                dst: self.dst,
                off: self.off,
                imm: self.imm,
            },
            ST_8B_IMM => ExecutableIxn::StoreDwordImm {
                dst: self.dst,
                off: self.off,
                imm: self.imm,
            },

            // 32-bit ALU operations
            ADD32_REG => ExecutableIxn::Add32 { dst: self.dst, src: self.src },
            ADD32_IMM => ExecutableIxn::Add32Imm { dst: self.dst, imm: self.imm },
            SUB32_REG => ExecutableIxn::Sub32 { dst: self.dst, src: self.src },
            SUB32_IMM => ExecutableIxn::Sub32Imm { dst: self.dst, imm: self.imm },
            MUL32_REG => ExecutableIxn::Mul32 { dst: self.dst, src: self.src },
            MUL32_IMM => ExecutableIxn::Mul32Imm { dst: self.dst, imm: self.imm },
            DIV32_REG => ExecutableIxn::Div32 { dst: self.dst, src: self.src },
            DIV32_IMM => ExecutableIxn::Div32Imm { dst: self.dst, imm: self.imm },
            OR32_REG => ExecutableIxn::Or32 { dst: self.dst, src: self.src },
            OR32_IMM => ExecutableIxn::Or32Imm { dst: self.dst, imm: self.imm },
            AND32_REG => ExecutableIxn::And32 { dst: self.dst, src: self.src },
            AND32_IMM => ExecutableIxn::And32Imm { dst: self.dst, imm: self.imm },
            LSH32_REG => ExecutableIxn::Lsh32 { dst: self.dst, src: self.src },
            LSH32_IMM => ExecutableIxn::Lsh32Imm { dst: self.dst, imm: self.imm },
            RSH32_REG => ExecutableIxn::Rsh32 { dst: self.dst, src: self.src },
            RSH32_IMM => ExecutableIxn::Rsh32Imm { dst: self.dst, imm: self.imm },
            NEG32 => ExecutableIxn::Neg32 { dst: self.dst },
            MOD32_REG => ExecutableIxn::Mod32 { dst: self.dst, src: self.src },
            MOD32_IMM => ExecutableIxn::Mod32Imm { dst: self.dst, imm: self.imm },
            XOR32_REG => ExecutableIxn::Xor32 { dst: self.dst, src: self.src },
            XOR32_IMM => ExecutableIxn::Xor32Imm { dst: self.dst, imm: self.imm },
            MOV32_REG => ExecutableIxn::Mov32 { dst: self.dst, src: self.src },
            MOV32_IMM => ExecutableIxn::Mov32Imm { dst: self.dst, imm: self.imm },
            ARSH32_REG => ExecutableIxn::Arsh32 { dst: self.dst, src: self.src },
            ARSH32_IMM => ExecutableIxn::Arsh32Imm { dst: self.dst, imm: self.imm },

            // 64-bit ALU operations
            ADD64_REG => ExecutableIxn::Add64 { dst: self.dst, src: self.src },
            ADD64_IMM => ExecutableIxn::Add64Imm { dst: self.dst, imm: self.imm },
            SUB64_REG => ExecutableIxn::Sub64 { dst: self.dst, src: self.src },
            SUB64_IMM => ExecutableIxn::Sub64Imm { dst: self.dst, imm: self.imm },
            MUL64_REG => ExecutableIxn::Mul64 { dst: self.dst, src: self.src },
            MUL64_IMM => ExecutableIxn::Mul64Imm { dst: self.dst, imm: self.imm },
            DIV64_REG => ExecutableIxn::Div64 { dst: self.dst, src: self.src },
            DIV64_IMM => ExecutableIxn::Div64Imm { dst: self.dst, imm: self.imm },
            OR64_REG => ExecutableIxn::Or64 { dst: self.dst, src: self.src },
            OR64_IMM => ExecutableIxn::Or64Imm { dst: self.dst, imm: self.imm },
            AND64_REG => ExecutableIxn::And64 { dst: self.dst, src: self.src },
            AND64_IMM => ExecutableIxn::And64Imm { dst: self.dst, imm: self.imm },
            LSH64_REG => ExecutableIxn::Lsh64 { dst: self.dst, src: self.src },
            LSH64_IMM => ExecutableIxn::Lsh64Imm { dst: self.dst, imm: self.imm },
            RSH64_REG => ExecutableIxn::Rsh64 { dst: self.dst, src: self.src },
            RSH64_IMM => ExecutableIxn::Rsh64Imm { dst: self.dst, imm: self.imm },
            NEG64 => ExecutableIxn::Neg64 { dst: self.dst },
            MOD64_REG => ExecutableIxn::Mod64 { dst: self.dst, src: self.src },
            MOD64_IMM => ExecutableIxn::Mod64Imm { dst: self.dst, imm: self.imm },
            XOR64_REG => ExecutableIxn::Xor64 { dst: self.dst, src: self.src },
            XOR64_IMM => ExecutableIxn::Xor64Imm { dst: self.dst, imm: self.imm },
            MOV64_REG => ExecutableIxn::Mov64 { dst: self.dst, src: self.src },
            MOV64_IMM => ExecutableIxn::Mov64Imm { dst: self.dst, imm: self.imm },
            ARSH64_REG => ExecutableIxn::Arsh64 { dst: self.dst, src: self.src },
            ARSH64_IMM => ExecutableIxn::Arsh64Imm { dst: self.dst, imm: self.imm },
            HOR64_IMM => ExecutableIxn::HorImm { dst: self.dst, imm: self.imm },

            // Jump operations
            JA => ExecutableIxn::Ja { off: self.off },
            JEQ_REG => ExecutableIxn::Jeq {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            JEQ_IMM => ExecutableIxn::JeqImm {
                dst: self.dst,
                imm: self.imm,
                off: self.off,
            },
            JGT_REG => ExecutableIxn::Jgt {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            JGT_IMM => ExecutableIxn::JgtImm {
                dst: self.dst,
                imm: self.imm,
                off: self.off,
            },
            JGE_REG => ExecutableIxn::Jge {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            JGE_IMM => ExecutableIxn::JgeImm {
                dst: self.dst,
                imm: self.imm,
                off: self.off,
            },
            JLT_REG => ExecutableIxn::Jlt {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            JLT_IMM => ExecutableIxn::JltImm {
                dst: self.dst,
                imm: self.imm,
                off: self.off,
            },
            JLE_REG => ExecutableIxn::Jle {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            JLE_IMM => ExecutableIxn::JleImm {
                dst: self.dst,
                imm: self.imm,
                off: self.off,
            },
            JSET_REG => ExecutableIxn::Jset {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            JSET_IMM => ExecutableIxn::JsetImm {
                dst: self.dst,
                imm: self.imm,
                off: self.off,
            },
            JNE_REG => ExecutableIxn::Jne {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            JNE_IMM => ExecutableIxn::JneImm {
                dst: self.dst,
                imm: self.imm,
                off: self.off,
            },
            JSGT_REG => ExecutableIxn::Jsgt {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            JSGT_IMM => ExecutableIxn::JsgtImm {
                dst: self.dst,
                imm: self.imm,
                off: self.off,
            },
            JSGE_REG => ExecutableIxn::Jsge {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            JSGE_IMM => ExecutableIxn::JsgeImm {
                dst: self.dst,
                imm: self.imm,
                off: self.off,
            },
            JSLT_REG => ExecutableIxn::Jslt {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            JSLT_IMM => ExecutableIxn::JsltImm {
                dst: self.dst,
                imm: self.imm,
                off: self.off,
            },
            JSLE_REG => ExecutableIxn::Jsle {
                dst: self.dst,
                src: self.src,
                off: self.off,
            },
            JSLE_IMM => ExecutableIxn::JsleImm {
                dst: self.dst,
                imm: self.imm,
                off: self.off,
            },

            // Special operations
            CALL_IMM => ExecutableIxn::Call { imm: self.imm },
            CALL_REG => ExecutableIxn::CallReg { dst: self.dst, src: self.src },
            EXIT if !config.has_sbpf_version_enabled(SBPFVersion::V3) => ExecutableIxn::Exit,
            RETURN => ExecutableIxn::Return,
            SYSCALL if config.has_sbpf_version_enabled(SBPFVersion::V3) => ExecutableIxn::Syscall { imm: self.imm },

            // Endianness operations
            LE => ExecutableIxn::Le { dst: self.dst, imm: self.imm },
            BE => ExecutableIxn::Be { dst: self.dst, imm: self.imm },

            // Product/Quotient/Remainder operations
            LMUL32_REG => ExecutableIxn::LMul32 { dst: self.dst, src: self.src },
            LMUL32_IMM => ExecutableIxn::LMul32Imm { dst: self.dst, imm: self.imm },
            UDIV32_REG => ExecutableIxn::UDiv32 { dst: self.dst, src: self.src },
            UDIV32_IMM => ExecutableIxn::UDiv32Imm { dst: self.dst, imm: self.imm },
            UREM32_REG => ExecutableIxn::URem32 { dst: self.dst, src: self.src },
            UREM32_IMM => ExecutableIxn::URem32Imm { dst: self.dst, imm: self.imm },
            SDIV32_REG => ExecutableIxn::SDiv32 { dst: self.dst, src: self.src },
            SDIV32_IMM => ExecutableIxn::SDiv32Imm { dst: self.dst, imm: self.imm },
            SREM32_REG => ExecutableIxn::SRem32 { dst: self.dst, src: self.src },
            SREM32_IMM => ExecutableIxn::SRem32Imm { dst: self.dst, imm: self.imm },

            LMUL64_REG => ExecutableIxn::LMul64 { dst: self.dst, src: self.src },
            LMUL64_IMM => ExecutableIxn::LMul64Imm { dst: self.dst, imm: self.imm },
            UHMUL64_REG => ExecutableIxn::UHMul64 { dst: self.dst, src: self.src },
            UHMUL64_IMM => ExecutableIxn::UHMul64Imm { dst: self.dst, imm: self.imm },
            UDIV64_REG => ExecutableIxn::UDiv64 { dst: self.dst, src: self.src },
            UDIV64_IMM => ExecutableIxn::UDiv64Imm { dst: self.dst, imm: self.imm },
            UREM64_REG => ExecutableIxn::URem64 { dst: self.dst, src: self.src },
            UREM64_IMM => ExecutableIxn::URem64Imm { dst: self.dst, imm: self.imm },
            SHMUL64_REG => ExecutableIxn::SHMul64 { dst: self.dst, src: self.src },
            SHMUL64_IMM => ExecutableIxn::SHMul64Imm { dst: self.dst, imm: self.imm },
            SDIV64_REG => ExecutableIxn::SDiv64 { dst: self.dst, src: self.src },
            SDIV64_IMM => ExecutableIxn::SDiv64Imm { dst: self.dst, imm: self.imm },
            SREM64_REG => ExecutableIxn::SRem64 { dst: self.dst, src: self.src },
            SREM64_IMM => ExecutableIxn::SRem64Imm { dst: self.dst, imm: self.imm },

            // Unknown
            _ => panic!("Unknown instruction"),
        }
    }
}

// from sbpf

/// Byte offset of the immediate field in the instruction
pub const BYTE_OFFSET_IMMEDIATE: usize = 4;
/// Byte length of the immediate field in the instruction
pub const BYTE_LEN_IMMEDIATE: usize = 4;

/// BPF relocation types.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum BpfRelocationType {
    /// No relocation, placeholder
    R_Bpf_None = 0,
    /// R_BPF_64_64 relocation type is used for lddw / ld_imm64 instruction.
    /// The actual to-be-relocated data (0 or section offset) is
    /// stored at r_offset + 4 and the read/write data bitsize is 32
    /// (4 bytes). The relocation can be resolved with the symbol
    /// value plus implicit addend.
    R_Bpf_64_64 = 1,
    /// 64 bit relocation of a ldxdw instruction.  The ldxdw
    /// instruction occupies two instruction slots. The 64-bit address
    /// to load from is split into the 32-bit imm field of each
    /// slot. The first slot's pre-relocation imm field contains the
    /// virtual address (typically same as the file offset) of the
    /// location to load. Relocation involves calculating the
    /// post-load 64-bit physical address referenced by the imm field
    /// and writing that physical address back into the imm fields of
    /// the ldxdw instruction.
    R_Bpf_64_Relative = 8,
    /// Relocation of a call instruction.  The existing imm field
    /// contains either an offset of the instruction to jump to (think
    /// local function call) or a special value of "-1".  If -1 the
    /// symbol must be looked up in the symbol table.  The relocation
    /// entry contains the symbol number to call.  In order to support
    /// both local jumps and calling external symbols a 32-bit hash is
    /// computed and stored in the the call instruction's 32-bit imm
    /// field.  The hash is used later to look up the 64-bit address
    /// to jump to.  In the case of a local jump the hash is
    /// calculated using the current program counter and in the case
    /// of a symbol the hash is calculated using the name of the
    /// symbol.
    R_Bpf_64_32 = 10,
}
