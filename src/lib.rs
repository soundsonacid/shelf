#![allow(unreachable_patterns, clippy::match_overlapping_arm, clippy::not_unsafe_ptr_arg_deref)]

pub mod config;
pub mod context;
pub mod instruction;
pub mod memory;
pub mod parser;
pub mod program;
pub mod syscall;
pub mod vm;
