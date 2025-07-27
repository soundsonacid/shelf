use crate::instruction::constants::MM_RODATA_START;
use crate::vm::Vm;

pub fn syscall_string(vm: *mut Vm, vm_addr: u64, len: u64, _r3: u64, _r4: u64, _r5: u64) {
    dbg!(&vm_addr);
    let a = vm_addr - MM_RODATA_START;
    dbg!(&a);
    dbg!(&len);
    let vm = unsafe { &*vm };

    let host_addr = vm.ctx.memory.translate_vm_addr(vm_addr as usize);

    let region = vm.ctx.memory.find_region_for_addr(host_addr).unwrap();

    let str_bytes = region.read_bytes(host_addr, len as usize);
    let msg = str::from_utf8(str_bytes).unwrap();
    println!("log: {msg}");
}
