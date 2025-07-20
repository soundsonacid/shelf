use crate::vm::Vm;

pub fn syscall_string(vm: *mut Vm, addr_start: u64, len: u64, _r3: u64, _r4: u64, _r5: u64) {
    let region = unsafe {
        (&*vm)
            .ctx
            .memory
            .find_region_for_addr(addr_start as usize)
            .unwrap()
    };
    let str_bytes = region.read_bytes(addr_start as usize, len as usize);
    let msg = str::from_utf8(str_bytes).unwrap();
    println!("log: {msg}");
}
