use std::ffi::c_void;
use std::ffi::CString;
use std::mem;


// Définitions des types pour les APIs natives
pub type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut *mut c_void,
    ZeroBits: usize,
    RegionSize: *mut usize,
    AllocationType: u32,
    Protect: u32,
) -> i32;

pub type NtProtectVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut *mut c_void,
    RegionSize: *mut usize,
    NewProtect: u32,
    OldProtect: *mut u32,
) -> i32;

pub type RtlCreateUserThreadFn = unsafe extern "system" fn(
    ProcessHandle: *mut c_void,
    SecurityDescriptor: *mut c_void,
    CreateSuspended: u8,
    StackZeroBits: u32,
    StackReserve: *mut usize,
    StackCommit: *mut usize,
    StartAddress: *mut c_void,
    StartParameter: *mut c_void,
    ThreadHandle: *mut *mut c_void,
    ClientId: *mut c_void,
) -> i32;

pub type NtWaitForSingleObjectFn = unsafe extern "system" fn(
    Handle: *mut c_void,
    Alertable: u8,
    Timeout: *mut c_void,
) -> i32;

pub type NtCloseFn = unsafe extern "system" fn(
    Handle: *mut c_void,
) -> i32;



// Constantes pour NtAllocateVirtualMemory
pub const MEM_COMMIT: u32 = 0x00001000;
pub const MEM_RESERVE: u32 = 0x00002000;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;



extern "system" {
    fn GetProcAddress(h_module: *mut c_void, lp_proc_name: *const i8) -> *mut c_void;
    fn GetModuleHandleA(lp_module_name: *const i8) -> *mut c_void;
}



pub fn get_ntdll_function<T>(function_name: &str) -> Option<T> {
    unsafe {
        let ntdll = CString::new("ntdll.dll").unwrap();
        let module = GetModuleHandleA(ntdll.as_ptr());

        if module.is_null() {
            println!("[-] Échec de GetModuleHandleA pour ntdll.dll");
            return None;
        }

        let func = CString::new(function_name).unwrap();
        let addr = GetProcAddress(module, func.as_ptr());

        if addr.is_null() {
            println!("[-] Échec de GetProcAddress pour {}", function_name);
            return None;
        }

        Some(mem::transmute_copy(&addr))
    }
}

