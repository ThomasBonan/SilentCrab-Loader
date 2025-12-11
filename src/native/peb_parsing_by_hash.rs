//loader/src/native/peb_parsing_by_hash.rs

use std::ffi::c_void;


#[repr(C)]
pub struct LIST_ENTRY {
    flink: *mut LIST_ENTRY,
    blink: *mut LIST_ENTRY,
}

#[repr(C)]
pub struct UNICODE_STRING {
    length: u16,           // en bytes
    maximum_length: u16,
    buffer: *mut u16,
}

pub unsafe fn unicode_to_string(unicode: &UNICODE_STRING) -> String {
    if unicode.buffer.is_null() || unicode.length == 0 {
        return String::new();
    }

    let mut result = String::new();
    for i in 0..(unicode.length / 2) {
        let ch = *unicode.buffer.offset(i as isize);
        if ch < 128 {
            result.push((ch as u8) as char);
        }
    }
    result.to_lowercase()
}

pub unsafe fn find_ntdll_simple() -> Option<*mut c_void> {
    
    // Obtenir le PEB
    let peb: *mut c_void;
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    }
    
    
    // PEB_LDR_DATA à offset 0x18 (0x18 / 8 = 3 car *mut c_void = 8 bytes)
    let ldr_data = *(peb as *mut *mut c_void).offset(0x3);

    if ldr_data.is_null() {
        return None;
    }

    // InLoadOrderModuleList à offset 0x10 (0x10 / 8 = 2)
    let first_module = *(ldr_data as *mut *mut LIST_ENTRY).offset(0x2);

    let mut current = first_module;
    let mut count = 0;

    while !current.is_null() && count < 20 {
        count += 1;

        let ldr_entry = current as *mut c_void;
        
        // BaseDllName à offset 0x58
        let base_dll_name_ptr = ldr_entry.byte_offset(0x58) as *const UNICODE_STRING;
        let base_dll_name = &*base_dll_name_ptr;
        
        let name = unicode_to_string(base_dll_name);
        
        if name.contains("ntdll.dll") {
            // DllBase à offset 0x30
            let dll_base = *(ldr_entry.byte_offset(0x30) as *const *mut c_void);
            return Some(dll_base);
        }

        current = (*current).flink;
        if current == first_module {
            break;
        }
    }

    None
}

pub fn simple_hash(data: &str) -> u32 {
    let mut hash: u32 = 0x811C9DC5;
    
    for byte in data.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    
    // Hash du null terminator
    hash ^= 0;
    hash = hash.wrapping_mul(0x01000193);
    
    hash
}

pub unsafe fn find_function_by_hash(module_base: *mut c_void, target_hash: u32) -> Option<*mut c_void> {
    
    // DOS Header
    let dos_header = module_base as *const u16;
    if *dos_header != 0x5A4D {
        return None;
    }

    // e_lfanew offset
    let e_lfanew = *(module_base.byte_offset(0x3C) as *const i32);
    
    let pe_header = module_base.byte_offset((e_lfanew as usize).try_into().unwrap());

    // Signature PE
    let pe_signature = *(pe_header as *const u32);
    if pe_signature != 0x00004550 {
        return None;
    }

    // Export Directory RVA (DataDirectory[0])
    let export_dir_rva = *(pe_header.byte_offset(0x88) as *const u32);
    let export_dir_size = *(pe_header.byte_offset(0x8C) as *const u32);
    

    if export_dir_rva == 0 || export_dir_size == 0 {
        return None;
    }

    let export_table = module_base.byte_offset((export_dir_rva as usize).try_into().unwrap());

    // Pointeurs dans l'export table
    let names_rva = *(export_table.byte_offset(0x20) as *const u32);
    let ordinals_rva = *(export_table.byte_offset(0x24) as *const u32);
    let functions_rva = *(export_table.byte_offset(0x1C) as *const u32);
    let names_count = *(export_table.byte_offset(0x18) as *const u32);
    

    let names_array = module_base.byte_offset((names_rva as usize).try_into().unwrap()) as *const u32;
    let ordinals_array = module_base.byte_offset((ordinals_rva as usize).try_into().unwrap()) as *const u16;
    let functions_array = module_base.byte_offset((functions_rva as usize).try_into().unwrap()) as *const u32;

    // Parcourir les noms des fonctions
    for i in 0..names_count {
        let name_rva = *names_array.offset(i as isize);
        let name_ptr = module_base.byte_offset((name_rva as usize).try_into().unwrap()) as *const i8;

        // Calculer le hash
        let mut hash: u32 = 0x811C9DC5;
        let mut j = 0;
        let mut func_name = String::new();

        loop {
            let ch = *name_ptr.offset(j);
            if ch == 0 {
                break;
            }
            func_name.push(ch as u8 as char);
            hash ^= ch as u8 as u32;
            hash = hash.wrapping_mul(0x01000193);
            j += 1;
        }

        // Null terminator
        hash ^= 0;
        hash = hash.wrapping_mul(0x01000193);

        if hash == target_hash {
            let ordinal = *ordinals_array.offset(i as isize);
            let function_rva = *functions_array.offset(ordinal as isize);
            let function_addr = module_base.byte_offset((function_rva as usize).try_into().unwrap());
            
            return Some(function_addr);
        }
    }

    None
}