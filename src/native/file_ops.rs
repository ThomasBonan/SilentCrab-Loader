// loader/src/native/file_ops.rs
use crate::native::call::{
    FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_STANDARD_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT, FileStandardInformation, IO_STATUS_BLOCK, NativeAPI, OBJ_CASE_INSENSITIVE, OBJECT_ATTRIBUTES, UNICODE_STRING
};
use std::{ptr, mem};

/// Convertir un chemin Rust en UNICODE_STRING
unsafe fn path_to_unicode_string(path: &str) -> (Vec<u16>, UNICODE_STRING) {
    // Convertir UTF-8 en UTF-16 (Wide char)
    let mut wide_path: Vec<u16> = path.encode_utf16().collect();
    wide_path.push(0); // Null terminator
    
    let unicode_string = UNICODE_STRING {
        Length: (wide_path.len() * 2 - 2) as u16, // Sans le null terminator
        MaximumLength: (wide_path.len() * 2) as u16, // Avec null terminator
        Buffer: wide_path.as_mut_ptr(),
    };
    
    (wide_path, unicode_string)
}

/// Vérifier si un fichier existe avec NTAPI (remplace metadata())
pub unsafe fn nt_file_exists(
    native_api: &NativeAPI,
    file_path: &str
) -> Result<bool, String> {
    // 1. Convertir le chemin
    let (wide_buffer, mut unicode_string) = path_to_unicode_string(file_path);
    
    // 2. Créer OBJECT_ATTRIBUTES
    let mut object_attr = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: ptr::null_mut(),
        ObjectName: &mut unicode_string,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null_mut(),
        SecurityQualityOfService: ptr::null_mut(),
    };
    
    // 3. IO_STATUS_BLOCK
    let mut io_status = IO_STATUS_BLOCK {
        Status: 0,
        Information: 0,
    };
    
    // 4. Ouvrir le fichier (ou essayer)
    let mut file_handle: *mut std::ffi::c_void = ptr::null_mut();
    
    let status = (native_api.nt_open_file)(
        &mut file_handle,
        FILE_READ_ATTRIBUTES,
        &mut object_attr,
        &mut io_status,
        FILE_SHARE_READ,
        FILE_OPEN | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    );
    
    // 5. Vérifier le résultat
    if status == -1073741772 { // STATUS_OBJECT_NAME_NOT_FOUND
    Ok(false)
    } else if status == -1073741702 { // STATUS_OBJECT_PATH_NOT_FOUND (0xC000003A)
        Ok(false)
    } else if status >= 0 {
        // Fichier existe
        let _ = (native_api.nt_close)(file_handle);
        Ok(true)
    } else {
        // Autre erreur
        Err(format!("NtOpenFile failed: 0x{:X}", status as u32))
    }
}

/// Obtenir des informations sur un fichier (équivalent à metadata())
pub unsafe fn nt_get_file_info(
    native_api: &NativeAPI,
    file_path: &str
) -> Result<FILE_STANDARD_INFORMATION, String> {
    // 1. Ouvrir le fichier
    let (wide_buffer, mut unicode_string) = path_to_unicode_string(file_path);
    
    let mut object_attr = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: ptr::null_mut(),
        ObjectName: &mut unicode_string,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null_mut(),
        SecurityQualityOfService: ptr::null_mut(),
    };
    
    let mut io_status = IO_STATUS_BLOCK { Status: 0, Information: 0 };
    let mut file_handle: *mut std::ffi::c_void = ptr::null_mut();
    
    let status = (native_api.nt_open_file)(
        &mut file_handle,
        FILE_READ_ATTRIBUTES,
        &mut object_attr,
        &mut io_status,
        FILE_SHARE_READ,
        FILE_OPEN | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    );
    
    if status != 0 {
        return Err(format!("NtOpenFile failed: 0x{:X}", status));
    }
    
    // 2. Obtenir les informations
    let mut file_info: crate::native::call::FILE_STANDARD_INFORMATION = mem::zeroed();
    let mut io_status2 = IO_STATUS_BLOCK { Status: 0, Information: 0 };
    
    let status = (native_api.nt_query_information_file)(
        file_handle,
        &mut io_status2,
        &mut file_info as *mut _ as *mut _,
        mem::size_of::<crate::native::call::FILE_STANDARD_INFORMATION>() as u32,
        FileStandardInformation,
    );
    
    // 3. Fermer le handle
    let _ = (native_api.nt_close)(file_handle);
    
    if status != 0 {
        return Err(format!("NtQueryInformationFile failed: 0x{:X}", status));
    }
    
    Ok(file_info)
}