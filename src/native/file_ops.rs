// loader/src/native/file_ops.rs
use crate::native::call::{
    FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_STANDARD_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT, FileStandardInformation, IO_STATUS_BLOCK, NativeAPI, OBJ_CASE_INSENSITIVE, OBJECT_ATTRIBUTES, UNICODE_STRING
};
use std::{ptr, mem};

/// Converts a UTF-8 Rust path string into a native Windows `UNICODE_STRING`
/// Required for passing wide strings to NTAPI like `NtOpenFile`
/// Returns both the underlying buffer and the constructed `UNICODE_STRING`
/// Caller is responsible for keeping the buffer alive
unsafe fn path_to_unicode_string(path: &str) -> (Vec<u16>, UNICODE_STRING) {
    let mut wide_path: Vec<u16> = path.encode_utf16().collect();
    wide_path.push(0); // Null terminator
    
    let unicode_string = UNICODE_STRING {
        Length: (wide_path.len() * 2 - 2) as u16, 
        MaximumLength: (wide_path.len() * 2) as u16, 
        Buffer: wide_path.as_mut_ptr(),
    };
    
    (wide_path, unicode_string)
}



/// Checks whether a file exists using `NtOpenFile`
/// This avoids any WinAPI dependencies (e.g., `std::fs::metadata`)
///
/// # Safety
/// This function calls raw NTAPI and uses unsafe memory structures
pub unsafe fn nt_file_exists(
    native_api: &NativeAPI,
    file_path: &str
) -> Result<bool, String> {
    // Convert Rust string to `UNICODE_STRING`
    let (wide_buffer, mut unicode_string) = path_to_unicode_string(file_path);
    
    // Set up OBJECT_ATTRIBUTES structure for `NtOpenFile`
    let mut object_attr = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: ptr::null_mut(),
        ObjectName: &mut unicode_string,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null_mut(),
        SecurityQualityOfService: ptr::null_mut(),
    };
    
    
    let mut io_status = IO_STATUS_BLOCK {
        Status: 0,
        Information: 0,
    };
    
    let mut file_handle: *mut std::ffi::c_void = ptr::null_mut();
    
    let status = (native_api.nt_open_file)(
        &mut file_handle,
        FILE_READ_ATTRIBUTES,
        &mut object_attr,
        &mut io_status,
        FILE_SHARE_READ,
        FILE_OPEN | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    );
    
    // Handle common failure statuses gracefully
    if status == -1073741772 { // STATUS_OBJECT_NAME_NOT_FOUND
    Ok(false)
    } else if status == -1073741702 { // STATUS_OBJECT_PATH_NOT_FOUND (0xC000003A)
        Ok(false)
    } else if status >= 0 {
        let _ = (native_api.nt_close)(file_handle);
        Ok(true)
    } else {
        Err(format!("NtOpenFile failed: 0x{:X}", status as u32))
    }
}



/// Retrieves standard file metadata using native NTAPI
/// Equivalent to `std::fs::metadata()` but avoids high-level WinAPI
///
/// # Safety
/// Must ensure provided NTAPI struct is valid and memory-safe
pub unsafe fn nt_get_file_info(
    native_api: &NativeAPI,
    file_path: &str
) -> Result<FILE_STANDARD_INFORMATION, String> {
    // Convert to wide path and build UNICODE_STRING
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
    
    // Open the file to retrieve its handle
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