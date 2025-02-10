use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::ptr::null_mut;

use winapi::ctypes::c_void;

use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::psapi::{EnumProcessModulesEx, GetModuleInformation, MODULEINFO, LIST_MODULES_64BIT};
use winapi::um::winnt::{HANDLE, IMAGE_DOS_HEADER, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS64};
use winapi::um::psapi::GetModuleBaseNameW;

#[derive(Debug)]
pub struct HookDetectionResult {
    pub function_rva: u32,
    pub function_va: usize,
    pub expected_module: String,
    pub actual_module: String,
    pub hooked: bool,
}

fn is_address_hooked(address: usize, module_bounds: &HashMap<String, (usize, usize)>) -> (bool, String) {
    for (module, &(base, size)) in module_bounds.iter() {
        if address >= base && address < base + size {
            return (false, module.clone());
        }
    }
    println!("Address 0x{:x} is hooked!", address);
    (true, "<unknown>".to_string())
}

fn read_struct<T>(process_handle: HANDLE, remote_addr: usize) -> Option<T> {
    let mut data: T = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<T>();

    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            remote_addr as *const c_void,
            &mut data as *mut _ as *mut c_void,
            size,
            null_mut(),
        )
    };

    if success == 0 {
        None
    } else {
        Some(data)
    }
}

fn read_pointer(process_handle: HANDLE, remote_addr: usize) -> Option<usize> {
    let mut val: usize = 0;
    let size = std::mem::size_of::<usize>();

    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            remote_addr as *const c_void,
            &mut val as *mut _ as *mut c_void,
            size,
            null_mut(),
        )
    };

    if success == 0 {
        None
    } else {
        Some(val)
    }
}

fn get_module_bounds(process_handle: HANDLE) -> HashMap<String, (usize, usize)> {
    
    let mut modules = vec![null_mut(); 1024];
    let mut needed = 0;

    if unsafe {
        EnumProcessModulesEx(
            process_handle,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<*mut c_void>()) as u32,
            &mut needed,
            LIST_MODULES_64BIT,
        )
    } == 0
    {
        println!("EnumProcessModulesEx failed!");
        return HashMap::new();
    }

    let module_count = needed as usize / std::mem::size_of::<*mut c_void>();
    let mut module_map = HashMap::new();

    for i in 0..module_count {
        let mut module_info: MODULEINFO = unsafe { std::mem::zeroed() };
        let success = unsafe {
            GetModuleInformation(
                process_handle,
                modules[i],
                &mut module_info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
        };
        if success == 0 {
            println!("Failed GetModuleInformation at index {}", i);
            continue;
        }

        let mut name_buf = [0u16; 256];
        let name_len = unsafe {
            GetModuleBaseNameW(
                process_handle,
                modules[i],
                name_buf.as_mut_ptr(),
                name_buf.len() as u32,
            )
        };
        if name_len == 0 {
            println!("Failed GetModuleBaseNameW at index {}", i);
            continue;
        }

        let name = OsString::from_wide(&name_buf[..name_len as usize])
            .to_string_lossy()
            .to_lowercase();

        let base = module_info.lpBaseOfDll as usize;
        let size = module_info.SizeOfImage as usize;

        // println!("{} | Base: 0x{:x} | Size: 0x{:x}", name, base, size);
        module_map.insert(name, (base, size));
    }

    module_map
}

/// Scans the Import Address Table (IAT) of a target module for hooks.
fn scan_iat_for_hooks(process_handle: HANDLE, target_module: &str) -> Vec<HookDetectionResult> {
    println!("Scanning IAT for hooks in '{}'", target_module);

    let module_bounds = get_module_bounds(process_handle);
    let (module_base, module_size) = match module_bounds.get(&target_module.to_lowercase()) {
        Some(bounds) => *bounds,
        None => {
            println!("Target module '{}' not found!", target_module);
            return vec![];
        }
    };

    let dos_header: IMAGE_DOS_HEADER = match read_struct(process_handle, module_base) {
        Some(hdr) => hdr,
        None => {
            println!("Failed to read DOS header for '{}'", target_module);
            return vec![];
        }
    };

    if dos_header.e_lfanew == 0 || (dos_header.e_lfanew as usize) > module_size {
        println!("Invalid DOS header for '{}'", target_module);
        return vec![];
    }

    let nt_headers_addr = module_base + dos_header.e_lfanew as usize;
    let nt_headers: IMAGE_NT_HEADERS64 = match read_struct(process_handle, nt_headers_addr) {
        Some(hdr) => hdr,
        None => {
            println!("Failed to read NT headers for '{}'", target_module);
            return vec![];
        }
    };

    let import_dir = nt_headers.OptionalHeader.DataDirectory[1];
    if import_dir.VirtualAddress == 0 || import_dir.VirtualAddress as usize > module_size {
        println!("No import table found for '{}'", target_module);
        return vec![];
    }

    let import_desc_base = module_base + import_dir.VirtualAddress as usize;
    let mut results = Vec::new();
    let mut offset = 0;

    loop {
        let import_descriptor_addr = import_desc_base + offset;
        let import_descriptor: IMAGE_IMPORT_DESCRIPTOR =
            match read_struct(process_handle, import_descriptor_addr) {
                Some(desc) => desc,
                None => break,
            };

        if import_descriptor.Name == 0 {
            break;
        }

        let thunk_data_addr = module_base + import_descriptor.FirstThunk as usize;
        let mut thunk_offset = 0;

        loop {
            let func_ptr_addr = thunk_data_addr + thunk_offset;
            let function_va = match read_pointer(process_handle, func_ptr_addr) {
                Some(val) => val,
                None => break,
            };
            if function_va == 0 {
                break;
            }

            let (hooked, actual_module) = is_address_hooked(function_va, &module_bounds);
            if hooked {
                let rva = (func_ptr_addr - module_base) as u32;
                println!(
                    "[ALERT] Hook detected in '{}'! RVA: 0x{:x}, VA: 0x{:x}, Expected: '{}', Found: '{}'",
                    target_module, rva, function_va, target_module, actual_module
                );

                results.push(HookDetectionResult {
                    function_rva: rva,
                    function_va,
                    expected_module: target_module.to_string(),
                    actual_module,
                    hooked,
                });
            }

            thunk_offset += std::mem::size_of::<usize>();
        }

        offset += std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
    }

    results
}

pub fn scan(process_handle: HANDLE) -> Vec<HookDetectionResult> {
    let mut all_hooks = vec![];
    all_hooks.extend(scan_iat_for_hooks(process_handle, "ntdll.dll"));
    all_hooks.extend(scan_iat_for_hooks(process_handle, "kernel32.dll"));
    println!("Total hooks found: {}", all_hooks.len());
    all_hooks
}