use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::ptr::null_mut;

use winapi::ctypes::c_void;
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::psapi::{EnumProcessModulesEx, GetModuleInformation, MODULEINFO, LIST_MODULES_64BIT};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE};
use winapi::um::winnt::{HANDLE, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_IMPORT_DESCRIPTOR};
use winapi::um::psapi::GetModuleBaseNameW;

#[derive(Debug)]
pub struct HookDetectionResult {
    pub function_rva: u32,
    pub function_va: usize,
    pub expected_module_base: usize,
    pub expected_module_end: usize,
    pub hooked: bool,
}

fn is_address_hooked(address: usize, module_bounds: &HashMap<String, (usize, usize)>) -> bool {
    for (_, &(base, size)) in module_bounds.iter() {
        if address >= base && address < base + size {
            return false;
        }
    }
    true
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
        return HashMap::new();
    }

    let module_count = needed as usize / std::mem::size_of::<*mut c_void>();
    let mut module_map = HashMap::new();

    for i in 0..module_count {
        let mut module_info: MODULEINFO = unsafe { std::mem::zeroed() };

        if unsafe {
            GetModuleInformation(
                process_handle,
                modules[i] as *mut _,
                &mut module_info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
        } == 0
        {
            continue;
        }

        let mut name_buf = [0u16; 256];
        if unsafe {
            GetModuleBaseNameW(
                process_handle,
                modules[i] as *mut _,
                name_buf.as_mut_ptr(),
                name_buf.len() as u32,
            )
        } == 0
        {
            continue;
        }

        let name = OsString::from_wide(&name_buf)
            .to_string_lossy()
            .trim_end_matches('\0')
            .to_lowercase();

        module_map.insert(name, (module_info.lpBaseOfDll as usize, module_info.SizeOfImage as usize));
    }

    module_map
}

pub fn scan_iat_for_hooks(process_handle: HANDLE, target_module: &str) -> Vec<HookDetectionResult> {
    let module_bounds = get_module_bounds(process_handle);
    let (module_base, module_size) = match module_bounds.get(target_module) {
        Some(bounds) => *bounds,
        None => return vec![],
    };

    let mut dos_header: IMAGE_DOS_HEADER = unsafe { std::mem::zeroed() };
    if unsafe {
        ReadProcessMemory(
            process_handle,
            module_base as *const c_void,
            &mut dos_header as *mut _ as *mut c_void,
            std::mem::size_of::<IMAGE_DOS_HEADER>(),
            null_mut(),
        )
    } == 0
    {
        return vec![];
    }

    if dos_header.e_lfanew == 0 || dos_header.e_lfanew as usize > module_size {
        return vec![];
    }

    let nt_headers_addr = module_base + dos_header.e_lfanew as usize;
    let mut nt_headers: IMAGE_NT_HEADERS64 = unsafe { std::mem::zeroed() };

    if unsafe {
        ReadProcessMemory(
            process_handle,
            nt_headers_addr as *const c_void,
            &mut nt_headers as *mut _ as *mut c_void,
            std::mem::size_of::<IMAGE_NT_HEADERS64>(),
            null_mut(),
        )
    } == 0
    {
        return vec![];
    }

    let import_directory = nt_headers.OptionalHeader.DataDirectory[1]; // import table
    if import_directory.VirtualAddress == 0 || import_directory.VirtualAddress as usize > module_size {
        return vec![];
    }

    let import_descriptor_addr = module_base + import_directory.VirtualAddress as usize;

    let mut results = vec![];
    let mut import_descriptor: IMAGE_IMPORT_DESCRIPTOR = unsafe { std::mem::zeroed() };
    let mut offset = 0;

    loop {
        if unsafe {
            ReadProcessMemory(
                process_handle,
                (import_descriptor_addr + offset) as *const c_void,
                &mut import_descriptor as *mut _ as *mut c_void,
                std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>(),
                null_mut(),
            )
        } == 0
        {
            break;
        }

        if import_descriptor.Name == 0 {
            break;
        }

        let thunk_data_addr = module_base + import_descriptor.FirstThunk as usize;
        let mut thunk_offset = 0;

        loop {
            let mut function_va: usize = 0;
            if unsafe {
                ReadProcessMemory(
                    process_handle,
                    (thunk_data_addr + thunk_offset) as *const c_void,
                    &mut function_va as *mut _ as *mut c_void,
                    std::mem::size_of::<usize>(),
                    null_mut(),
                )
            } == 0
            {
                break;
            }

            if function_va == 0 {
                break;
            }

            let hooked = is_address_hooked(function_va, &module_bounds);
            if hooked {
                results.push(HookDetectionResult {
                    function_rva: (thunk_data_addr + thunk_offset - module_base) as u32,
                    function_va,
                    expected_module_base: module_base,
                    expected_module_end: module_base + module_size,
                    hooked,
                });
            }

            thunk_offset += std::mem::size_of::<usize>();
        }

        offset += std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
    }

    results
}

pub fn scan_ntdll_kernel32(process_handle: HANDLE) -> Vec<HookDetectionResult> {
    let mut all_hooks = vec![];
    all_hooks.extend(scan_iat_for_hooks(process_handle, "ntdll.dll"));
    all_hooks.extend(scan_iat_for_hooks(process_handle, "kernel32.dll"));
    all_hooks
}