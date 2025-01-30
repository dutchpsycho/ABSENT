use capstone::arch::x86::X86Insn;
use capstone::arch::BuildsCapstone;
use capstone::prelude::*;

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::ptr;
use std::io::{self, Write};

use winapi::ctypes::c_void;

use winapi::um::errhandlingapi::GetLastError;
use winapi::um::sysinfoapi::GetSystemDirectoryW;
use winapi::um::libloaderapi::LOAD_LIBRARY_AS_DATAFILE;
use winapi::um::libloaderapi::{LoadLibraryExA, GetModuleHandleA, GetProcAddress};
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::psapi::{EnumProcessModules, GetModuleBaseNameA, GetModuleInformation, MODULEINFO};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE};
use winapi::um::winnt::{HANDLE, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_EXPORT_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT};

use winapi::shared::minwindef::HMODULE;

pub struct FunctionInfo {
    pub start: u64,
    pub end: u64,
}

pub fn process(process_handle: HANDLE) -> Result<(), String> {

    unsafe {
        let original_module_base = loc_ntdll(process_handle)?;
        let mut original_exports = HashMap::new();
        locate_exports(original_module_base, &mut original_exports)?;

        let clean_ntdll_path = sys_ntdll()?;
        let clean_module_base = load_ntdll(&clean_ntdll_path)?;
        let mut clean_exports = HashMap::new();
        locate_exports(clean_module_base, &mut clean_exports)?;

        let original_functions = routines(&original_exports, original_module_base, "original");
        let clean_functions = routines(&clean_exports, clean_module_base, "clean");

        cmpf(&original_functions, &clean_functions, original_module_base, clean_module_base);

        Ok(())

    }
}

unsafe fn loc_ntdll(process_handle: HANDLE) -> Result<*const u8, String> {
    let mut module_handles: [HMODULE; 1024] = [ptr::null_mut(); 1024];
    let mut bytes_needed = 0;

    if EnumProcessModules(
        process_handle,
        module_handles.as_mut_ptr(),
        std::mem::size_of_val(&module_handles) as u32,
        &mut bytes_needed,
    ) == 0 {
        return Err(format!("failed to enumerate modules -> {}", GetLastError()));
    }

    for &module_handle in &module_handles[..(bytes_needed / std::mem::size_of::<HMODULE>() as u32) as usize] {
        let mut module_name = vec![0u8; 260];
        if GetModuleBaseNameA(
            process_handle,
            module_handle,
            module_name.as_mut_ptr() as *mut i8, // FIX: cast to `*mut i8`
            module_name.len() as u32,
        ) > 0 {
            let name = CStr::from_ptr(module_name.as_ptr() as *const i8) // FIX: cast to `*const i8`
                .to_string_lossy()
                .to_string();
            if name.eq_ignore_ascii_case("ntdll.dll") {
                println!("located ntdll -> {:?}", module_handle);
                return Ok(module_handle as *const u8);
            }
        }
    }

    Err("failed to locate ntdll.dll in target process".to_string())
}

unsafe fn locate_exports(module_base: *const u8, exports: &mut HashMap<String, u64>) -> Result<(), String> {
    let dos_header = module_base as *const IMAGE_DOS_HEADER;
    let nt_headers = (module_base.offset((*dos_header).e_lfanew as isize)) as *const IMAGE_NT_HEADERS64;

    let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
    let export_dir = module_base.offset(export_dir_rva as isize) as *const IMAGE_EXPORT_DIRECTORY;

    let name_rvas = module_base.offset((*export_dir).AddressOfNames as isize) as *const u32;
    let func_rvas = module_base.offset((*export_dir).AddressOfFunctions as isize) as *const u32;
    let ordinals = module_base.offset((*export_dir).AddressOfNameOrdinals as isize) as *const u16;

    let count = (*export_dir).NumberOfNames;
    for i in 0..count {

        let name_offset = module_base.offset(*name_rvas.offset(i as isize) as isize) as *const u8;
        let export_name = CStr::from_ptr(name_offset as *const i8).to_string_lossy();

        let ordinal = *ordinals.offset(i as isize) as usize;
        let func_rva = *func_rvas.offset(ordinal as isize);

        exports.insert(export_name.to_string(), func_rva as u64);

    }

    Ok(())
}

fn sys_ntdll() -> Result<String, String> {
    let mut sys32_path = vec![0u16; 260];
    unsafe {
        if GetSystemDirectoryW(sys32_path.as_mut_ptr(), sys32_path.len() as u32) == 0 {
            return Err(format!("failed to get system directory -> {}", GetLastError()));
        }
    }

    let path = String::from_utf16_lossy(&sys32_path)
        .trim_end_matches('\0')
        .to_string();
    Ok(format!("{}\\ntdll.dll", path))
}

unsafe fn load_ntdll(path: &str) -> Result<*const u8, String> {
    let c_path = CString::new(path).map_err(|_| "Invalid sys32_path".to_string())?;
    let module = LoadLibraryExA(c_path.as_ptr(), ptr::null_mut(), 0);

    if module.is_null() {
        return Err(format!(
            "{}", GetLastError()
        ));
    }

    println!("Loaded clean ntdll -> {:?}", module);
    Ok(module as *const u8)
}

pub fn routines(
    exports: &HashMap<String, u64>,
    module_base: *const u8,
    label: &str,
) -> HashMap<String, FunctionInfo> {
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()
        .expect("Failed to create Capstone");

    let mut function_map = HashMap::new();
    let mut log_buffer = String::new();

    log_buffer.push_str(&format!("\n{} Functions:\n", label));

    let max_name_length = exports
        .keys()
        .filter(|export| export.starts_with("Ki") || export.starts_with("Zw") || export.starts_with("Nt"))
        .map(|name| name.len())
        .max()
        .unwrap_or(25);

    let prefix_priority = |name: &str| match name.get(0..2) {
        Some("Ki") => 0,
        Some("Zw") => 1,
        Some("Nt") => 2,
        _ => 3,
    };

    let mut sorted_functions: Vec<_> = exports
        .iter()
        .filter(|(export, _)| {
            export.starts_with("Ki") || export.starts_with("Zw") || export.starts_with("Nt")
        })
        .collect();
    sorted_functions.sort_by_key(|(name, _)| (prefix_priority(name), (*name).clone()));

    log_buffer.push_str(&format!(
        "{:<width$} | {:<14} | {:<14}\n",
        "Name", "Start Address", "End Address",
        width = max_name_length
    ));
    log_buffer.push_str(&format!(
        "{}|{}|{}\n",
        "-".repeat(max_name_length),
        "-".repeat(16),
        "-".repeat(16)
    ));

    for (export, &rva) in sorted_functions {
        let routine_start = unsafe { module_base.add(rva as usize) };
        let routine_data = unsafe { std::slice::from_raw_parts(routine_start, 0x1000) };

        match cs.disasm_all(routine_data, rva) {
            Ok(insns) => {
                let end_address = insns.iter().find_map(|insn| {
                    let id = insn.id().0;
                    if id == X86Insn::X86_INS_RET as u32 || id == X86Insn::X86_INS_JMP as u32 {
                        Some(insn.address())
                    } else {
                        None
                    }
                });

                if let Some(end) = end_address {
                    function_map.insert(
                        export.to_string(),
                        FunctionInfo {
                            start: rva as u64,
                            end,
                        },
                    );

                    log_buffer.push_str(&format!(
                        "{:<width$} | 0x{:08X}    | 0x{:08X}\n",
                        export, rva, end,
                        width = max_name_length
                    ));
                }
            }
            Err(e) => {
                log_buffer.push_str(&format!(
                    "{:<width$} | 0x{:08X}    | Failed to disassemble -> {}\n",
                    export, rva, e,
                    width = max_name_length
                ));
            }
        }
    }

    println!("{}", log_buffer);
    function_map
}

fn cmpf(
    original_functions: &HashMap<String, FunctionInfo>,
    clean_functions: &HashMap<String, FunctionInfo>,
    original_base: *const u8,
    clean_base: *const u8,
) {
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()
        .expect("failed to create capstone instance");

    for (func_name, original_info) in original_functions {
        if let Some(clean_info) = clean_functions.get(func_name) {
            let original_data = unsafe {
                std::slice::from_raw_parts(
                    original_base.add(original_info.start as usize),
                    (original_info.end - original_info.start) as usize,
                )
            };
            let clean_data = unsafe {
                std::slice::from_raw_parts(
                    clean_base.add(clean_info.start as usize),
                    (clean_info.end - clean_info.start) as usize,
                )
            };

            let original_insns = cs.disasm_all(original_data, original_info.start);
            let clean_insns = cs.disasm_all(clean_data, clean_info.start);

            match (original_insns, clean_insns) {
                (Ok(original), Ok(clean)) => {
                    let mut hook_detected = false;
                    let mut syscall_redirect = false;

                    for (o, c) in original.iter().zip(clean.iter()) {
                        let o_bytes = o.bytes();
                        let c_bytes = c.bytes();

                        // detect inline hooks (jmp/call hijacks)
                        if o.id().0 == X86Insn::X86_INS_JMP as u32
                            || o.id().0 == X86Insn::X86_INS_CALL as u32
                        {
                            if o_bytes != c_bytes {
                                println!(
                                    "[!] Inline hook detected -> {} (original: 0x{:x}, modified: 0x{:x})",
                                    func_name,
                                    o.address(),
                                    c.address()
                                );
                                hook_detected = true;
                            }
                        }

                        // detect syscall redirection (syscall replaced with jmp/call)
                        if o.id().0 == X86Insn::X86_INS_SYSCALL as u32
                            && c.id().0 != X86Insn::X86_INS_SYSCALL as u32
                        {
                            println!(
                                "[!] Syscall redirection detected -> {} (original: 0x{:x}, modified: 0x{:x})",
                                func_name,
                                o.address(),
                                c.address()
                            );
                            syscall_redirect = true;
                        }
                        
                        if hook_detected && syscall_redirect {
                            break;
                        }
                    }
                }
                _ => println!("Failed to disassemble func -> {}", func_name),
            }
        }
    }
}