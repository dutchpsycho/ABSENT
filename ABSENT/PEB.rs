use std::ptr::null_mut;
use std::mem::size_of;
use std::ffi::c_void;

use winapi::um::winnt::HANDLE;
use winapi::um::winnt::PROCESS_SET_INFORMATION;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::memoryapi::VirtualQueryEx;
use winapi::um::psapi::{EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL};
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::libloaderapi::{GetModuleHandleW, GetModuleFileNameW};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE};

use winapi::shared::ntdef::NTSTATUS;
use winapi::shared::ntdef::NT_SUCCESS;
use winapi::shared::ntstatus::STATUS_SUCCESS;

use winapi::shared::minwindef::{HMODULE, DWORD, MAX_PATH};
use winapi::shared::ntdef::{PVOID, ULONG, WCHAR, LIST_ENTRY, UNICODE_STRING};

#[repr(C)]
pub struct PROCESS_BASIC_INFORMATION {
    pub reserved1: PVOID,
    pub PebBaseAddress: *mut PEB,
    pub reserved2: [PVOID; 2],
    pub UniqueProcessId: PVOID,
    pub Reserved3: PVOID,
}

type NtQueryInformationProcessFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    ProcessInformationClass: ULONG,
    ProcessInformation: PVOID,
    ProcessInformationLength: ULONG,
    ReturnLength: PVOID,
) -> i32;

extern "system" {
    pub fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: ULONG,
        ProcessInformation: PVOID,
        ProcessInformationLength: ULONG,
        ReturnLength: PVOID,
    ) -> i32;
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Length: ULONG,
    pub Initialized: u8,
    pub SsHandle: PVOID,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
    pub EntryInProgress: PVOID,
    pub ShutdownInProgress: u8,
    pub ShutdownThreadId: PVOID,
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub DllBase: PVOID,
    pub EntryPoint: PVOID,
    pub SizeOfImage: ULONG,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub Flags: ULONG,
    pub LoadCount: u16,
    pub TlsIndex: u16,
    pub HashLinks: LIST_ENTRY,
    pub TimeDateStamp: ULONG,
}

#[repr(C)]
pub struct PEB {
    pub Reserved1: [u8; 2],
    pub BeingDebugged: u8,
    pub Reserved2: [u8; 1],
    pub Reserved3: [PVOID; 2],
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: PVOID,
}

fn get_peb(process_handle: winapi::um::winnt::HANDLE) -> Option<*mut PEB> {
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let status = unsafe {
        NtQueryInformationProcess(
            process_handle,
            0,
            &mut pbi as *mut _ as *mut _,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            null_mut(),
        )
    };

    if status != STATUS_SUCCESS {
        return None;
    }
    Some(pbi.PebBaseAddress)
}

fn get_loaded_modules(process_handle: winapi::um::winnt::HANDLE) -> Vec<String> {
    let mut modules: Vec<HMODULE> = vec![null_mut(); 1024];
    let mut needed: DWORD = 0;

    if unsafe {
        EnumProcessModulesEx(
            process_handle,
            modules.as_mut_ptr(),
            (modules.len() * size_of::<HMODULE>()) as u32,
            &mut needed,
            LIST_MODULES_ALL,
        )
    } == 0
    {
        return Vec::new();
    }

    modules.resize(needed as usize / size_of::<HMODULE>(), null_mut());

    modules.iter().filter_map(|&module| {
        if module.is_null() {
            return None;
        }
        let mut filename: [u16; MAX_PATH] = [0; MAX_PATH];
        if unsafe { GetModuleFileNameExW(process_handle, module, filename.as_mut_ptr(), MAX_PATH as u32) } > 0 {
            Some(String::from_utf16_lossy(&filename))
        } else {
            None
        }
    }).collect()
}

pub fn hidden_modules(process_handle: winapi::um::winnt::HANDLE) {
    if let Some(peb) = get_peb(process_handle) {
        let mut ldr_data_addr: *mut PEB_LDR_DATA = null_mut();
        if unsafe {
            ReadProcessMemory(
                process_handle,
                &(*peb).Ldr as *const _ as *const _,
                &mut ldr_data_addr as *mut _ as *mut _,
                size_of::<*mut PEB_LDR_DATA>(),
                null_mut(),
            )
        } == 0
        {
            println!("Failed to read peb->ldr");
            return;
        }

        let mut ldr_data: PEB_LDR_DATA = unsafe { std::mem::zeroed() };
        if unsafe {
            ReadProcessMemory(
                process_handle,
                ldr_data_addr as *const _,
                &mut ldr_data as *mut _ as *mut _,
                size_of::<PEB_LDR_DATA>(),
                null_mut(),
            )
        } == 0
        {
            println!("Failed to read peb ldr data");
            return;
        }

        let mut entry_addr = ldr_data.InLoadOrderModuleList.Flink;
        let mut seen_modules = Vec::new();

        while !entry_addr.is_null() && entry_addr != &ldr_data.InLoadOrderModuleList as *const _ as *mut _ {
            let mut ldr_entry: LDR_DATA_TABLE_ENTRY = unsafe { std::mem::zeroed() };
            if unsafe {
                ReadProcessMemory(
                    process_handle,
                    entry_addr as *const _,
                    &mut ldr_entry as *mut _ as *mut _,
                    size_of::<LDR_DATA_TABLE_ENTRY>(),
                    null_mut(),
                )
            } == 0
            {
                break;
            }

            let mut module_name: [u16; MAX_PATH] = [0; MAX_PATH];
            if unsafe {
                ReadProcessMemory(
                    process_handle,
                    ldr_entry.FullDllName.Buffer as *const _,
                    module_name.as_mut_ptr() as *mut _,
                    (ldr_entry.FullDllName.Length as usize) * 2,
                    null_mut(),
                )
            } != 0
            {
                let module_str = String::from_utf16_lossy(&module_name);
                seen_modules.push(module_str);
            }

            entry_addr = ldr_entry.InLoadOrderLinks.Flink;
        }

        let enumerated_modules = get_loaded_modules(process_handle);

        for module in seen_modules.iter() {
            if !enumerated_modules.contains(module) {
                println!("Potentially shadow-loaded module: {}", module);
            }
        }

        let ntdll_count = seen_modules.iter().filter(|m| m.to_lowercase().contains("ntdll.dll")).count();
        if ntdll_count > 1 {
            println!("Multiple instances of ntdll detected!");
        }
    }
}