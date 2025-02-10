use std::sync::Arc;
use std::mem::size_of;
use std::ptr::null_mut;

use crossbeam::thread as crossbeam_thread;

use winapi::ctypes::c_void;

use winapi::shared::minwindef::DWORD;
use winapi::shared::ntstatus::STATUS_SUCCESS;
use winapi::shared::ntdef::{NTSTATUS, PVOID, ULONG};

use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::winnt::{HANDLE, MEMORY_BASIC_INFORMATION, MEM_PRIVATE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,};

type NtQueryVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    MemoryInformationClass: ULONG,
    MemoryInformation: PVOID,
    MemoryInformationLength: ULONG,
    ReturnLength: *mut ULONG,
) -> NTSTATUS;

extern "system" {
    pub fn NtQueryVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        MemoryInformationClass: ULONG,
        MemoryInformation: PVOID,
        MemoryInformationLength: ULONG,
        ReturnLength: *mut ULONG,
    ) -> NTSTATUS;
}

#[derive(Debug, Clone)]
struct MemoryRegion {
    base_address: usize,
    region_size: usize,
}

fn check_all_patterns(bytes: &[u8]) -> Option<&'static str> {

    if bytes.len() >= 6
        && bytes[0] == 0x4C
        && bytes[1] == 0x8B
        && (bytes[2] == 0xD1 || bytes[2] == 0xCA)
        && bytes[3] == 0xB8
        && bytes[5] == 0x0F
        && bytes[6] == 0x05
    {
        return Some("Standard Syscall");
    }

    if bytes.len() >= 6
        && bytes[0] == 0x4C
        && bytes[1] == 0x8B
        && bytes[2] == 0xD1
        && bytes[3] == 0xB8
        && (bytes[5] == 0xC3 || bytes[5] == 0xEB)
    {
        return Some("Ret-Based Syscall");
    }

    if bytes.len() >= 8
        && (bytes[0] == 0x48 || bytes[0] == 0x49)
        && (bytes[1] == 0x8B || bytes[1] == 0x89)
        && bytes[3] == 0xB8
        && (bytes[6] == 0xFF || bytes[6] == 0xE9)
    {
        return Some("Obfuscated Syscall");
    }

    None
}

fn gather_regions(process_handle: HANDLE) -> Vec<MemoryRegion> {
    let mut regions = Vec::new();
    let mut address: usize = 0;

    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

    while unsafe {
        NtQueryVirtualMemory(
            process_handle,
            address as *mut c_void,
            0,
            &mut mbi as *mut _ as *mut _,
            size_of::<MEMORY_BASIC_INFORMATION>() as u32,
            null_mut(),
        )
    } == STATUS_SUCCESS
    {
        let protect = mbi.Protect;
        let state = mbi.State;
        let size = mbi.RegionSize;
        let base = mbi.BaseAddress as usize;

        if state == MEM_PRIVATE
            && (protect == PAGE_EXECUTE
                || protect == PAGE_EXECUTE_READ
                || protect == PAGE_EXECUTE_READWRITE
                || protect == PAGE_EXECUTE_WRITECOPY)
        {
            regions.push(MemoryRegion {
                base_address: base,
                region_size: size,
            });
        }

        address = base + size;
    }

    if regions.is_empty() {
        println!("No executable private memory regions found");
    }

    regions
}

fn scan_region(process_handle: HANDLE, region: &MemoryRegion) {
    let size = region.region_size;
    if size < 8 {
        return;
    }

    let mut buffer = vec![0u8; size];
    let ok = unsafe {
        ReadProcessMemory(
            process_handle,
            region.base_address as *const c_void,
            buffer.as_mut_ptr() as *mut c_void,
            size,
            null_mut(),
        )
    };

    if ok == 0 {
        println!("Failed to read memory at 0x{:x}", region.base_address);
        return;
    }

    for offset in 0..size.saturating_sub(8) {
        if let Some(label) = check_all_patterns(&buffer[offset..offset + 8]) {
            let abs_address = region.base_address + offset;
            println!("[+] {} at 0x{:x}", label, abs_address);
        }
    }
}

pub fn prologue_check(process_handle: HANDLE) {
    let regions = gather_regions(process_handle);

    if regions.is_empty() {
        return;
    }

    let handle_usize = process_handle as usize;
    let regions_arc = Arc::new(regions);

    crossbeam_thread::scope(|scope| {
        let num_threads = 4;
        let chunk_size = std::cmp::max((regions_arc.len() + num_threads - 1) / num_threads, 1);

        for (i, chunk) in regions_arc.chunks(chunk_size).enumerate() {
            let local_regions = chunk.to_vec();
            scope.spawn(move |_| {
                let local_handle = handle_usize as HANDLE;
                println!("Thread {} scanning {} regions...", i, local_regions.len());

                for region in local_regions.iter() {
                    scan_region(local_handle, region);
                }
            });
        }
    })
    .expect("Failed to spawn threads in crossbeam scope");
}