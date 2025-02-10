use std::ptr::null_mut;
use std::ffi::{CString, CStr};

use anyhow::{Result, Context};

use winapi::um::processthreadsapi::{OpenProcess, OpenThread, GetThreadTimes};
use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, Thread32First, Thread32Next,
    PROCESSENTRY32, THREADENTRY32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD,
};
use winapi::um::handleapi::CloseHandle;
use winapi::um::winuser::FindWindowA;
use winapi::um::winuser::GetWindowThreadProcessId;
use winapi::shared::minwindef::FILETIME;

pub struct ProcessInfo {
    pub handle: HANDLE,
    pub pid: u32,
    pub tHandle: HANDLE,
}

pub fn Scope(process_name: &str) -> Result<ProcessInfo> {
    let pid = match wPID(process_name) {
        Some(pid) => pid,
        None => PID(process_name)?,
    };

    let process_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if process_handle.is_null() {
        return Err(anyhow::anyhow!("Failed to open process with PID: {}", pid));
    }

    let tHandle = find_low_cycle_thread(pid).context("Failed to find a low-cycle thread")?;

    Ok(ProcessInfo {
        handle: process_handle,
        pid,
        tHandle,
    })
}

fn wPID(window_name: &str) -> Option<u32> {
    let c_window_name = CString::new(window_name.to_lowercase()).ok()?;
    unsafe {
        let hwnd = FindWindowA(null_mut(), c_window_name.as_ptr() as *const i8);
        if hwnd.is_null() {
            return None;
        }

        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, &mut pid as *mut u32);
        if pid == 0 {
            None
        } else {
            Some(pid)
        }
    }
}

fn PID(process_name: &str) -> Result<u32> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot.is_null() {
        return Err(anyhow::anyhow!("Failed to create process snapshot"));
    }

    let mut entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    let c_process_name = CString::new(process_name.to_lowercase()).context("Failed to convert to name")?;

    let mut pid = None;
    unsafe {
        if Process32First(snapshot, &mut entry) != 0 {
            loop {
                let current_name = CStr::from_ptr(entry.szExeFile.as_ptr())
                    .to_string_lossy()
                    .to_lowercase();
                if current_name == c_process_name.to_string_lossy()
                    || current_name == format!("{}.exe", c_process_name.to_string_lossy())
                {
                    pid = Some(entry.th32ProcessID);
                    break;
                }
                if Process32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }

    pid.ok_or_else(|| anyhow::anyhow!("Process not found: {}", process_name))
}

fn find_low_cycle_thread(pid: u32) -> Result<HANDLE> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot.is_null() {
        return Err(anyhow::anyhow!("Failed to create thread snapshot"));
    }

    let mut thread_entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

    let mut lowest_cycles = u64::MAX;
    let mut valid_thread_handle = None;

    unsafe {
        if Thread32First(snapshot, &mut thread_entry) != 0 {
            loop {
                if thread_entry.th32OwnerProcessID == pid {
                    let tHandle = OpenThread(THREAD_ALL_ACCESS, 0, thread_entry.th32ThreadID);
                    if !tHandle.is_null() {
                        let cycles = cycles(tHandle)?;
                        if cycles > 0 && cycles < lowest_cycles {
                            if let Some(old_handle) = valid_thread_handle {
                                CloseHandle(old_handle);
                            }
                            lowest_cycles = cycles;
                            valid_thread_handle = Some(tHandle);
                        } else {
                            CloseHandle(tHandle);
                        }
                    }
                }
                if Thread32Next(snapshot, &mut thread_entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }

    valid_thread_handle.ok_or_else(|| anyhow::anyhow!("No valid thread found"))
}

fn cycles(tHandle: HANDLE) -> Result<u64> {
    let mut creation_time: FILETIME = unsafe { std::mem::zeroed() };
    let mut exit_time: FILETIME = unsafe { std::mem::zeroed() };
    let mut kernel_time: FILETIME = unsafe { std::mem::zeroed() };
    let mut user_time: FILETIME = unsafe { std::mem::zeroed() };

    let result = unsafe {
        GetThreadTimes(
            tHandle,
            &mut creation_time as *mut FILETIME,
            &mut exit_time as *mut FILETIME,
            &mut kernel_time as *mut FILETIME,
            &mut user_time as *mut FILETIME,
        )
    };

    if result == 0 {
        return Err(anyhow::anyhow!("Failed to get thread times"));
    }

    let kernel_time = ((kernel_time.dwHighDateTime as u64) << 32) | (kernel_time.dwLowDateTime as u64);
    let user_time = ((user_time.dwHighDateTime as u64) << 32) | (user_time.dwLowDateTime as u64);

    Ok(kernel_time + user_time)
}
