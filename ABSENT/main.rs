#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_imports)]
#![allow(unused_assignments)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

// cba dealing with windows-sys and its outdated docs
// ill fix this in the future, deal with the SLIGHTLY larger binary size for now

pub mod scope;
pub mod hooks;
pub mod bounds;
pub mod ldr;
pub mod mem;

use scope::*;
use hooks::*;
use bounds::*;
use ldr::*;
use mem::*;

use std::env;
use std::io::{self, Write};
use anyhow::{Result, Error};

use winapi::ctypes::c_void;
use winapi::shared::ntdef::HANDLE;

fn main() -> Result<(), Error> {
    let ascii_art = r#"
     N       `7MM"""Yp,   .M"""bgd `7MM"""YNMM  `7MN.   `7MF MMPM"NMM""YMM 
    ;MM:       MM    Yb  ,MI    "Y   MM     `7   MMN.    M   P'   MM    `7 
   ,V^MM.      MM    dP  `MMb.       MM   d      M YMb   M        MM      
  ,M  `MM      MM"""bg.    `YMMNq.   MMmmMM      M  `MN. M        MM      
  AbmmmqMA     MM    `Y  .     `MM   MM   Y  ,   M   `MM.M        MM      
 A'     VML    MM    ,9  Mb     dM   MM     ,M   M     YMM        MM      
.AMA.   .AMMA .JMMmmmd9   P"Ybmmd"  .JMMmmmmMM .JML.    YM      .JMML.    
   "#;
   
   println!("{}", ascii_art);

    let args: Vec<String> = env::args().collect();

    let input = if args.len() > 1 {
        args[1].clone()
    } else {
        print!("Process name / Window title -> ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        input.trim().to_string()
    };

    let pI = match Scope(&input) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("{}", e);
            return Ok(());
        }
    };

    let pH: HANDLE = pI.handle as HANDLE;
    let tH: HANDLE = pI.tHandle as HANDLE;

    println!("Process handle: {:?}\n  Thread handle: {:?}\n  PID: {}", pH, tH, pI.pid);

    scan_ntdll_kernel32(pH);
    mem(pH);
    check_peb_ldr(pH);

    match process(pH) {
        Ok(_) => println!("No hooks detected. Analysis complete."),
        Err(e) => eprintln!("{}", e),
    }

    let mut exit_input = String::new();
    io::stdin().read_line(&mut exit_input)?;

    Ok(())
}