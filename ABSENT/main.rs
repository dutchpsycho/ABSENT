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
pub mod winsys;

pub mod scope;
pub mod inline;

use scope::*;
use inline::*;

use std::env;
use std::io::{self, Write};
use anyhow::{Result, Error};

fn main() -> Result<(), Error> {
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

    let pH = pI.handle;
    let tH = pI.tHandle;

    println!("Process handle: {:?}\n  Thread handle: {:?}\n  PID: {}", pH, tH, pI.pid);

    match process(pH) {
        Ok(_) => println!("No hooks detected. Analysis complete."),
        Err(e) => eprintln!("{}", e),
    }

    let mut exit_input = String::new();
    io::stdin().read_line(&mut exit_input)?;

    Ok(())
}