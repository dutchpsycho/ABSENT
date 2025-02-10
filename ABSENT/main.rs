#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_imports)]
#![allow(unused_assignments)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

pub mod scanner;
pub mod Integrity;
pub mod IAT;
pub mod PEB;
pub mod prologue;

use scanner::*;
use Integrity::*;
use IAT::*;
use PEB::*;
use prologue::*;

use std::env;
use std::io::{self, Write};
use anyhow::{Result, Error};

use winapi::ctypes::c_void;
use winapi::shared::ntdef::HANDLE;

fn main() -> Result<(), Error> {
    let ascii_art = r#"                                                          
           =                                     
           .=                                    
           ]).                                   
          ~=%}                          - :      
          -:}%+                        .+^+      
           [[%{      ABSENT V1.0       [(}*      
           ]@%%[                      -@@@+      
           :%%%%(                     >@@@-      
          = {%{%@[                 :[#@@@#       
           >[@@%@@{.              -}@@@@@{:      
           -{@@@{@@#.          =[ ~}@@@@@<.      
           *~=[@@@@%%%^      -: .{@@@@@%.        
            +[)*@@@@@%@[    .~.=@@@@@@}.         
               ~^~<(%@%%#%{(({@@@@@@=            
               ::>{@%%%@@%%@@@@@@@>              
                   +#%%%%@@@@@@@@@{-             
              ..*((#%%%%@@@@@@@@@@@@]            
              ..*(%@@@@@@@@@@@@]~  +%+           
              =}@@@@@@@@@@@}         .           
           ={@@@{)]}*:~[@%#[]^                   
          :*)=.            :[[:                  
        --                  ^]                  
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

    scan(pH);
    prologue_check(pH);
    hidden_modules(pH);

    match integrity_check(pH) {
        Ok(_) => println!("No hooks detected. Analysis complete."),
        Err(e) => eprintln!("{}", e),
    }

    let mut exit_input = String::new();
    io::stdin().read_line(&mut exit_input)?;

    Ok(())
}