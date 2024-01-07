use colored::Colorize;
use regex::Regex;
use std::fs;
use std::path::Path;
use structopt::StructOpt;
use std::io::{self, Write};
use std::process::Command;

#[derive(StructOpt, Debug)]
#[structopt(
    name = "patch4pwn",
    about = "auto patch elf with glibc-all-in-one, and copy the debug file to current dir."
)]
struct Opt {
    // target elf file
    #[structopt(short = "f", long = "file")]
    elf_file: String,

    // target glibc version
    #[structopt(short = "t", long = "target", default_value = "2.31-0ubuntu9.9_amd64")]
    target_description: String,

    // glibc-all-in-one path
    #[structopt(short = "b", long = "base_dir", default_value = "/home/eastxuelian/config/glibc-all-in-one/libs")]
    base_dir: String,
}

fn read_int() -> Option<usize> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok()?;
    input.trim().parse().ok()
}

fn parse_ldd_output(binary: &str) -> Result<Vec<(String, String)>, io::Error> {
    let output = Command::new("ldd").arg(binary).output()?.stdout;

    let output_str = String::from_utf8_lossy(&output);

    let re = Regex::new(r"(?:(?P<name1>[\w\.]+\.so(?:\.\d+)?))?\s*(?:=>)?\s*(?P<path>[^\s(]+)(?: \((?P<address>0x[\da-fA-F]+)\))?").expect("Failed to compile regex");

    let mut result = Vec::new();
    for cap in re.captures_iter(&output_str) {
        let name = cap.name("name1").or(cap.name("path")).unwrap().as_str().to_string();
        let path = cap.name("path").map(|p| p.as_str().to_string()).unwrap_or_default();
        
        if !name.is_empty() && !path.is_empty() {
            result.push((name, path));
        }
    }
    Ok(result)
}

fn contains_libc_pattern(name: &str) -> bool {
    let pattern = r"libc\.so\.6|libc-\d+\.\d{2}\.so";

    let re = Regex::new(pattern).unwrap();
    re.is_match(name)
}

fn match_glibc(target: &str, base_dir: &Path) -> Vec<String> {
    let mut result = Vec::new();

    if let Ok(entries) = fs::read_dir(base_dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_dir() && path.to_string_lossy().contains(target) {
                    result.push(path.to_string_lossy().into_owned());
                }
            }
        }
    }

    result
}

fn replace_needed(binary_path: &str, old_needed: &str, new_needed: &str) -> std::io::Result<()> {
    // println!("patchelf --replace-needed {} {} {}", old_needed, new_needed, binary_path);
    let status = Command::new("patchelf")
        .args(&["--replace-needed", old_needed, new_needed, binary_path])
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to run patchelf",
        ))
    }
}

fn set_interpreter(binary_path: &str, interpreter: &str) -> std::io::Result<()> {
    let status = Command::new("patchelf")
        .args(&["--set-interpreter", interpreter, binary_path])
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to run patchelf",
        ))
    }
}

fn main() {
    let opt = Opt::from_args();

    let base_dir = Path::new(&opt.base_dir);
    let found_glibc = match_glibc(&opt.target_description, base_dir);

    if found_glibc.len() < 1 {
        println!("[-] Failed to find libc: {}", opt.target_description.red());
    } else {
        let mut idx = 0;

        if found_glibc.len() > 1 {
            println!(
                "[*] Found following libcs in {}:",
                base_dir.to_string_lossy().yellow()
            );
            for i in 0..found_glibc.len() {
                println!("\t[{}] {}", i, found_glibc[i].blue());
            }

            print!("Enter your choice > ");
            io::stdout().flush().unwrap();

            match read_int() {
                Some(num) => idx = num,
                None => println!("Please enter a valid integer!"),
            }
        }

        let dir = &found_glibc[idx];
        let elfpath = &opt.elf_file;

        match parse_ldd_output(elfpath) {
            Ok(libs) => {

                for (name, _path) in libs {
                    if contains_libc_pattern(&name) {
                        let newlibc_path = format!("{}/libc.so.6", dir);
                        match replace_needed(elfpath, &name, &newlibc_path) {
                            Ok(_) => println!("[+] {}", "Successfully replaced needed library.".green()),
                            Err(e) => eprintln!("[-] Error: {}", e),
                        }
                    }
                }

                let newld_path = format!("{}/ld-linux-x86-64.so.2", dir);
                match set_interpreter(elfpath, &newld_path) {
                    Ok(_) => println!("[+] {}", "Successfully set interpreter.".green()),
                    Err(e) => eprintln!("[-] Error: {}", e),
                }

                let elf_path = Path::new(elfpath);
                let elf_parent = elf_path.parent().expect("no parent route").to_string_lossy();
                let debug_dir = format!("{}/.debug/", elf_parent);
                let gaio_debug = format!("{}/.debug/", dir);
                let full_path = Path::new(&debug_dir);

                match fs::metadata(&full_path) {
                    Ok(metadata) => {
                        if metadata.is_dir() {
                            match fs::remove_dir_all(debug_dir.clone()) {
                                Ok(()) => {
                                    println!("[*] {}", ".debug already exists, deleting...".red());
                                },
                                    Err(_) => {
                                    println!("[-] {}", "You should not get here???".red());
                                }
                            }
                        }
                    }
                    Err(_) => {
                        println!("[*] creating .debug");
                    }
                }

                let _ = Command::new("cp")
                    .args(&["-r", &gaio_debug, &debug_dir])
                    .output()
                    .expect("[-] cp failed.");

                let final_ldd = Command::new("ldd")
                    .args(&[&elfpath])
                    .output()
                    .expect("[-] ldd failed.");
                if final_ldd.status.success() {
                    let ldd_output = String::from_utf8_lossy(&final_ldd.stdout);
                    println!("--------------ldd---------------");
                    print!("{}", ldd_output.yellow());
                    println!("--------------ldd---------------");
                } else {
                    eprintln!("Error: {:?}", String::from_utf8_lossy(&final_ldd.stderr));
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        }
    }
}
