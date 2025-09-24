mod cli;
mod detector;
mod pe;
mod elf;
mod macho;
mod utils;

use anyhow::Result;
use cli::Cli;
use clap::Parser;
use detector::FileType;

fn main() -> Result<()> {
    let args = Cli::parse();
    let file_data = std::fs::read(&args.file)?;

    match detector::detect_file_type(&file_data) {
        Some(FileType::PE) => pe::parse_pe(&file_data, &args.file)?,
        Some(FileType::ELF) => elf::parse_elf(&file_data, &args.file)?,
        Some(FileType::MachO) => macho::parse_macho(&file_data, &args.file)?,
        None => println!("Unknown or unsupported binary format."),
    }

    Ok(())
}
