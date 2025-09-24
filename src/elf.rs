use anyhow::{Result, Context};
use scroll::{Pread, LE, BE};
use crate::utils::{read_cstring};

#[derive(Debug)]
struct SectionHeader {
    name_offset: u32,
    sh_type: u32,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
}

pub fn parse_elf(data: &[u8], filename: &str) -> Result<()> {
    println!("File: {}", filename);
    println!("Format: ELF");

    let class = data[4];
    let endian = data[5];
    let is_le = endian == 1;
    let parse_u16 = |off: usize| -> u16 {
        if is_le { data.pread_with(off, LE).unwrap() } else { data.pread_with(off, BE).unwrap() }
    };
    let parse_u32 = |off: usize| -> u32 {
        if is_le { data.pread_with(off, LE).unwrap() } else { data.pread_with(off, BE).unwrap() }
    };
    let parse_u64 = |off: usize| -> u64 {
        if is_le { data.pread_with(off, LE).unwrap() } else { data.pread_with(off, BE).unwrap() }
    };

    println!("Class: {}", if class == 1 { "32-bit" } else { "64-bit" });
    println!("Endian: {}", if endian == 1 { "Little" } else { "Big" });

    let entry = if class == 1 {
        parse_u32(24) as u64
    } else {
        parse_u64(24)
    };
    println!("Entry point: 0x{:X}", entry);

    // Section header table
    let shoff = if class == 1 {
        parse_u32(32) as u64
    } else {
        parse_u64(40)
    };
    let shentsize = parse_u16(if class == 1 { 46 } else { 58 }) as u64;
    let shnum = parse_u16(if class == 1 { 48 } else { 60 }) as u64;
    let shstrndx = parse_u16(if class == 1 { 50 } else { 62 }) as u64;

    let mut sections = Vec::new();
    for i in 0..shnum {
        let base = (shoff + i * shentsize) as usize;
        let name_offset = parse_u32(base);
        let sh_type = parse_u32(base + 4);
        let sh_offset = if class == 1 {
            parse_u32(base + 16) as u64
        } else {
            parse_u64(base + 24)
        };
        let sh_size = if class == 1 {
            parse_u32(base + 20) as u64
        } else {
            parse_u64(base + 32)
        };
        let sh_link = parse_u32(base + 24);
        let sh_entsize = if class == 1 {
            parse_u32(base + 36) as u64
        } else {
            parse_u64(base + 56)
        };
        sections.push(SectionHeader {
            name_offset,
            sh_type,
            sh_offset,
            sh_size,
            sh_link,
            sh_entsize,
        });
    }

    // Section names
    let shstr_section = &sections[shstrndx as usize];
    let shstr_data = &data[shstr_section.sh_offset as usize ..
                           (shstr_section.sh_offset + shstr_section.sh_size) as usize];

    println!("\nSections:");
    for (idx, sec) in sections.iter().enumerate() {
        let name = read_cstring(shstr_data, sec.name_offset as usize);
        println!("  [{}] {} | Type: {} | Offset: 0x{:X} | Size: {}", idx, name, sec.sh_type, sec.sh_offset, sec.sh_size);
    }

    // Imports from .dynamic
    println!("\nImports (from .dynamic):");
    for sec in &sections {
        let name = read_cstring(shstr_data, sec.name_offset as usize);
        if name == ".dynamic" {
            parse_dynamic_section(data, sec, &sections, shstr_data, class, is_le);
        }
    }

    // Exports from .symtab
    println!("\nExports (from .symtab):");
    for sec in &sections {
        let name = read_cstring(shstr_data, sec.name_offset as usize);
        if name == ".symtab" {
            parse_symbol_table(data, sec, &sections, shstr_data, class, is_le);
        }
    }

    Ok(())
}

fn parse_dynamic_section(data: &[u8], sec: &SectionHeader, sections: &[SectionHeader], shstr_data: &[u8], class: u8, is_le: bool) {
    let entsize = sec.sh_entsize as usize;
    let count = sec.sh_size as usize / entsize;
    let parse_u64_fn = |off: usize| -> u64 {
        if is_le { data.pread_with(off, LE).unwrap() } else { data.pread_with(off, BE).unwrap() }
    };
    let parse_u32_fn = |off: usize| -> u32 {
        if is_le { data.pread_with(off, LE).unwrap() } else { data.pread_with(off, BE).unwrap() }
    };

    for i in 0..count {
        let off = sec.sh_offset as usize + i * entsize;
        let tag = if class == 1 {
            parse_u32_fn(off) as i64
        } else {
            parse_u64_fn(off) as i64
        };
        let val = if class == 1 {
            parse_u32_fn(off + 4) as u64
        } else {
            parse_u64_fn(off + 8)
        };
        // DT_NEEDED = 1
        if tag == 1 {
            let strtab = &sections[sec.sh_link as usize];
            let str_data = &data[strtab.sh_offset as usize ..
                                 (strtab.sh_offset + strtab.sh_size) as usize];
            let libname = read_cstring(str_data, val as usize);
            println!("  {}", libname);
        }
    }
}

fn parse_symbol_table(data: &[u8], sec: &SectionHeader, sections: &[SectionHeader], shstr_data: &[u8], class: u8, is_le: bool) {
    let entsize = sec.sh_entsize as usize;
    let count = sec.sh_size as usize / entsize;
    let parse_u64_fn = |off: usize| -> u64 {
        if is_le { data.pread_with(off, LE).unwrap() } else { data.pread_with(off, BE).unwrap() }
    };
    let parse_u32_fn = |off: usize| -> u32 {
        if is_le { data.pread_with(off, LE).unwrap() } else { data.pread_with(off, BE).unwrap() }
    };

    let strtab = &sections[sec.sh_link as usize];
    let str_data = &data[strtab.sh_offset as usize ..
                         (strtab.sh_offset + strtab.sh_size) as usize];

    for i in 0..count {
        let off = sec.sh_offset as usize + i * entsize;
        let name_offset = parse_u32_fn(off);
        let name = read_cstring(str_data, name_offset as usize);
        if !name.is_empty() {
            println!("  {}", name);
        }
    }
}
