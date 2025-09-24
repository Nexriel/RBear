use anyhow::{Result, Context};
use chrono::{NaiveDateTime, TimeZone, Utc};
use scroll::Pread;

use crate::utils::{rva_to_file_offset, read_cstring, read_u16, read_u32};

#[derive(Debug)]
struct SectionInfo {
    virt_addr: u32,
    raw_ptr: u32,
    raw_size: u32,
}

pub fn parse_pe(data: &[u8], filename: &str) -> Result<()> {
    println!("File: {}", filename);
    println!("Format: PE (Portable Executable)");

    // DOS header
    let e_magic: &str = std::str::from_utf8(&data[0..2])
        .context("Failed to read DOS header magic")?;
    if e_magic != "MZ" {
        anyhow::bail!("Not a valid PE file");
    }
    let e_lfanew: u32 = data.pread(0x3C)?;

    // NT headers
    let pe_sig: &str = std::str::from_utf8(
        &data[e_lfanew as usize..e_lfanew as usize + 2]
    ).context("Failed to read PE signature")?;
    if pe_sig != "PE" {
        anyhow::bail!("Missing PE signature");
    }

    let machine: u16 = data.pread(e_lfanew as usize + 4)?;
    let num_sections: u16 = data.pread(e_lfanew as usize + 6)?;
    let timestamp: u32 = data.pread(e_lfanew as usize + 8)?;
    let opt_header_size: u16 = data.pread(e_lfanew as usize + 20)?;
    let entry_point_rva: u32 = data.pread(e_lfanew as usize + 40)?;

    println!("Machine: 0x{:X}", machine);
    println!("Sections: {}", num_sections);
    let datetime = NaiveDateTime::from_timestamp_opt(timestamp as i64, 0).unwrap();
    println!("Timestamp: {}", Utc.from_utc_datetime(&datetime));
    println!("Entry Point RVA: 0x{:X}", entry_point_rva);

    // Parse sections
    let sec_table_offset = e_lfanew as usize + 24 + opt_header_size as usize;
    let mut sections = Vec::new();

    println!("\nSections:");
    for i in 0..num_sections {
        let offset = sec_table_offset + (i as usize * 40);
        let name = String::from_utf8_lossy(&data[offset..offset + 8])
            .trim_matches(char::from(0))
            .to_string();
        let virt_size: u32 = data.pread(offset + 8)?;
        let virt_addr: u32 = data.pread(offset + 12)?;
        let raw_size: u32 = data.pread(offset + 16)?;
        let raw_ptr: u32 = data.pread(offset + 20)?;
        println!(
            "  {} | VA: 0x{:X} | VS: {} | RS: {} | RAW_PTR: 0x{:X}",
            name, virt_addr, virt_size, raw_size, raw_ptr
        );
        sections.push(SectionInfo {
            virt_addr,
            raw_ptr,
            raw_size,
        });
    }

    // Data directories
    let opt_header_offset = e_lfanew as usize + 24;
    let magic: u16 = data.pread(opt_header_offset)?;
    let is_pe32_plus = magic == 0x20B;

    let data_dir_offset = if is_pe32_plus {
        opt_header_offset + 112
    } else {
        opt_header_offset + 96
    };

    let import_rva: u32 = data.pread(data_dir_offset)?;
    let _import_size: u32 = data.pread(data_dir_offset + 4)?;
    let export_rva: u32 = data.pread(data_dir_offset + 8)?;
    let _export_size: u32 = data.pread(data_dir_offset + 12)?;

    println!("\nImports:");
    parse_pe_imports(data, import_rva, &sections)?;

    println!("\nExports:");
    parse_pe_exports(data, export_rva, &sections)?;

    Ok(())
}

fn parse_pe_imports(data: &[u8], import_rva: u32, sections: &[SectionInfo]) -> Result<()> {
    if import_rva == 0 {
        println!("  No imports.");
        return Ok(());
    }

    let mut offset = match rva_to_file_offset(import_rva, &sections_to_tuples(sections)) {
        Some(v) => v,
        None => {
            println!("  Failed to resolve import table offset.");
            return Ok(());
        }
    };

    loop {
        let orig_first_thunk: u32 = read_u32(data, offset);
        let time_date_stamp: u32 = read_u32(data, offset + 4);
        let forwarder_chain: u32 = read_u32(data, offset + 8);
        let name_rva: u32 = read_u32(data, offset + 12);
        let first_thunk: u32 = read_u32(data, offset + 16);

        if orig_first_thunk == 0 {
            break;
        }

        let name_offset = match rva_to_file_offset(name_rva, &sections_to_tuples(sections)) {
            Some(v) => v,
            None => {
                println!("  [Bad DLL name RVA]");
                return Ok(());
            }
        };
        let dll_name = read_cstring(data, name_offset);
        println!("  DLL: {}", dll_name);

        // Parse functions
        let mut thunk_offset = match rva_to_file_offset(orig_first_thunk, &sections_to_tuples(sections)) {
            Some(v) => v,
            None => break,
        };

        loop {
            let thunk_data: u64 = data.pread(thunk_offset)?;
            if thunk_data == 0 {
                break;
            }
            if thunk_data & 0x8000000000000000 != 0 {
                println!("    Ordinal: {}", thunk_data & 0xFFFF);
            } else {
                let hint_name_rva = (thunk_data & 0x7FFFFFFF) as u32;
                let hint_name_offset = match rva_to_file_offset(hint_name_rva, &sections_to_tuples(sections)) {
                    Some(v) => v,
                    None => break,
                };
                let _hint = read_u16(data, hint_name_offset);
                let func_name = read_cstring(data, hint_name_offset + 2);
                println!("    {}", func_name);
            }
            thunk_offset += 8; // 64-bit thunks
        }

        offset += 20; // next IMAGE_IMPORT_DESCRIPTOR
    }

    Ok(())
}

fn parse_pe_exports(data: &[u8], export_rva: u32, sections: &[SectionInfo]) -> Result<()> {
    if export_rva == 0 {
        println!("  No exports.");
        return Ok(());
    }

    let exp_offset = match rva_to_file_offset(export_rva, &sections_to_tuples(sections)) {
        Some(v) => v,
        None => {
            println!("  Failed to resolve export table offset.");
            return Ok(());
        }
    };

    let characteristics: u32 = read_u32(data, exp_offset);
    let time_date_stamp: u32 = read_u32(data, exp_offset + 4);
    let major_ver: u16 = read_u16(data, exp_offset + 8);
    let minor_ver: u16 = read_u16(data, exp_offset + 10);
    let name_rva: u32 = read_u32(data, exp_offset + 12);
    let ordinal_base: u32 = read_u32(data, exp_offset + 16);
    let num_funcs: u32 = read_u32(data, exp_offset + 20);
    let num_names: u32 = read_u32(data, exp_offset + 24);
    let addr_table_rva: u32 = read_u32(data, exp_offset + 28);
    let name_ptr_rva: u32 = read_u32(data, exp_offset + 32);
    let ord_table_rva: u32 = read_u32(data, exp_offset + 36);

    let dll_name_offset = rva_to_file_offset(name_rva, &sections_to_tuples(sections)).unwrap_or(0);
    let dll_name = read_cstring(data, dll_name_offset);
    println!("  DLL Name: {}", dll_name);
    println!("  Functions: {}", num_funcs);
    println!("  Names: {}", num_names);
    println!("  Ordinal Base: {}", ordinal_base);

    let name_ptr_offset = rva_to_file_offset(name_ptr_rva, &sections_to_tuples(sections)).unwrap_or(0);
    let ord_table_offset = rva_to_file_offset(ord_table_rva, &sections_to_tuples(sections)).unwrap_or(0);

    for i in 0..num_names {
        let func_name_rva: u32 = read_u32(data, name_ptr_offset + (i as usize * 4));
        let func_name_offset = match rva_to_file_offset(func_name_rva, &sections_to_tuples(sections)) {
            Some(v) => v,
            None => continue,
        };
        let func_name = read_cstring(data, func_name_offset);
        let ordinal: u16 = read_u16(data, ord_table_offset + (i as usize * 2));
        println!("    {} (Ordinal {})", func_name, ordinal + ordinal_base as u16);
    }

    Ok(())
}

fn sections_to_tuples(sections: &[SectionInfo]) -> Vec<(u32, u32, u32)> {
    sections.iter()
        .map(|s| (s.virt_addr, s.raw_ptr, s.raw_size))
        .collect()
}
