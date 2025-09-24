use scroll::Pread;

pub fn rva_to_file_offset(rva: u32, sections: &[(u32, u32, u32)]) -> Option<usize> {
    for (virt_addr, raw_ptr, raw_size) in sections {
        if rva >= *virt_addr && rva < *virt_addr + *raw_size {
            let offset = (rva - virt_addr) + raw_ptr;
            return Some(offset as usize);
        }
    }
    None
}

pub fn read_cstring(data: &[u8], start: usize) -> String {
    let mut s = String::new();
    for &b in &data[start..] {
        if b == 0 { break; }
        s.push(b as char);
    }
    s
}

pub fn read_u16(data: &[u8], offset: usize) -> u16 {
    data.pread::<u16>(offset).unwrap_or(0)
}

pub fn read_u32(data: &[u8], offset: usize) -> u32 {
    data.pread::<u32>(offset).unwrap_or(0)
}

pub fn read_u64(data: &[u8], offset: usize) -> u64 {
    data.pread::<u64>(offset).unwrap_or(0)
}
