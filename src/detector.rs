pub enum FileType {
    PE,
    ELF,
    MachO,
}

pub fn detect_file_type(data: &[u8]) -> Option<FileType> {
    if data.len() > 2 && &data[0..2] == b"MZ" {
        Some(FileType::PE)
    } else if data.len() > 4 && &data[0..4] == b"\x7FELF" {
        Some(FileType::ELF)
    } else if data.len() > 4 {
        let macho_magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        match macho_magic {
            0xFEEDFACE | 0xFEEDFACF | 0xCAFEBABE | 0xCAFEBABF => Some(FileType::MachO),
            _ => None,
        }
    } else {
        None
    }
}
