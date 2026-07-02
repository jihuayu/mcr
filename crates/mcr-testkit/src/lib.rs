pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub mod elf {
    pub const ELF64_HEADER_SIZE: u16 = 64;
    pub const ELF64_PROGRAM_HEADER_SIZE: u16 = 56;

    pub const ET_EXEC: u16 = 2;
    pub const ET_DYN: u16 = 3;
    pub const EM_X86_64: u16 = 62;

    pub const PT_LOAD: u32 = 1;
    pub const PT_INTERP: u32 = 3;

    pub const PF_X: u32 = 1;
    pub const PF_W: u32 = 2;
    pub const PF_R: u32 = 4;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Elf64Builder {
        object_type: u16,
        machine: u16,
        entrypoint: u64,
        program_headers: Vec<Elf64ProgramHeader>,
        data: Vec<(u64, Vec<u8>)>,
    }

    impl Default for Elf64Builder {
        fn default() -> Self {
            Self {
                object_type: ET_EXEC,
                machine: EM_X86_64,
                entrypoint: 0,
                program_headers: Vec::new(),
                data: Vec::new(),
            }
        }
    }

    impl Elf64Builder {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        #[must_use]
        pub fn object_type(mut self, object_type: u16) -> Self {
            self.object_type = object_type;
            self
        }

        #[must_use]
        pub fn machine(mut self, machine: u16) -> Self {
            self.machine = machine;
            self
        }

        #[must_use]
        pub fn entrypoint(mut self, entrypoint: u64) -> Self {
            self.entrypoint = entrypoint;
            self
        }

        #[must_use]
        pub fn program_header(mut self, header: Elf64ProgramHeader) -> Self {
            self.program_headers.push(header);
            self
        }

        #[must_use]
        pub fn data_at(mut self, file_offset: u64, data: Vec<u8>) -> Self {
            self.data.push((file_offset, data));
            self
        }

        #[must_use]
        pub fn build(self) -> Vec<u8> {
            let phoff = u64::from(ELF64_HEADER_SIZE);
            let ph_table_len = usize::from(ELF64_PROGRAM_HEADER_SIZE) * self.program_headers.len();
            let mut len = usize::from(ELF64_HEADER_SIZE) + ph_table_len;

            for header in &self.program_headers {
                len = len.max(
                    header
                        .file_offset
                        .checked_add(header.file_size)
                        .expect("test ELF segment range should not overflow")
                        as usize,
                );
            }

            for (offset, data) in &self.data {
                len = len.max(
                    offset
                        .checked_add(data.len() as u64)
                        .expect("test ELF data range should not overflow")
                        as usize,
                );
            }

            let mut bytes = vec![0; len];
            bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
            bytes[4] = 2;
            bytes[5] = 1;
            bytes[6] = 1;
            write_u16(&mut bytes, 16, self.object_type);
            write_u16(&mut bytes, 18, self.machine);
            write_u32(&mut bytes, 20, 1);
            write_u64(&mut bytes, 24, self.entrypoint);
            write_u64(&mut bytes, 32, phoff);
            write_u16(&mut bytes, 52, ELF64_HEADER_SIZE);
            write_u16(&mut bytes, 54, ELF64_PROGRAM_HEADER_SIZE);
            write_u16(
                &mut bytes,
                56,
                self.program_headers
                    .len()
                    .try_into()
                    .expect("test ELF should fit u16 phnum"),
            );

            for (index, header) in self.program_headers.iter().enumerate() {
                let offset =
                    usize::from(ELF64_HEADER_SIZE) + index * usize::from(ELF64_PROGRAM_HEADER_SIZE);
                header
                    .write_to(&mut bytes[offset..offset + usize::from(ELF64_PROGRAM_HEADER_SIZE)]);
            }

            for (offset, data) in self.data {
                let offset = offset as usize;
                bytes[offset..offset + data.len()].copy_from_slice(&data);
            }

            bytes
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Elf64ProgramHeader {
        header_type: u32,
        flags: u32,
        file_offset: u64,
        virtual_address: u64,
        physical_address: u64,
        file_size: u64,
        memory_size: u64,
        alignment: u64,
    }

    impl Elf64ProgramHeader {
        #[must_use]
        pub fn new(
            header_type: u32,
            flags: u32,
            file_offset: u64,
            virtual_address: u64,
            file_size: u64,
            memory_size: u64,
            alignment: u64,
        ) -> Self {
            Self {
                header_type,
                flags,
                file_offset,
                virtual_address,
                physical_address: virtual_address,
                file_size,
                memory_size,
                alignment,
            }
        }

        #[must_use]
        pub fn load(
            flags: u32,
            file_offset: u64,
            virtual_address: u64,
            file_size: u64,
            memory_size: u64,
        ) -> Self {
            Self::new(
                PT_LOAD,
                flags,
                file_offset,
                virtual_address,
                file_size,
                memory_size,
                0x1000,
            )
        }

        fn write_to(&self, bytes: &mut [u8]) {
            write_u32(bytes, 0, self.header_type);
            write_u32(bytes, 4, self.flags);
            write_u64(bytes, 8, self.file_offset);
            write_u64(bytes, 16, self.virtual_address);
            write_u64(bytes, 24, self.physical_address);
            write_u64(bytes, 32, self.file_size);
            write_u64(bytes, 40, self.memory_size);
            write_u64(bytes, 48, self.alignment);
        }
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::CRATE_NAME;

    #[test]
    fn package_name_is_stable() {
        assert_eq!(CRATE_NAME, "mcr-testkit");
    }
}
