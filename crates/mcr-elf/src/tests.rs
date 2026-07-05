use mcr_testkit::elf::{
    ELF64_HEADER_SIZE as TEST_ELF64_HEADER_SIZE, ET_DYN as TEST_ET_DYN, ET_EXEC as TEST_ET_EXEC,
    Elf64Builder, Elf64ProgramHeader, PF_R as TEST_PF_R, PF_W as TEST_PF_W, PF_X as TEST_PF_X,
    PT_INTERP as TEST_PT_INTERP,
};

use super::{
    AuxiliaryVectorEntry, CRATE_NAME, DEFAULT_CLOCK_TICKS_PER_SECOND,
    DEFAULT_INTERPRETER_LOAD_BASE, DEFAULT_POSITION_INDEPENDENT_EXECUTABLE_BASE, ElfObjectType,
    ElfValidationError, GuestImageError, GuestVma, GuestVmaKind, InitialStackConfig,
    InitialStackError, SegmentPermissions, auxv, build_guest_memory_image,
    build_guest_memory_image_with_interpreter, build_initial_stack, is_elf64, parse_load_plan,
};

#[test]
fn package_name_is_stable() {
    assert_eq!(CRATE_NAME, "mcr-elf");
}

#[test]
fn parses_static_executable_load_plan() {
    let elf = Elf64Builder::new()
        .object_type(TEST_ET_EXEC)
        .entrypoint(0x401000)
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_X,
            0x1000,
            0x401000,
            0x20,
            0x20,
        ))
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_W,
            0x2000,
            0x402000,
            0x08,
            0x100,
        ))
        .data_at(0x1000, vec![0xcc; 0x20])
        .data_at(0x2000, vec![0x2a; 0x08])
        .build();

    let plan = parse_load_plan(&elf).expect("valid static ELF should parse");

    assert!(is_elf64(&elf));
    assert_eq!(plan.object_type(), ElfObjectType::Executable);
    assert_eq!(plan.entrypoint(), 0x401000);
    assert!(plan.interpreter().is_none());
    assert_eq!(plan.segments().len(), 2);

    let text = &plan.segments()[0];
    assert_eq!(text.program_header_index(), 0);
    assert_eq!(
        text.permissions(),
        SegmentPermissions::new(true, false, true)
    );
    assert_eq!(text.mapping().start(), 0x401000);
    assert_eq!(text.mapping().end(), 0x402000);
    assert_eq!(text.mapping().file_offset(), 0x1000);
    assert_eq!(text.mapping().file_size(), 0x20);

    let data = &plan.segments()[1];
    assert_eq!(data.program_header_index(), 1);
    assert_eq!(
        data.permissions(),
        SegmentPermissions::new(true, true, false)
    );
    assert_eq!(data.mapping().start(), 0x402000);
    assert_eq!(data.mapping().end(), 0x403000);
    assert_eq!(data.mapping().file_offset(), 0x2000);
    assert_eq!(data.mapping().file_size(), 0x08);

    let program_headers = plan.program_headers();
    assert_eq!(
        program_headers.file_offset(),
        u64::from(TEST_ELF64_HEADER_SIZE)
    );
    assert_eq!(program_headers.entry_count(), 2);
    assert_eq!(program_headers.virtual_address(), None);
}

#[test]
fn plans_unaligned_segment_with_page_aligned_mapping() {
    let elf = Elf64Builder::new()
        .entrypoint(0x401234)
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_X,
            0x1234,
            0x401234,
            0x20,
            0x40,
        ))
        .data_at(0x1234, vec![0xcc; 0x20])
        .build();

    let plan = parse_load_plan(&elf).expect("valid unaligned segment should parse");
    let segment = &plan.segments()[0];

    assert_eq!(segment.mapping().start(), 0x401000);
    assert_eq!(segment.mapping().end(), 0x402000);
    assert_eq!(segment.mapping().file_offset(), 0x1000);
    assert_eq!(segment.mapping().file_size(), 0x254);
}

#[test]
fn detects_dynamic_interpreter() {
    let interpreter = b"/lib64/ld-linux-x86-64.so.2\0";
    let elf = Elf64Builder::new()
        .object_type(TEST_ET_DYN)
        .entrypoint(0x1010)
        .program_header(Elf64ProgramHeader::new(
            TEST_PT_INTERP,
            TEST_PF_R,
            0x300,
            0,
            interpreter.len() as u64,
            interpreter.len() as u64,
            1,
        ))
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_X,
            0x1000,
            0x1000,
            0x80,
            0x80,
        ))
        .data_at(0x300, interpreter.to_vec())
        .data_at(0x1000, vec![0x90; 0x80])
        .build();

    let plan = parse_load_plan(&elf).expect("dynamic ELF should parse");

    assert_eq!(plan.object_type(), ElfObjectType::SharedObject);
    assert_eq!(
        plan.interpreter().expect("interpreter").as_bytes(),
        b"/lib64/ld-linux-x86-64.so.2"
    );
}

#[test]
fn builds_deterministic_initial_stack_layout() {
    let elf = Elf64Builder::new()
        .entrypoint(0x401000)
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_X,
            0,
            0x400000,
            0x80,
            0x2000,
        ))
        .build();
    let plan = parse_load_plan(&elf).expect("valid static ELF should parse");
    let random_bytes = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];

    let stack = build_initial_stack(
        &plan,
        InitialStackConfig::new(0x8000_0000, 0x4000, b"/bin/app".to_vec())
            .with_argv([b"/bin/app".to_vec(), b"--flag".to_vec()])
            .with_envp([b"HOME=/root".to_vec(), b"PATH=/bin".to_vec()])
            .with_random_bytes(random_bytes),
    )
    .expect("initial stack should build");

    assert_eq!(stack.stack_top(), 0x8000_0000);
    assert_eq!(stack.stack_base(), 0x7fff_c000);
    assert_eq!(stack.stack_pointer(), 0x7fff_fe40);
    assert_eq!(stack.bytes().len(), 0x1c0);
    assert_eq!(stack.argv_addresses(), &[0x7fff_ffcb, 0x7fff_ffd4]);
    assert_eq!(stack.envp_addresses(), &[0x7fff_ffdb, 0x7fff_ffe6]);
    assert_eq!(stack.executable_path_address(), 0x7fff_fff7);
    assert_eq!(stack.platform_address(), 0x7fff_fff0);
    assert_eq!(stack.random_address(), 0x7fff_ffbb);

    assert_eq!(read_stack_u64(&stack, 0x7fff_fe40), 2);
    assert_eq!(read_stack_u64(&stack, 0x7fff_fe48), 0x7fff_ffcb);
    assert_eq!(read_stack_u64(&stack, 0x7fff_fe50), 0x7fff_ffd4);
    assert_eq!(read_stack_u64(&stack, 0x7fff_fe58), 0);
    assert_eq!(read_stack_u64(&stack, 0x7fff_fe60), 0x7fff_ffdb);
    assert_eq!(read_stack_u64(&stack, 0x7fff_fe68), 0x7fff_ffe6);
    assert_eq!(read_stack_u64(&stack, 0x7fff_fe70), 0);

    assert_eq!(
        read_stack_bytes(&stack, 0x7fff_ffbb, 16),
        random_bytes.as_slice()
    );
    assert_eq!(read_stack_c_string(&stack, 0x7fff_ffcb), b"/bin/app");
    assert_eq!(read_stack_c_string(&stack, 0x7fff_ffd4), b"--flag");
    assert_eq!(read_stack_c_string(&stack, 0x7fff_ffdb), b"HOME=/root");
    assert_eq!(read_stack_c_string(&stack, 0x7fff_ffe6), b"PATH=/bin");
    assert_eq!(read_stack_c_string(&stack, 0x7fff_fff0), b"x86_64");
    assert_eq!(read_stack_c_string(&stack, 0x7fff_fff7), b"/bin/app");
}

#[test]
fn builds_mvp_auxiliary_vector_values() {
    let elf = Elf64Builder::new()
        .entrypoint(0x401000)
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_X,
            0,
            0x400000,
            0x80,
            0x2000,
        ))
        .build();
    let plan = parse_load_plan(&elf).expect("valid static ELF should parse");

    let stack = build_initial_stack(
        &plan,
        InitialStackConfig::new(0x8000_0000, 0x4000, b"/bin/app".to_vec())
            .with_argv([b"/bin/app".to_vec()])
            .with_envp([b"LANG=C".to_vec()])
            .with_interpreter_base(0x7000_0000),
    )
    .expect("initial stack should build");

    assert_eq!(
        stack.auxv_entries(),
        &[
            AuxiliaryVectorEntry::new(auxv::AT_PHDR, 0x400040),
            AuxiliaryVectorEntry::new(auxv::AT_PHENT, 56),
            AuxiliaryVectorEntry::new(auxv::AT_PHNUM, 1),
            AuxiliaryVectorEntry::new(auxv::AT_PAGESZ, 4096),
            AuxiliaryVectorEntry::new(auxv::AT_BASE, 0x7000_0000),
            AuxiliaryVectorEntry::new(auxv::AT_FLAGS, 0),
            AuxiliaryVectorEntry::new(auxv::AT_ENTRY, 0x401000),
            AuxiliaryVectorEntry::new(auxv::AT_UID, 0),
            AuxiliaryVectorEntry::new(auxv::AT_EUID, 0),
            AuxiliaryVectorEntry::new(auxv::AT_GID, 0),
            AuxiliaryVectorEntry::new(auxv::AT_EGID, 0),
            AuxiliaryVectorEntry::new(auxv::AT_HWCAP, 0),
            AuxiliaryVectorEntry::new(auxv::AT_CLKTCK, DEFAULT_CLOCK_TICKS_PER_SECOND),
            AuxiliaryVectorEntry::new(auxv::AT_SECURE, 0),
            AuxiliaryVectorEntry::new(auxv::AT_RANDOM, stack.random_address()),
            AuxiliaryVectorEntry::new(auxv::AT_HWCAP2, 0),
            AuxiliaryVectorEntry::new(auxv::AT_EXECFN, stack.executable_path_address()),
            AuxiliaryVectorEntry::new(auxv::AT_PLATFORM, stack.platform_address()),
            AuxiliaryVectorEntry::new(auxv::AT_NULL, 0),
        ]
    );

    let auxv_start = stack.stack_pointer() + 8 + 8 * 2 + 8 * 2;
    for (index, entry) in stack.auxv_entries().iter().enumerate() {
        let address = auxv_start + u64::try_from(index).unwrap() * 16;
        assert_eq!(read_stack_u64(&stack, address), entry.key());
        assert_eq!(read_stack_u64(&stack, address + 8), entry.value());
    }
}

#[test]
fn builds_guest_memory_image_from_load_plan() {
    let elf = Elf64Builder::new()
        .entrypoint(0x401000)
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_X,
            0,
            0x400000,
            0x1000,
            0x2000,
        ))
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_W,
            0x3000,
            0x402000,
            0x03,
            0x08,
        ))
        .data_at(0x100, vec![0xaa, 0xbb, 0xcc, 0xdd])
        .data_at(0x3000, vec![0x11, 0x22, 0x33])
        .build();
    let plan = parse_load_plan(&elf).expect("valid ELF should parse");

    let image = build_guest_memory_image(
        &plan,
        &elf,
        InitialStackConfig::new(0x8000_0000, 0x4000, b"/bin/app".to_vec()),
    )
    .expect("guest memory image should build");

    assert_eq!(image.entrypoint(), 0x401000);
    assert_eq!(
        image.initial_stack_pointer(),
        image.initial_stack().stack_pointer()
    );
    assert_eq!(image.brk(), 0x403000);
    assert_eq!(image.read(0x400100, 4).unwrap(), &[0xaa, 0xbb, 0xcc, 0xdd]);
    assert_eq!(
        image.read(0x402000, 8).unwrap(),
        &[0x11, 0x22, 0x33, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        image
            .read(
                image.initial_stack().stack_pointer(),
                image.initial_stack().bytes().len()
            )
            .unwrap(),
        image.initial_stack().bytes()
    );

    assert_eq!(
        image.vmas(),
        &[
            GuestVma::new(
                0x400000,
                0x402000,
                SegmentPermissions::new(true, false, true),
                GuestVmaKind::ElfLoad {
                    program_header_index: 0,
                    file_offset: 0,
                    file_size: 0x1000,
                },
            ),
            GuestVma::new(
                0x402000,
                0x403000,
                SegmentPermissions::new(true, true, false),
                GuestVmaKind::ElfLoad {
                    program_header_index: 1,
                    file_offset: 0x3000,
                    file_size: 0x03,
                },
            ),
            GuestVma::new(
                0x7fff_c000,
                0x8000_0000,
                SegmentPermissions::new(true, true, false),
                GuestVmaKind::Stack,
            ),
        ]
    );
}

#[test]
fn builds_dynamic_guest_memory_image_with_musl_interpreter() {
    let interpreter_path = b"/lib/ld-musl-x86_64.so.1\0";
    let executable = Elf64Builder::new()
        .object_type(TEST_ET_DYN)
        .entrypoint(0x1010)
        .program_header(Elf64ProgramHeader::new(
            TEST_PT_INTERP,
            TEST_PF_R,
            0x300,
            0,
            interpreter_path.len() as u64,
            interpreter_path.len() as u64,
            1,
        ))
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_X,
            0,
            0,
            0x1000,
            0x2000,
        ))
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_W,
            0x3000,
            0x3000,
            0x20,
            0x100,
        ))
        .data_at(0x300, interpreter_path.to_vec())
        .data_at(0x400, vec![0xaa, 0xbb, 0xcc, 0xdd])
        .data_at(0x3000, vec![0x11, 0x22])
        .build();
    let interpreter = Elf64Builder::new()
        .object_type(TEST_ET_DYN)
        .entrypoint(0x400)
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_X,
            0,
            0,
            0x1000,
            0x1000,
        ))
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_W,
            0x2000,
            0x2000,
            0x10,
            0x100,
        ))
        .data_at(0x400, vec![0x90; 4])
        .data_at(0x2000, vec![0x33, 0x44])
        .build();
    let plan = parse_load_plan(&executable).expect("dynamic ELF should parse");

    let image = build_guest_memory_image_with_interpreter(
        &plan,
        &executable,
        Some(&interpreter),
        InitialStackConfig::new(0x8000_0000, 0x4000, b"/bin/sh".to_vec()).with_argv([
            b"/bin/sh".to_vec(),
            b"-c".to_vec(),
            b"echo hi".to_vec(),
        ]),
    )
    .expect("dynamic guest image should build");

    let loaded_interpreter = image.interpreter().expect("interpreter should load");
    assert_eq!(image.entrypoint(), DEFAULT_INTERPRETER_LOAD_BASE + 0x400);
    assert_eq!(
        image.executable_load_bias(),
        DEFAULT_POSITION_INDEPENDENT_EXECUTABLE_BASE
    );
    assert_eq!(loaded_interpreter.path(), b"/lib/ld-musl-x86_64.so.1");
    assert_eq!(
        loaded_interpreter.load_bias(),
        DEFAULT_INTERPRETER_LOAD_BASE
    );
    assert_eq!(
        image.read(DEFAULT_POSITION_INDEPENDENT_EXECUTABLE_BASE + 0x400, 4),
        Some([0xaa, 0xbb, 0xcc, 0xdd].as_slice())
    );
    assert_eq!(
        image.read(DEFAULT_INTERPRETER_LOAD_BASE + 0x400, 4),
        Some([0x90, 0x90, 0x90, 0x90].as_slice())
    );
    assert!(image.vmas().iter().any(|vma| matches!(
        vma.kind(),
        GuestVmaKind::InterpreterLoad {
            path,
            program_header_index: 0,
            ..
        } if path == b"/lib/ld-musl-x86_64.so.1"
    )));
    assert!(image.vmas().iter().any(|vma| matches!(
        vma.kind(),
        GuestVmaKind::ElfLoad {
            program_header_index: 1,
            ..
        }
    ) && vma.start()
        == DEFAULT_POSITION_INDEPENDENT_EXECUTABLE_BASE));

    let auxv = image.initial_stack().auxv_entries();
    assert_eq!(
        auxv_value(auxv, auxv::AT_PHDR),
        DEFAULT_POSITION_INDEPENDENT_EXECUTABLE_BASE + 0x40
    );
    assert_eq!(
        auxv_value(auxv, auxv::AT_BASE),
        DEFAULT_INTERPRETER_LOAD_BASE
    );
    assert_eq!(
        auxv_value(auxv, auxv::AT_ENTRY),
        DEFAULT_POSITION_INDEPENDENT_EXECUTABLE_BASE + 0x1010
    );
    assert_eq!(auxv_value(auxv, auxv::AT_SECURE), 0);
    assert_eq!(
        auxv_value(auxv, auxv::AT_CLKTCK),
        DEFAULT_CLOCK_TICKS_PER_SECOND
    );
    assert_eq!(auxv_value(auxv, auxv::AT_UID), 0);
    assert_eq!(auxv_value(auxv, auxv::AT_EUID), 0);
    assert_eq!(auxv_value(auxv, auxv::AT_GID), 0);
    assert_eq!(auxv_value(auxv, auxv::AT_EGID), 0);
}

#[test]
fn dynamic_image_requires_interpreter_bytes() {
    let interpreter_path = b"/lib/ld-musl-x86_64.so.1\0";
    let executable = Elf64Builder::new()
        .object_type(TEST_ET_DYN)
        .entrypoint(0x1010)
        .program_header(Elf64ProgramHeader::new(
            TEST_PT_INTERP,
            TEST_PF_R,
            0x300,
            0,
            interpreter_path.len() as u64,
            interpreter_path.len() as u64,
            1,
        ))
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_X,
            0,
            0,
            0x1000,
            0x2000,
        ))
        .data_at(0x300, interpreter_path.to_vec())
        .build();
    let plan = parse_load_plan(&executable).expect("dynamic ELF should parse");

    assert_eq!(
        build_guest_memory_image(
            &plan,
            &executable,
            InitialStackConfig::new(0x8000_0000, 0x4000, b"/bin/sh".to_vec()),
        ),
        Err(GuestImageError::MissingInterpreterBytes)
    );
}

#[test]
fn rejects_initial_stack_when_phdr_address_is_unavailable() {
    let elf = Elf64Builder::new()
        .entrypoint(0x401000)
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_X,
            0x1000,
            0x401000,
            0x20,
            0x20,
        ))
        .data_at(0x1000, vec![0xcc; 0x20])
        .build();
    let plan = parse_load_plan(&elf).expect("valid static ELF should parse");

    assert_eq!(
        build_initial_stack(
            &plan,
            InitialStackConfig::new(0x8000_0000, 0x4000, b"/bin/app".to_vec())
        ),
        Err(InitialStackError::MissingProgramHeaderAddress)
    );
}

fn read_stack_u64(stack: &super::InitialStack, guest_address: u64) -> u64 {
    let bytes = read_stack_bytes(stack, guest_address, 8);
    u64::from_le_bytes(bytes.try_into().unwrap())
}

fn read_stack_bytes(stack: &super::InitialStack, guest_address: u64, len: usize) -> &[u8] {
    let offset = usize::try_from(guest_address - stack.stack_pointer()).unwrap();
    &stack.bytes()[offset..offset + len]
}

fn read_stack_c_string(stack: &super::InitialStack, guest_address: u64) -> &[u8] {
    let start = usize::try_from(guest_address - stack.stack_pointer()).unwrap();
    let end = stack.bytes()[start..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|offset| start + offset)
        .expect("NUL terminator");
    &stack.bytes()[start..end]
}

fn auxv_value(entries: &[AuxiliaryVectorEntry], key: u64) -> u64 {
    entries
        .iter()
        .find(|entry| entry.key() == key)
        .unwrap_or_else(|| panic!("missing auxv key {key}"))
        .value()
}

#[test]
fn rejects_malformed_magic() {
    let mut elf = Elf64Builder::new()
        .entrypoint(0x401000)
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_X,
            0x1000,
            0x401000,
            0x20,
            0x20,
        ))
        .data_at(0x1000, vec![0xcc; 0x20])
        .build();
    elf[0] = 0;

    assert_eq!(parse_load_plan(&elf), Err(ElfValidationError::InvalidMagic));
    assert!(!is_elf64(&elf));
}

#[test]
fn rejects_unsupported_architecture() {
    let mut elf = Elf64Builder::new()
        .entrypoint(0x401000)
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_X,
            0x1000,
            0x401000,
            0x20,
            0x20,
        ))
        .data_at(0x1000, vec![0xcc; 0x20])
        .build();
    elf[18..20].copy_from_slice(&183_u16.to_le_bytes());

    assert_eq!(
        parse_load_plan(&elf),
        Err(ElfValidationError::UnsupportedMachine { value: 183 })
    );
}

#[test]
fn rejects_segment_file_size_larger_than_memory_size() {
    let elf = Elf64Builder::new()
        .entrypoint(0x401000)
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_X,
            0x1000,
            0x401000,
            0x21,
            0x20,
        ))
        .data_at(0x1000, vec![0xcc; 0x21])
        .build();

    assert_eq!(
        parse_load_plan(&elf),
        Err(ElfValidationError::SegmentFileSizeExceedsMemorySize {
            index: 0,
            file_size: 0x21,
            memory_size: 0x20,
        })
    );
}

#[test]
fn rejects_entrypoint_outside_executable_segment() {
    let elf = Elf64Builder::new()
        .entrypoint(0x402000)
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_X,
            0x1000,
            0x401000,
            0x20,
            0x20,
        ))
        .data_at(0x1000, vec![0xcc; 0x20])
        .build();

    assert_eq!(
        parse_load_plan(&elf),
        Err(ElfValidationError::EntrypointNotExecutable {
            entrypoint: 0x402000,
        })
    );
}

#[test]
fn rejects_unterminated_interpreter() {
    let interpreter = b"/lib64/ld-linux-x86-64.so.2";
    let elf = Elf64Builder::new()
        .entrypoint(0x401000)
        .program_header(Elf64ProgramHeader::new(
            TEST_PT_INTERP,
            TEST_PF_R,
            0x300,
            0,
            interpreter.len() as u64,
            interpreter.len() as u64,
            1,
        ))
        .program_header(Elf64ProgramHeader::load(
            TEST_PF_R | TEST_PF_X,
            0x1000,
            0x401000,
            0x20,
            0x20,
        ))
        .data_at(0x300, interpreter.to_vec())
        .data_at(0x1000, vec![0xcc; 0x20])
        .build();

    assert_eq!(
        parse_load_plan(&elf),
        Err(ElfValidationError::UnterminatedInterpreter { index: 0 })
    );
}
