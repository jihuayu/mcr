use mcr_sys::{
    LINUX_MAP_ANONYMOUS, LINUX_MAP_FIXED, LINUX_MAP_FIXED_NOREPLACE, LINUX_MAP_PRIVATE,
    LINUX_MAP_SHARED, LINUX_PROT_EXEC, LINUX_PROT_READ, LINUX_PROT_WRITE, MemorySyscalls,
    MmapSyscallArgs, MprotectSyscallArgs, MunmapSyscallArgs, Syscall, SyscallArgs, SyscallRequest,
};

use super::{
    GUEST_PAGE_SIZE, GuestLibcIntrinsic, GuestLibcIntrinsicError, GuestMemory, GuestMemoryError,
    GuestMemoryProtection, GuestVmaKind,
};

const BRK_BASE: u64 = 0x0100_0000;
const MMAP_BASE: u64 = 0x0200_0000;
const ADDRESS_END: u64 = 0x0400_0000;

fn memory() -> GuestMemory {
    GuestMemory::with_layout(BRK_BASE, MMAP_BASE, ADDRESS_END).unwrap()
}

fn anonymous(addr: u64, length: u64, prot: u32, flags: u32) -> MmapSyscallArgs {
    MmapSyscallArgs {
        addr,
        length,
        prot,
        flags: flags | LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        fd: -1,
        offset: 0,
    }
}

#[test]
fn mmap_places_anonymous_mapping_and_detects_overlap() {
    let mut memory = memory();
    let addr = memory
        .mmap(anonymous(0, GUEST_PAGE_SIZE, LINUX_PROT_READ, 0))
        .unwrap();

    assert_eq!(addr, MMAP_BASE);
    assert_eq!(memory.vmas().count(), 1);
    assert_eq!(
        memory.vma_containing(addr).unwrap().protection(),
        GuestMemoryProtection::new(true, false, false)
    );

    let overlap = memory.mmap(anonymous(
        addr,
        GUEST_PAGE_SIZE,
        LINUX_PROT_READ,
        LINUX_MAP_FIXED_NOREPLACE,
    ));

    assert_eq!(overlap, Err(GuestMemoryError::AddressInUse));
}

#[test]
fn mmap_fixed_replaces_overlapping_mapping() {
    let mut memory = memory();
    let addr = memory
        .mmap(anonymous(0, GUEST_PAGE_SIZE * 2, LINUX_PROT_READ, 0))
        .unwrap();
    memory.write(addr, b"a").unwrap_err();

    let fixed = memory
        .mmap(anonymous(
            addr,
            GUEST_PAGE_SIZE,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_FIXED,
        ))
        .unwrap();

    assert_eq!(fixed, addr);
    memory.write(addr, b"b").unwrap();
    assert_eq!(memory.vmas().count(), 2);
}

#[test]
fn intrinsic_memory_primitives_preserve_guest_access_rules_and_overlap() {
    let mut memory = memory();
    let addr = memory
        .mmap(anonymous(
            0,
            GUEST_PAGE_SIZE,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            0,
        ))
        .unwrap();

    memory.intrinsic_memset(addr, b'a', 8).unwrap();
    assert_eq!(memory.intrinsic_memchr(addr, b'a', 8).unwrap(), Some(addr));
    assert_eq!(memory.intrinsic_memchr(addr, b'z', 8).unwrap(), None);

    memory.write(addr, b"abcdef\0tail").unwrap();
    memory.intrinsic_memmove(addr + 2, addr, 6).unwrap();
    let mut moved = [0; 8];
    memory.read(addr, &mut moved).unwrap();
    assert_eq!(&moved, b"ababcdef");
    assert_eq!(memory.intrinsic_memcmp(addr + 2, addr + 2, 3).unwrap(), 0);
    assert!(memory.intrinsic_memcmp(addr, addr + 5, 3).unwrap() < 0);
    assert_eq!(memory.intrinsic_strlen(addr, 12).unwrap(), Some(11));

    memory
        .mprotect(MprotectSyscallArgs {
            addr,
            length: GUEST_PAGE_SIZE,
            prot: LINUX_PROT_READ,
        })
        .unwrap();
    assert_eq!(
        memory.intrinsic_memset(addr, 0, 1),
        Err(GuestMemoryError::AccessDenied)
    );
}

#[test]
fn libc_intrinsic_dispatch_uses_sysv_register_arguments_and_abi_returns() {
    let mut memory = memory();
    let addr = memory
        .mmap(anonymous(
            0,
            GUEST_PAGE_SIZE,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            0,
        ))
        .unwrap();
    let src = addr;
    let dst = addr + 32;
    let other = addr + 64;
    memory.write(src, b"abc\0tail").unwrap();
    memory.write(other, b"abd\0tail").unwrap();

    assert_eq!(
        memory
            .dispatch_libc_intrinsic(GuestLibcIntrinsic::Memcpy, dst, src, 3)
            .unwrap(),
        dst
    );
    let mut copied = [0; 3];
    memory.read(dst, &mut copied).unwrap();
    assert_eq!(&copied, b"abc");

    assert_eq!(
        memory
            .dispatch_libc_intrinsic(GuestLibcIntrinsic::Memset, dst + 3, b'x'.into(), 2)
            .unwrap(),
        dst + 3
    );
    assert_eq!(
        memory
            .dispatch_libc_intrinsic(GuestLibcIntrinsic::Memchr, src, b'b'.into(), 4)
            .unwrap(),
        src + 1
    );
    assert_eq!(
        memory
            .dispatch_libc_intrinsic(GuestLibcIntrinsic::Strlen { max_len: 16 }, src, 0, 0)
            .unwrap(),
        3
    );
    assert_eq!(
        memory
            .dispatch_libc_intrinsic(GuestLibcIntrinsic::Memcmp, src, other, 3)
            .unwrap() as i64,
        -1
    );

    assert_eq!(
        memory.dispatch_libc_intrinsic(GuestLibcIntrinsic::Memcpy, src + 1, src, 3),
        Err(GuestLibcIntrinsicError::UnsupportedOverlap)
    );
    assert_eq!(
        memory.dispatch_libc_intrinsic(GuestLibcIntrinsic::Strlen { max_len: 2 }, src, 0, 0),
        Err(GuestLibcIntrinsicError::UnterminatedString)
    );
}

#[test]
fn libc_intrinsic_symbol_classifier_accepts_versioned_libc_names() {
    assert_eq!(
        GuestLibcIntrinsic::from_symbol_name("memcpy"),
        Some(GuestLibcIntrinsic::Memcpy)
    );
    assert_eq!(
        GuestLibcIntrinsic::from_symbol_name("memset@@GLIBC_2.2.5"),
        Some(GuestLibcIntrinsic::Memset)
    );
    assert_eq!(
        GuestLibcIntrinsic::from_symbol_name("strlen@GLIBC_2.2.5"),
        Some(GuestLibcIntrinsic::Strlen {
            max_len: super::DEFAULT_LIBC_STRLEN_MAX
        })
    );
    assert_eq!(GuestLibcIntrinsic::from_symbol_name("strcpy"), None);
}

#[test]
fn mprotect_updates_permissions_and_splits_vmas() {
    let mut memory = memory();
    let addr = memory
        .mmap(anonymous(
            0,
            GUEST_PAGE_SIZE * 3,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            0,
        ))
        .unwrap();
    memory.write(addr + GUEST_PAGE_SIZE, b"x").unwrap();

    memory
        .mprotect(MprotectSyscallArgs {
            addr: addr + GUEST_PAGE_SIZE,
            length: GUEST_PAGE_SIZE,
            prot: LINUX_PROT_READ,
        })
        .unwrap();

    assert_eq!(memory.vmas().count(), 3);
    assert_eq!(
        memory.write(addr + GUEST_PAGE_SIZE, b"y"),
        Err(GuestMemoryError::AccessDenied)
    );
    let mut byte = [0];
    memory.read(addr + GUEST_PAGE_SIZE, &mut byte).unwrap();
    assert_eq!(byte, [b'x']);
}

#[test]
fn patch_code_fixed_updates_executable_bytes_and_restores_protection() {
    let mut memory = memory();
    let addr = memory
        .mmap(anonymous(
            0,
            GUEST_PAGE_SIZE,
            LINUX_PROT_READ | LINUX_PROT_EXEC,
            0,
        ))
        .unwrap();

    memory
        .patch_code_fixed([(addr, [0xcc, 0x90]), (addr + 8, [0x90, 0xcc])])
        .unwrap();

    let mut bytes = [0; 10];
    memory.read(addr, &mut bytes).unwrap();
    assert_eq!(bytes[..2], [0xcc, 0x90]);
    assert_eq!(bytes[8..10], [0x90, 0xcc]);
    assert_eq!(
        memory.write(addr, b"x"),
        Err(GuestMemoryError::AccessDenied)
    );
}

#[test]
fn munmap_removes_middle_range_and_keeps_remaining_bytes() {
    let mut memory = memory();
    let addr = memory
        .mmap(anonymous(
            0,
            GUEST_PAGE_SIZE * 3,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            0,
        ))
        .unwrap();
    memory.write(addr, b"l").unwrap();
    memory.write(addr + GUEST_PAGE_SIZE * 2, b"r").unwrap();

    memory
        .munmap(MunmapSyscallArgs {
            addr: addr + GUEST_PAGE_SIZE,
            length: GUEST_PAGE_SIZE,
        })
        .unwrap();

    assert_eq!(memory.vmas().count(), 2);
    assert_eq!(
        memory.read(addr + GUEST_PAGE_SIZE, &mut [0]),
        Err(GuestMemoryError::NotMapped)
    );
    let mut bytes = [0, 0];
    memory.read(addr, &mut bytes[..1]).unwrap();
    memory
        .read(addr + GUEST_PAGE_SIZE * 2, &mut bytes[1..])
        .unwrap();
    assert_eq!(bytes, [b'l', b'r']);
}

#[test]
fn anonymous_mmap_zero_fills_reused_unmapped_range() {
    let mut memory = memory();
    let addr = memory
        .mmap(anonymous(
            0,
            GUEST_PAGE_SIZE * 3,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            0,
        ))
        .unwrap();
    let middle = addr + GUEST_PAGE_SIZE;
    memory.write(addr, b"l").unwrap();
    memory.write(middle, b"stale").unwrap();
    memory.write(addr + GUEST_PAGE_SIZE * 2, b"r").unwrap();
    memory
        .mprotect(MprotectSyscallArgs {
            addr,
            length: GUEST_PAGE_SIZE,
            prot: LINUX_PROT_READ,
        })
        .unwrap();
    memory
        .munmap(MunmapSyscallArgs {
            addr: middle,
            length: GUEST_PAGE_SIZE,
        })
        .unwrap();

    let remapped = memory
        .mmap(anonymous(
            middle,
            GUEST_PAGE_SIZE,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_FIXED,
        ))
        .unwrap();

    assert_eq!(remapped, middle);
    let mut zeroes = [0xff; 5];
    memory.read(middle, &mut zeroes).unwrap();
    assert_eq!(zeroes, [0; 5]);
    assert_eq!(
        memory.write(addr, b"x"),
        Err(GuestMemoryError::AccessDenied)
    );
    let mut preserved = [0, 0];
    memory.read(addr, &mut preserved[..1]).unwrap();
    memory
        .read(addr + GUEST_PAGE_SIZE * 2, &mut preserved[1..])
        .unwrap();
    assert_eq!(preserved, [b'l', b'r']);
}

#[test]
fn try_clone_runtime_preserves_mappings_and_isolates_writes() {
    let mut memory = memory();
    let addr = memory
        .mmap(anonymous(
            0,
            GUEST_PAGE_SIZE,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            0,
        ))
        .unwrap();
    memory.write(addr, b"parent").unwrap();

    let mut clone = memory.try_clone_runtime().unwrap();
    clone.write(addr, b"child!").unwrap();

    let mut parent_bytes = [0; 6];
    memory.read(addr, &mut parent_bytes).unwrap();
    let mut child_bytes = [0; 6];
    clone.read(addr, &mut child_bytes).unwrap();

    assert_eq!(&parent_bytes, b"parent");
    assert_eq!(&child_bytes, b"child!");
}

#[test]
fn try_clone_runtime_reuses_read_only_allocations_until_writeable() {
    let mut memory = memory();
    let addr = MMAP_BASE;
    memory
        .insert_loaded_mapping(
            addr,
            GUEST_PAGE_SIZE,
            GuestMemoryProtection::new(true, false, true),
            &vec![b'p'; GUEST_PAGE_SIZE as usize],
        )
        .unwrap();
    let allocation_id = memory.vma_containing(addr).unwrap().allocation_id;

    let mut clone = memory.try_clone_runtime().unwrap();

    assert!(std::sync::Arc::ptr_eq(
        &memory.allocations.get(&allocation_id).unwrap().memory,
        &clone.allocations.get(&allocation_id).unwrap().memory
    ));

    clone
        .mprotect(MprotectSyscallArgs {
            addr,
            length: GUEST_PAGE_SIZE,
            prot: LINUX_PROT_READ | LINUX_PROT_WRITE,
        })
        .unwrap();
    clone.write(addr, b"child").unwrap();

    let clone_allocation_id = clone.vma_containing(addr).unwrap().allocation_id;
    assert!(!std::sync::Arc::ptr_eq(
        &memory.allocations.get(&allocation_id).unwrap().memory,
        &clone.allocations.get(&clone_allocation_id).unwrap().memory
    ));
    let mut parent = [0; 5];
    let mut child = [0; 5];
    memory.read(addr, &mut parent).unwrap();
    clone.read(addr, &mut child).unwrap();
    assert_eq!(&parent, b"ppppp");
    assert_eq!(&child, b"child");
}

#[test]
fn try_clone_runtime_detaches_only_mutated_read_only_pages() {
    let mut memory = memory();
    let addr = MMAP_BASE;
    memory
        .insert_loaded_mapping(
            addr,
            GUEST_PAGE_SIZE * 3,
            GuestMemoryProtection::new(true, false, false),
            &vec![b'p'; (GUEST_PAGE_SIZE * 3) as usize],
        )
        .unwrap();
    let parent_allocation_id = memory.vma_containing(addr).unwrap().allocation_id;

    let mut clone = memory.try_clone_runtime().unwrap();
    let middle = addr + GUEST_PAGE_SIZE;
    clone
        .mprotect(MprotectSyscallArgs {
            addr: middle,
            length: GUEST_PAGE_SIZE,
            prot: LINUX_PROT_READ | LINUX_PROT_WRITE,
        })
        .unwrap();
    clone.write(middle, b"child").unwrap();

    let clone_left_id = clone.vma_containing(addr).unwrap().allocation_id;
    let clone_middle_id = clone.vma_containing(middle).unwrap().allocation_id;
    let clone_right_id = clone
        .vma_containing(addr + GUEST_PAGE_SIZE * 2)
        .unwrap()
        .allocation_id;
    let parent_memory = &memory
        .allocations
        .get(&parent_allocation_id)
        .unwrap()
        .memory;
    assert!(std::sync::Arc::ptr_eq(
        parent_memory,
        &clone.allocations.get(&clone_left_id).unwrap().memory
    ));
    assert!(!std::sync::Arc::ptr_eq(
        parent_memory,
        &clone.allocations.get(&clone_middle_id).unwrap().memory
    ));
    assert!(std::sync::Arc::ptr_eq(
        parent_memory,
        &clone.allocations.get(&clone_right_id).unwrap().memory
    ));

    let mut parent = [0; 5];
    let mut child = [0; 5];
    memory.read(middle, &mut parent).unwrap();
    clone.read(middle, &mut child).unwrap();
    assert_eq!(&parent, b"ppppp");
    assert_eq!(&child, b"child");
}

#[test]
fn try_clone_runtime_preserves_split_vma_protections() {
    let mut memory = memory();
    let addr = memory
        .mmap(anonymous(
            0,
            GUEST_PAGE_SIZE * 3,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            0,
        ))
        .unwrap();
    memory.write(addr, b"left").unwrap();
    memory.write(addr + GUEST_PAGE_SIZE * 2, b"right").unwrap();
    memory
        .mprotect(MprotectSyscallArgs {
            addr: addr + GUEST_PAGE_SIZE,
            length: GUEST_PAGE_SIZE,
            prot: LINUX_PROT_READ,
        })
        .unwrap();

    let mut clone = memory.try_clone_runtime().unwrap();

    assert_eq!(clone.vmas().count(), 3);
    assert_eq!(
        clone.write(addr + GUEST_PAGE_SIZE, b"x"),
        Err(GuestMemoryError::AccessDenied)
    );
    let mut bytes = [0; 9];
    clone.read(addr, &mut bytes[..4]).unwrap();
    clone
        .read(addr + GUEST_PAGE_SIZE * 2, &mut bytes[4..])
        .unwrap();
    assert_eq!(&bytes, b"leftright");
}

#[test]
fn invalid_memory_addresses_and_flags_are_rejected() {
    let mut memory = memory();

    assert_eq!(
        memory.mmap(anonymous(
            123,
            GUEST_PAGE_SIZE,
            LINUX_PROT_READ,
            LINUX_MAP_FIXED
        )),
        Err(GuestMemoryError::InvalidAddress)
    );
    assert_eq!(
        memory.munmap(MunmapSyscallArgs {
            addr: 123,
            length: GUEST_PAGE_SIZE
        }),
        Err(GuestMemoryError::InvalidAddress)
    );
    assert_eq!(
        memory.mprotect(MprotectSyscallArgs {
            addr: MMAP_BASE,
            length: GUEST_PAGE_SIZE,
            prot: LINUX_PROT_READ
        }),
        Err(GuestMemoryError::NotMapped)
    );
    assert_eq!(
        memory.mmap(anonymous(0, GUEST_PAGE_SIZE, 0x8000, 0)),
        Err(GuestMemoryError::InvalidProtection)
    );
}

#[test]
fn brk_grows_shrinks_and_preserves_heap_data() {
    let mut memory = memory();

    assert_eq!(memory.set_brk(0).current, BRK_BASE);
    assert_eq!(memory.set_brk(BRK_BASE + 16).current, BRK_BASE + 16);
    memory.write(BRK_BASE, b"heap").unwrap();
    assert_eq!(
        memory.vma_containing(BRK_BASE).unwrap().kind(),
        &GuestVmaKind::Heap
    );

    assert_eq!(
        memory.set_brk(BRK_BASE + GUEST_PAGE_SIZE + 8).current,
        BRK_BASE + GUEST_PAGE_SIZE + 8
    );
    let mut bytes = [0; 4];
    memory.read(BRK_BASE, &mut bytes).unwrap();
    assert_eq!(&bytes, b"heap");

    assert_eq!(memory.set_brk(BRK_BASE + 1).current, BRK_BASE + 1);
    assert!(memory.vma_containing(BRK_BASE).is_some());
    assert_eq!(memory.set_brk(BRK_BASE).current, BRK_BASE);
    assert!(memory.vma_containing(BRK_BASE).is_none());
}

#[test]
fn brk_growth_fails_when_it_would_overlap_another_vma() {
    let mut memory = memory();
    memory
        .mmap(anonymous(
            BRK_BASE + GUEST_PAGE_SIZE,
            GUEST_PAGE_SIZE,
            LINUX_PROT_READ,
            LINUX_MAP_FIXED,
        ))
        .unwrap();

    let outcome = memory.set_brk(BRK_BASE + GUEST_PAGE_SIZE * 2);

    assert_eq!(outcome.current, BRK_BASE);
    assert_eq!(outcome.error, Some(GuestMemoryError::OutOfMemory));
}

#[cfg(windows)]
#[test]
fn brk_growth_reuses_fixed_allocation_tail_after_native_clone() {
    let brk_base = 0x0100_1000;
    let mut memory = GuestMemory::with_layout(brk_base, MMAP_BASE, ADDRESS_END).unwrap();
    memory
        .insert_loaded_mapping(
            0x0100_0000,
            GUEST_PAGE_SIZE,
            GuestMemoryProtection::new(true, false, true),
            &[0x7f; GUEST_PAGE_SIZE as usize],
        )
        .unwrap();
    let mut memory = memory.try_clone_runtime_at_guest_addresses().unwrap();

    let outcome = memory.set_brk(brk_base + GUEST_PAGE_SIZE);

    assert_eq!(outcome.current, brk_base + GUEST_PAGE_SIZE);
    assert_eq!(outcome.error, None);
    memory.write(brk_base, b"heap").unwrap();
    let mut loaded = [0];
    memory.read(0x0100_0000, &mut loaded).unwrap();
    assert_eq!(loaded, [0x7f]);
}

#[test]
fn file_backed_mmap_is_zero_filled_and_guest_local() {
    let mut memory = memory();
    let addr = memory
        .mmap(MmapSyscallArgs {
            addr: 0,
            length: GUEST_PAGE_SIZE,
            prot: LINUX_PROT_READ | LINUX_PROT_WRITE,
            flags: LINUX_MAP_SHARED,
            fd: 3,
            offset: 0,
        })
        .unwrap();

    assert!(matches!(
        memory.vma_containing(addr).unwrap().kind(),
        GuestVmaKind::FileBacked {
            fd: 3,
            offset: 0,
            shared: true
        }
    ));
    let mut byte = [1];
    memory.read(addr, &mut byte).unwrap();
    assert_eq!(byte, [0]);
    memory.write(addr, b"x").unwrap();
    memory.read(addr, &mut byte).unwrap();
    assert_eq!(byte, [b'x']);
}

#[test]
fn memory_syscall_dispatch_returns_linux_results() {
    let mut memory = memory();
    let request = SyscallRequest {
        context: mcr_sys::TraceContext {
            pid: 1,
            tid: 1,
            rip: 0,
        },
        syscall: Syscall::Mmap,
        number: Syscall::MMAP,
        args: SyscallArgs::new([
            0,
            GUEST_PAGE_SIZE,
            u64::from(LINUX_PROT_READ | LINUX_PROT_EXEC),
            u64::from(LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS),
            u64::MAX,
            0,
        ]),
    };

    let outcome = memory.dispatch_memory(&request);

    assert_eq!(outcome.result, mcr_sys::SyscallReturn::success(MMAP_BASE));
}

#[test]
fn madvise_accepts_common_hints_and_rejects_invalid_arguments() {
    let memory = memory();

    assert_eq!(memory.madvise(MMAP_BASE, GUEST_PAGE_SIZE, 0), Ok(0));
    assert_eq!(memory.madvise(MMAP_BASE, 0, 4), Ok(0));
    assert_eq!(memory.madvise(MMAP_BASE, GUEST_PAGE_SIZE, 8), Ok(0));
    assert_eq!(memory.madvise(MMAP_BASE, GUEST_PAGE_SIZE, 25), Ok(0));
    assert_eq!(memory.madvise(MMAP_BASE, GUEST_PAGE_SIZE, 100), Ok(0));
    assert_eq!(memory.madvise(MMAP_BASE, GUEST_PAGE_SIZE, 101), Ok(0));
    assert_eq!(
        memory.madvise(MMAP_BASE + 1, GUEST_PAGE_SIZE, 0),
        Err(GuestMemoryError::InvalidAddress)
    );
    assert_eq!(
        memory.madvise(MMAP_BASE, GUEST_PAGE_SIZE, 0xffff),
        Err(GuestMemoryError::InvalidFlags)
    );
    assert_eq!(
        memory.madvise(!(GUEST_PAGE_SIZE - 1), GUEST_PAGE_SIZE * 2, 0),
        Err(GuestMemoryError::InvalidLength)
    );
}
