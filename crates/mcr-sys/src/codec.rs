use std::time::Duration;

use crate::{
    LINUX_AF_INET, LINUX_AF_INET6, LINUX_POLLIN, LINUX_POLLOUT, LINUX_POLLPRI, LINUX_POLLRDNORM,
    LINUX_POLLWRNORM, LinuxErrno, LinuxIovec, LinuxMsghdr, LinuxPollfd, LinuxTimespec,
};

pub const LINUX_IOV_MAX: usize = 1024;
pub const LINUX_MAX_C_STRING_LEN: usize = 4096;
pub const LINUX_MAX_VECTOR_ITEMS: usize = 4096;
pub const LINUX_MAX_SELECT_FDS: usize = 4096;
pub const LINUX_SELECT_FD_BITS: usize = 64;
pub const LINUX_SOCKADDR_IN_LEN: usize = 16;
pub const LINUX_SOCKADDR_IN6_LEN: usize = 28;

pub trait GuestMemoryAccess {
    fn read_bytes(&self, addr: u64, buffer: &mut [u8]) -> Result<(), GuestMemoryAccessError>;
    fn write_bytes(&mut self, addr: u64, buffer: &[u8]) -> Result<(), GuestMemoryAccessError>;

    fn read_c_string(&self, addr: u64, max_len: usize) -> Result<String, GuestMemoryAccessError> {
        let mut bytes = Vec::new();
        for offset in 0..max_len {
            let mut byte = [0];
            self.read_bytes(
                addr.checked_add(offset as u64)
                    .ok_or(GuestMemoryAccessError::Fault)?,
                &mut byte,
            )?;
            if byte[0] == 0 {
                return String::from_utf8(bytes).map_err(|_| GuestMemoryAccessError::Fault);
            }
            bytes.push(byte[0]);
        }
        Err(GuestMemoryAccessError::Fault)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestMemoryAccessError {
    Fault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxSocketAddress {
    Inet {
        address: [u8; 4],
        port: u16,
    },
    Inet6 {
        address: [u8; 16],
        port: u16,
        flowinfo: u32,
        scope_id: u32,
    },
}

impl LinuxSocketAddress {
    #[must_use]
    pub const fn inet(address: [u8; 4], port: u16) -> Self {
        Self::Inet { address, port }
    }

    #[must_use]
    pub const fn inet6(address: [u8; 16], port: u16, flowinfo: u32, scope_id: u32) -> Self {
        Self::Inet6 {
            address,
            port,
            flowinfo,
            scope_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSelectInterest {
    pub fd: i32,
    pub events: i16,
    pub read: bool,
    pub write: bool,
    pub exceptional: bool,
}

pub fn memory_errno<E>(_error: E) -> LinuxErrno {
    LinuxErrno::EFAULT
}

pub fn read_guest_u32(memory: &impl GuestMemoryAccess, addr: u64) -> Result<u32, LinuxErrno> {
    let mut bytes = [0; 4];
    memory.read_bytes(addr, &mut bytes).map_err(memory_errno)?;
    Ok(u32::from_le_bytes(bytes))
}

pub fn write_guest_u32(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    value: u32,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(addr, &value.to_le_bytes())
        .map_err(memory_errno)
}

pub fn read_guest_i64(memory: &impl GuestMemoryAccess, addr: u64) -> Result<i64, LinuxErrno> {
    let mut bytes = [0; 8];
    memory.read_bytes(addr, &mut bytes).map_err(memory_errno)?;
    Ok(i64::from_le_bytes(bytes))
}

pub fn read_guest_u64(memory: &impl GuestMemoryAccess, addr: u64) -> Result<u64, LinuxErrno> {
    let mut bytes = [0; 8];
    memory.read_bytes(addr, &mut bytes).map_err(memory_errno)?;
    Ok(u64::from_le_bytes(bytes))
}

pub fn read_guest_c_bytes(
    memory: &impl GuestMemoryAccess,
    addr: u64,
) -> Result<Vec<u8>, LinuxErrno> {
    let mut bytes = Vec::new();
    for offset in 0..LINUX_MAX_C_STRING_LEN {
        let mut byte = [0];
        memory
            .read_bytes(
                addr.checked_add(offset as u64).ok_or(LinuxErrno::EFAULT)?,
                &mut byte,
            )
            .map_err(memory_errno)?;
        if byte[0] == 0 {
            return Ok(bytes);
        }
        bytes.push(byte[0]);
    }
    Err(LinuxErrno::ENAMETOOLONG)
}

pub fn read_guest_vector(
    memory: &impl GuestMemoryAccess,
    vector_addr: u64,
) -> Result<Vec<Vec<u8>>, LinuxErrno> {
    if vector_addr == 0 {
        return Ok(Vec::new());
    }

    let mut values = Vec::new();
    for index in 0..LINUX_MAX_VECTOR_ITEMS {
        let item_addr = vector_addr
            .checked_add((index * 8) as u64)
            .ok_or(LinuxErrno::EFAULT)?;
        let ptr = read_guest_u64(memory, item_addr)?;
        if ptr == 0 {
            return Ok(values);
        }
        values.push(read_guest_c_bytes(memory, ptr)?);
    }
    Err(LinuxErrno::E2BIG)
}

pub fn read_guest_timespec(
    memory: &impl GuestMemoryAccess,
    addr: u64,
) -> Result<LinuxTimespec, LinuxErrno> {
    Ok(LinuxTimespec {
        tv_sec: read_guest_i64(memory, addr)?,
        tv_nsec: read_guest_i64(memory, addr.checked_add(8).ok_or(LinuxErrno::EFAULT)?)?,
    })
}

pub fn write_guest_timespec(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    timespec: LinuxTimespec,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(addr, &timespec.tv_sec.to_le_bytes())
        .map_err(memory_errno)?;
    memory
        .write_bytes(
            addr.checked_add(8).ok_or(LinuxErrno::EFAULT)?,
            &timespec.tv_nsec.to_le_bytes(),
        )
        .map_err(memory_errno)
}

pub fn read_required_timespec_duration(
    memory: &impl GuestMemoryAccess,
    addr: u64,
) -> Result<Duration, LinuxErrno> {
    let timespec = read_guest_timespec(memory, addr)?;
    if timespec.tv_sec < 0 || !(0..1_000_000_000).contains(&timespec.tv_nsec) {
        return Err(LinuxErrno::EINVAL);
    }
    Ok(Duration::new(
        timespec.tv_sec as u64,
        timespec.tv_nsec as u32,
    ))
}

pub fn read_select_timeout(
    memory: &impl GuestMemoryAccess,
    addr: u64,
) -> Result<Option<Duration>, LinuxErrno> {
    if addr == 0 {
        return Ok(None);
    }
    let tv_sec = read_guest_i64(memory, addr)?;
    let tv_usec = read_guest_i64(memory, addr.checked_add(8).ok_or(LinuxErrno::EFAULT)?)?;
    if tv_sec < 0 || !(0..1_000_000).contains(&tv_usec) {
        return Err(LinuxErrno::EINVAL);
    }
    Ok(Some(Duration::new(
        tv_sec as u64,
        u32::try_from(tv_usec * 1_000).map_err(|_| LinuxErrno::EINVAL)?,
    )))
}

pub fn read_pollfd(memory: &impl GuestMemoryAccess, addr: u64) -> Result<LinuxPollfd, LinuxErrno> {
    let mut bytes = [0; std::mem::size_of::<LinuxPollfd>()];
    memory.read_bytes(addr, &mut bytes).map_err(memory_errno)?;
    Ok(LinuxPollfd {
        fd: i32::from_le_bytes(bytes[0..4].try_into().expect("pollfd fd")),
        events: i16::from_le_bytes(bytes[4..6].try_into().expect("pollfd events")),
        revents: i16::from_le_bytes(bytes[6..8].try_into().expect("pollfd revents")),
    })
}

pub fn write_pollfd_revents(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    revents: i16,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(
            addr.checked_add(6).ok_or(LinuxErrno::EFAULT)?,
            &revents.to_le_bytes(),
        )
        .map_err(memory_errno)
}

pub fn select_nfds(raw: u64) -> Result<usize, LinuxErrno> {
    let signed = raw as i64;
    if signed < 0 {
        return Err(LinuxErrno::EINVAL);
    }
    let nfds = usize::try_from(signed).map_err(|_| LinuxErrno::EINVAL)?;
    if nfds > LINUX_MAX_SELECT_FDS {
        return Err(LinuxErrno::EINVAL);
    }
    Ok(nfds)
}

pub fn read_select_interests(
    memory: &impl GuestMemoryAccess,
    nfds: usize,
    readfds_addr: u64,
    writefds_addr: u64,
    exceptfds_addr: u64,
) -> Result<Vec<LinuxSelectInterest>, LinuxErrno> {
    let mut interests = Vec::new();
    for fd in 0..nfds {
        let read = select_fd_set_contains(memory, readfds_addr, fd)?;
        let write = select_fd_set_contains(memory, writefds_addr, fd)?;
        let exceptional = select_fd_set_contains(memory, exceptfds_addr, fd)?;
        if !read && !write && !exceptional {
            continue;
        }
        let mut events = 0;
        if read {
            events |= LINUX_POLLIN | LINUX_POLLRDNORM;
        }
        if write {
            events |= LINUX_POLLOUT | LINUX_POLLWRNORM;
        }
        if exceptional {
            events |= LINUX_POLLPRI;
        }
        interests.push(LinuxSelectInterest {
            fd: i32::try_from(fd).map_err(|_| LinuxErrno::EINVAL)?,
            events,
            read,
            write,
            exceptional,
        });
    }
    Ok(interests)
}

pub fn select_fd_set_contains(
    memory: &impl GuestMemoryAccess,
    set_addr: u64,
    fd: usize,
) -> Result<bool, LinuxErrno> {
    if set_addr == 0 {
        return Ok(false);
    }
    let word_addr = select_fd_word_addr(set_addr, fd)?;
    let word = read_guest_u64(memory, word_addr)?;
    Ok(word & select_fd_bit(fd) != 0)
}

pub fn write_select_fd_set(
    memory: &mut impl GuestMemoryAccess,
    set_addr: u64,
    nfds: usize,
    fds: &[i32],
) -> Result<(), LinuxErrno> {
    if set_addr == 0 {
        return Ok(());
    }
    write_zeroed(memory, set_addr, select_fd_set_len(nfds)?)?;
    for fd in fds {
        if *fd < 0 {
            continue;
        }
        let fd = usize::try_from(*fd).map_err(|_| LinuxErrno::EINVAL)?;
        if fd >= nfds {
            continue;
        }
        let word_addr = select_fd_word_addr(set_addr, fd)?;
        let word = read_guest_u64(memory, word_addr)? | select_fd_bit(fd);
        memory
            .write_bytes(word_addr, &word.to_le_bytes())
            .map_err(memory_errno)?;
    }
    Ok(())
}

pub fn select_fd_set_len(nfds: usize) -> Result<usize, LinuxErrno> {
    nfds.checked_add(LINUX_SELECT_FD_BITS - 1)
        .map(|bits| bits / LINUX_SELECT_FD_BITS * 8)
        .ok_or(LinuxErrno::EINVAL)
}

pub fn write_zeroed(
    memory: &mut impl GuestMemoryAccess,
    addr: u64,
    len: usize,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(addr, &vec![0; len])
        .map_err(memory_errno)
}

pub fn read_iovecs(
    memory: &impl GuestMemoryAccess,
    addr: u64,
    count: usize,
) -> Result<Vec<LinuxIovec>, LinuxErrno> {
    if count > LINUX_IOV_MAX {
        return Err(LinuxErrno::EINVAL);
    }

    let mut iovecs = Vec::with_capacity(count);
    for index in 0..count {
        let item_addr = addr
            .checked_add((index * std::mem::size_of::<LinuxIovec>()) as u64)
            .ok_or(LinuxErrno::EFAULT)?;
        let mut bytes = [0; std::mem::size_of::<LinuxIovec>()];
        memory
            .read_bytes(item_addr, &mut bytes)
            .map_err(memory_errno)?;
        iovecs.push(LinuxIovec {
            iov_base: u64::from_le_bytes(bytes[0..8].try_into().expect("iovec base")),
            iov_len: u64::from_le_bytes(bytes[8..16].try_into().expect("iovec len")),
        });
    }
    Ok(iovecs)
}

pub fn read_iovec_buffers(
    memory: &impl GuestMemoryAccess,
    iovecs: &[LinuxIovec],
) -> Result<Vec<Vec<u8>>, LinuxErrno> {
    let mut buffers = Vec::with_capacity(iovecs.len());
    for iovec in iovecs {
        let len = usize::try_from(iovec.iov_len).map_err(|_| LinuxErrno::EINVAL)?;
        let mut buffer = vec![0; len];
        memory
            .read_bytes(iovec.iov_base, &mut buffer)
            .map_err(memory_errno)?;
        buffers.push(buffer);
    }
    Ok(buffers)
}

pub fn iovec_output_buffers(iovecs: &[LinuxIovec]) -> Result<Vec<Vec<u8>>, LinuxErrno> {
    iovecs
        .iter()
        .map(|iovec| {
            usize::try_from(iovec.iov_len)
                .map(|len| vec![0; len])
                .map_err(|_| LinuxErrno::EINVAL)
        })
        .collect()
}

pub fn write_iovec_buffers(
    memory: &mut impl GuestMemoryAccess,
    iovecs: &[LinuxIovec],
    buffers: &[Vec<u8>],
    bytes_written: usize,
) -> Result<(), LinuxErrno> {
    let mut consumed = 0usize;
    for (iovec, buffer) in iovecs.iter().zip(buffers) {
        let len = usize::try_from(iovec.iov_len).map_err(|_| LinuxErrno::EINVAL)?;
        let remaining = bytes_written.saturating_sub(consumed);
        let write_len = len.min(remaining);
        if write_len > 0 {
            memory
                .write_bytes(iovec.iov_base, &buffer[..write_len])
                .map_err(memory_errno)?;
        }
        consumed += write_len;
        if consumed >= bytes_written {
            break;
        }
    }
    Ok(())
}

pub fn read_msghdr(memory: &impl GuestMemoryAccess, addr: u64) -> Result<LinuxMsghdr, LinuxErrno> {
    let mut bytes = [0; std::mem::size_of::<LinuxMsghdr>()];
    memory.read_bytes(addr, &mut bytes).map_err(memory_errno)?;
    Ok(LinuxMsghdr {
        msg_name: u64::from_le_bytes(bytes[0..8].try_into().expect("msg_name")),
        msg_namelen: u32::from_le_bytes(bytes[8..12].try_into().expect("msg_namelen")),
        __pad1: u32::from_le_bytes(bytes[12..16].try_into().expect("pad1")),
        msg_iov: u64::from_le_bytes(bytes[16..24].try_into().expect("msg_iov")),
        msg_iovlen: u64::from_le_bytes(bytes[24..32].try_into().expect("msg_iovlen")),
        msg_control: u64::from_le_bytes(bytes[32..40].try_into().expect("msg_control")),
        msg_controllen: u64::from_le_bytes(bytes[40..48].try_into().expect("msg_controllen")),
        msg_flags: u32::from_le_bytes(bytes[48..52].try_into().expect("msg_flags")),
        __pad2: u32::from_le_bytes(bytes[52..56].try_into().expect("pad2")),
    })
}

pub fn write_msghdr_namelen(
    memory: &mut impl GuestMemoryAccess,
    msghdr: u64,
    namelen: u32,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(msghdr + 8, &namelen.to_le_bytes())
        .map_err(memory_errno)
}

pub fn write_msghdr_flags(
    memory: &mut impl GuestMemoryAccess,
    msghdr: u64,
    flags: u32,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(msghdr + 48, &flags.to_le_bytes())
        .map_err(memory_errno)
}

pub fn read_socket_address(
    memory: &impl GuestMemoryAccess,
    sockaddr: u64,
    addrlen: u32,
) -> Result<LinuxSocketAddress, LinuxErrno> {
    if addrlen < 2 {
        return Err(LinuxErrno::EINVAL);
    }

    let mut family = [0; 2];
    memory
        .read_bytes(sockaddr, &mut family)
        .map_err(memory_errno)?;
    match u32::from(u16::from_le_bytes(family)) {
        LINUX_AF_INET => {
            if (addrlen as usize) < LINUX_SOCKADDR_IN_LEN {
                return Err(LinuxErrno::EINVAL);
            }
            let mut bytes = [0; LINUX_SOCKADDR_IN_LEN];
            memory
                .read_bytes(sockaddr, &mut bytes)
                .map_err(memory_errno)?;
            Ok(LinuxSocketAddress::inet(
                bytes[4..8].try_into().expect("IPv4 address length"),
                u16::from_be_bytes([bytes[2], bytes[3]]),
            ))
        }
        LINUX_AF_INET6 => {
            if (addrlen as usize) < LINUX_SOCKADDR_IN6_LEN {
                return Err(LinuxErrno::EINVAL);
            }
            let mut bytes = [0; LINUX_SOCKADDR_IN6_LEN];
            memory
                .read_bytes(sockaddr, &mut bytes)
                .map_err(memory_errno)?;
            Ok(LinuxSocketAddress::inet6(
                bytes[8..24].try_into().expect("IPv6 address length"),
                u16::from_be_bytes([bytes[2], bytes[3]]),
                u32::from_le_bytes(bytes[4..8].try_into().expect("flowinfo length")),
                u32::from_le_bytes(bytes[24..28].try_into().expect("scope_id length")),
            ))
        }
        _ => Err(LinuxErrno::EAFNOSUPPORT),
    }
}

pub fn write_socket_address(
    memory: &mut impl GuestMemoryAccess,
    sockaddr: u64,
    addrlen_addr: u64,
    address: LinuxSocketAddress,
) -> Result<(), LinuxErrno> {
    let encoded = encode_socket_address(address);
    let addrlen = read_guest_u32(memory, addrlen_addr)? as usize;
    let write_len = addrlen.min(encoded.len());
    if write_len > 0 {
        memory
            .write_bytes(sockaddr, &encoded[..write_len])
            .map_err(memory_errno)?;
    }
    let actual_len = u32::try_from(encoded.len()).expect("sockaddr length fits socklen_t");
    memory
        .write_bytes(addrlen_addr, &actual_len.to_le_bytes())
        .map_err(memory_errno)
}

pub fn write_optional_socket_address(
    memory: &mut impl GuestMemoryAccess,
    sockaddr: u64,
    addrlen_addr: u64,
    address: LinuxSocketAddress,
) -> Result<(), LinuxErrno> {
    if sockaddr == 0 {
        return Ok(());
    }
    if addrlen_addr == 0 {
        return Err(LinuxErrno::EFAULT);
    }
    write_socket_address(memory, sockaddr, addrlen_addr, address)
}

pub fn write_socket_address_to_msghdr_name(
    memory: &mut impl GuestMemoryAccess,
    msghdr: u64,
    sockaddr: u64,
    addrlen: u32,
    address: LinuxSocketAddress,
) -> Result<(), LinuxErrno> {
    if sockaddr == 0 {
        return Ok(());
    }

    let encoded = encode_socket_address(address);
    let write_len = (addrlen as usize).min(encoded.len());
    if write_len > 0 {
        memory
            .write_bytes(sockaddr, &encoded[..write_len])
            .map_err(memory_errno)?;
    }
    let actual_len = u32::try_from(encoded.len()).expect("sockaddr length fits socklen_t");
    write_msghdr_namelen(memory, msghdr, actual_len)
}

#[must_use]
pub fn encode_socket_address(address: LinuxSocketAddress) -> Vec<u8> {
    match address {
        LinuxSocketAddress::Inet { address, port } => {
            let mut bytes = vec![0; LINUX_SOCKADDR_IN_LEN];
            bytes[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_le_bytes());
            bytes[2..4].copy_from_slice(&port.to_be_bytes());
            bytes[4..8].copy_from_slice(&address);
            bytes
        }
        LinuxSocketAddress::Inet6 {
            address,
            port,
            flowinfo,
            scope_id,
        } => {
            let mut bytes = vec![0; LINUX_SOCKADDR_IN6_LEN];
            bytes[0..2].copy_from_slice(&(LINUX_AF_INET6 as u16).to_le_bytes());
            bytes[2..4].copy_from_slice(&port.to_be_bytes());
            bytes[4..8].copy_from_slice(&flowinfo.to_le_bytes());
            bytes[8..24].copy_from_slice(&address);
            bytes[24..28].copy_from_slice(&scope_id.to_le_bytes());
            bytes
        }
    }
}

fn select_fd_word_addr(set_addr: u64, fd: usize) -> Result<u64, LinuxErrno> {
    set_addr
        .checked_add(((fd / LINUX_SELECT_FD_BITS) * 8) as u64)
        .ok_or(LinuxErrno::EFAULT)
}

fn select_fd_bit(fd: usize) -> u64 {
    1u64 << (fd % LINUX_SELECT_FD_BITS)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[derive(Default)]
    struct TestMemory {
        bytes: BTreeMap<u64, u8>,
    }

    impl TestMemory {
        fn write_raw(&mut self, addr: u64, bytes: &[u8]) {
            for (index, byte) in bytes.iter().copied().enumerate() {
                self.bytes.insert(addr + index as u64, byte);
            }
        }
    }

    impl GuestMemoryAccess for TestMemory {
        fn read_bytes(&self, addr: u64, buffer: &mut [u8]) -> Result<(), GuestMemoryAccessError> {
            for (index, item) in buffer.iter_mut().enumerate() {
                *item = *self
                    .bytes
                    .get(&(addr + index as u64))
                    .ok_or(GuestMemoryAccessError::Fault)?;
            }
            Ok(())
        }

        fn write_bytes(&mut self, addr: u64, buffer: &[u8]) -> Result<(), GuestMemoryAccessError> {
            self.write_raw(addr, buffer);
            Ok(())
        }
    }

    #[test]
    fn string_vector_codec_reads_null_terminated_values() {
        let mut memory = TestMemory::default();
        memory.write_raw(0x1000, &0x2000u64.to_le_bytes());
        memory.write_raw(0x1008, &0x2010u64.to_le_bytes());
        memory.write_raw(0x1010, &0u64.to_le_bytes());
        memory.write_raw(0x2000, b"/bin/sh\0");
        memory.write_raw(0x2010, b"PATH=/bin\0");

        assert_eq!(
            read_guest_vector(&memory, 0x1000).unwrap(),
            vec![b"/bin/sh".to_vec(), b"PATH=/bin".to_vec()]
        );
    }

    #[test]
    fn iovec_codec_copies_guest_buffers() {
        let mut memory = TestMemory::default();
        memory.write_raw(0x1000, &0x2000u64.to_le_bytes());
        memory.write_raw(0x1008, &2u64.to_le_bytes());
        memory.write_raw(0x1010, &0x2010u64.to_le_bytes());
        memory.write_raw(0x1018, &3u64.to_le_bytes());
        memory.write_raw(0x2000, b"ab");
        memory.write_raw(0x2010, b"cde");

        let iovecs = read_iovecs(&memory, 0x1000, 2).unwrap();
        assert_eq!(
            read_iovec_buffers(&memory, &iovecs).unwrap(),
            vec![b"ab".to_vec(), b"cde".to_vec()]
        );

        let mut output = TestMemory::default();
        write_iovec_buffers(&mut output, &iovecs, &[b"xy".to_vec(), b"z12".to_vec()], 4).unwrap();
        let mut copied = [0; 2];
        output.read_bytes(0x2000, &mut copied).unwrap();
        assert_eq!(&copied, b"xy");
        let mut copied = [0; 2];
        output.read_bytes(0x2010, &mut copied).unwrap();
        assert_eq!(&copied, b"z1");
    }

    #[test]
    fn sockaddr_codec_round_trips_ipv4_and_ipv6() {
        let ipv4 = LinuxSocketAddress::inet([127, 0, 0, 1], 8080);
        assert_eq!(
            encode_socket_address(ipv4),
            [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]
        );

        let mut memory = TestMemory::default();
        memory.write_raw(0x1000, &encode_socket_address(ipv4));
        assert_eq!(
            read_socket_address(&memory, 0x1000, LINUX_SOCKADDR_IN_LEN as u32).unwrap(),
            ipv4
        );

        let ipv6 = LinuxSocketAddress::inet6([1; 16], 443, 7, 2);
        memory.write_raw(0x2000, &encode_socket_address(ipv6));
        assert_eq!(
            read_socket_address(&memory, 0x2000, LINUX_SOCKADDR_IN6_LEN as u32).unwrap(),
            ipv6
        );
    }

    #[test]
    fn select_bitset_codec_preserves_linux_layout() {
        let mut memory = TestMemory::default();
        write_select_fd_set(&mut memory, 0x1000, 100, &[3, 99]).unwrap();

        assert!(select_fd_set_contains(&memory, 0x1000, 3).unwrap());
        assert!(select_fd_set_contains(&memory, 0x1000, 99).unwrap());
        assert!(!select_fd_set_contains(&memory, 0x1000, 4).unwrap());
    }
}
