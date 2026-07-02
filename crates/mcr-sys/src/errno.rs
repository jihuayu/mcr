use core::fmt;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LinuxErrno(u16);

impl LinuxErrno {
    pub const MAX: u16 = 4095;

    pub const EPERM: Self = Self(1);
    pub const ENOENT: Self = Self(2);
    pub const ESRCH: Self = Self(3);
    pub const EINTR: Self = Self(4);
    pub const EIO: Self = Self(5);
    pub const ENXIO: Self = Self(6);
    pub const E2BIG: Self = Self(7);
    pub const ENOEXEC: Self = Self(8);
    pub const EBADF: Self = Self(9);
    pub const ECHILD: Self = Self(10);
    pub const EAGAIN: Self = Self(11);
    pub const EWOULDBLOCK: Self = Self(11);
    pub const ENOMEM: Self = Self(12);
    pub const EACCES: Self = Self(13);
    pub const EFAULT: Self = Self(14);
    pub const ENOTBLK: Self = Self(15);
    pub const EBUSY: Self = Self(16);
    pub const EEXIST: Self = Self(17);
    pub const EXDEV: Self = Self(18);
    pub const ENODEV: Self = Self(19);
    pub const ENOTDIR: Self = Self(20);
    pub const EISDIR: Self = Self(21);
    pub const EINVAL: Self = Self(22);
    pub const ENFILE: Self = Self(23);
    pub const EMFILE: Self = Self(24);
    pub const ENOTTY: Self = Self(25);
    pub const ETXTBSY: Self = Self(26);
    pub const EFBIG: Self = Self(27);
    pub const ENOSPC: Self = Self(28);
    pub const ESPIPE: Self = Self(29);
    pub const EROFS: Self = Self(30);
    pub const EMLINK: Self = Self(31);
    pub const EPIPE: Self = Self(32);
    pub const EDOM: Self = Self(33);
    pub const ERANGE: Self = Self(34);
    pub const EDEADLK: Self = Self(35);
    pub const EDEADLOCK: Self = Self(35);
    pub const ENAMETOOLONG: Self = Self(36);
    pub const ENOLCK: Self = Self(37);
    pub const ENOSYS: Self = Self(38);
    pub const ENOTEMPTY: Self = Self(39);
    pub const ELOOP: Self = Self(40);
    pub const ENOMSG: Self = Self(42);
    pub const EIDRM: Self = Self(43);
    pub const ECHRNG: Self = Self(44);
    pub const EL2NSYNC: Self = Self(45);
    pub const EL3HLT: Self = Self(46);
    pub const EL3RST: Self = Self(47);
    pub const ELNRNG: Self = Self(48);
    pub const EUNATCH: Self = Self(49);
    pub const ENOCSI: Self = Self(50);
    pub const EL2HLT: Self = Self(51);
    pub const EBADE: Self = Self(52);
    pub const EBADR: Self = Self(53);
    pub const EXFULL: Self = Self(54);
    pub const ENOANO: Self = Self(55);
    pub const EBADRQC: Self = Self(56);
    pub const EBADSLT: Self = Self(57);
    pub const EBFONT: Self = Self(59);
    pub const ENOSTR: Self = Self(60);
    pub const ENODATA: Self = Self(61);
    pub const ETIME: Self = Self(62);
    pub const ENOSR: Self = Self(63);
    pub const ENONET: Self = Self(64);
    pub const ENOPKG: Self = Self(65);
    pub const EREMOTE: Self = Self(66);
    pub const ENOLINK: Self = Self(67);
    pub const EADV: Self = Self(68);
    pub const ESRMNT: Self = Self(69);
    pub const ECOMM: Self = Self(70);
    pub const EPROTO: Self = Self(71);
    pub const EMULTIHOP: Self = Self(72);
    pub const EDOTDOT: Self = Self(73);
    pub const EBADMSG: Self = Self(74);
    pub const EOVERFLOW: Self = Self(75);
    pub const ENOTUNIQ: Self = Self(76);
    pub const EBADFD: Self = Self(77);
    pub const EREMCHG: Self = Self(78);
    pub const ELIBACC: Self = Self(79);
    pub const ELIBBAD: Self = Self(80);
    pub const ELIBSCN: Self = Self(81);
    pub const ELIBMAX: Self = Self(82);
    pub const ELIBEXEC: Self = Self(83);
    pub const EILSEQ: Self = Self(84);
    pub const ERESTART: Self = Self(85);
    pub const ESTRPIPE: Self = Self(86);
    pub const EUSERS: Self = Self(87);
    pub const ENOTSOCK: Self = Self(88);
    pub const EDESTADDRREQ: Self = Self(89);
    pub const EMSGSIZE: Self = Self(90);
    pub const EPROTOTYPE: Self = Self(91);
    pub const ENOPROTOOPT: Self = Self(92);
    pub const EPROTONOSUPPORT: Self = Self(93);
    pub const ESOCKTNOSUPPORT: Self = Self(94);
    pub const EOPNOTSUPP: Self = Self(95);
    pub const ENOTSUP: Self = Self(95);
    pub const EPFNOSUPPORT: Self = Self(96);
    pub const EAFNOSUPPORT: Self = Self(97);
    pub const EADDRINUSE: Self = Self(98);
    pub const EADDRNOTAVAIL: Self = Self(99);
    pub const ENETDOWN: Self = Self(100);
    pub const ENETUNREACH: Self = Self(101);
    pub const ENETRESET: Self = Self(102);
    pub const ECONNABORTED: Self = Self(103);
    pub const ECONNRESET: Self = Self(104);
    pub const ENOBUFS: Self = Self(105);
    pub const EISCONN: Self = Self(106);
    pub const ENOTCONN: Self = Self(107);
    pub const ESHUTDOWN: Self = Self(108);
    pub const ETOOMANYREFS: Self = Self(109);
    pub const ETIMEDOUT: Self = Self(110);
    pub const ECONNREFUSED: Self = Self(111);
    pub const EHOSTDOWN: Self = Self(112);
    pub const EHOSTUNREACH: Self = Self(113);
    pub const EALREADY: Self = Self(114);
    pub const EINPROGRESS: Self = Self(115);
    pub const ESTALE: Self = Self(116);
    pub const EUCLEAN: Self = Self(117);
    pub const ENOTNAM: Self = Self(118);
    pub const ENAVAIL: Self = Self(119);
    pub const EISNAM: Self = Self(120);
    pub const EREMOTEIO: Self = Self(121);
    pub const EDQUOT: Self = Self(122);
    pub const ENOMEDIUM: Self = Self(123);
    pub const EMEDIUMTYPE: Self = Self(124);
    pub const ECANCELED: Self = Self(125);
    pub const ENOKEY: Self = Self(126);
    pub const EKEYEXPIRED: Self = Self(127);
    pub const EKEYREVOKED: Self = Self(128);
    pub const EKEYREJECTED: Self = Self(129);
    pub const EOWNERDEAD: Self = Self(130);
    pub const ENOTRECOVERABLE: Self = Self(131);
    pub const ERFKILL: Self = Self(132);
    pub const EHWPOISON: Self = Self(133);

    #[must_use]
    pub const fn new(raw: u16) -> Option<Self> {
        if raw >= 1 && raw <= Self::MAX {
            Some(Self(raw))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn raw(self) -> u16 {
        self.0
    }

    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        match self.0 {
            1 => Some("EPERM"),
            2 => Some("ENOENT"),
            3 => Some("ESRCH"),
            4 => Some("EINTR"),
            5 => Some("EIO"),
            6 => Some("ENXIO"),
            7 => Some("E2BIG"),
            8 => Some("ENOEXEC"),
            9 => Some("EBADF"),
            10 => Some("ECHILD"),
            11 => Some("EAGAIN"),
            12 => Some("ENOMEM"),
            13 => Some("EACCES"),
            14 => Some("EFAULT"),
            15 => Some("ENOTBLK"),
            16 => Some("EBUSY"),
            17 => Some("EEXIST"),
            18 => Some("EXDEV"),
            19 => Some("ENODEV"),
            20 => Some("ENOTDIR"),
            21 => Some("EISDIR"),
            22 => Some("EINVAL"),
            23 => Some("ENFILE"),
            24 => Some("EMFILE"),
            25 => Some("ENOTTY"),
            26 => Some("ETXTBSY"),
            27 => Some("EFBIG"),
            28 => Some("ENOSPC"),
            29 => Some("ESPIPE"),
            30 => Some("EROFS"),
            31 => Some("EMLINK"),
            32 => Some("EPIPE"),
            33 => Some("EDOM"),
            34 => Some("ERANGE"),
            35 => Some("EDEADLK"),
            36 => Some("ENAMETOOLONG"),
            37 => Some("ENOLCK"),
            38 => Some("ENOSYS"),
            39 => Some("ENOTEMPTY"),
            40 => Some("ELOOP"),
            42 => Some("ENOMSG"),
            43 => Some("EIDRM"),
            44 => Some("ECHRNG"),
            45 => Some("EL2NSYNC"),
            46 => Some("EL3HLT"),
            47 => Some("EL3RST"),
            48 => Some("ELNRNG"),
            49 => Some("EUNATCH"),
            50 => Some("ENOCSI"),
            51 => Some("EL2HLT"),
            52 => Some("EBADE"),
            53 => Some("EBADR"),
            54 => Some("EXFULL"),
            55 => Some("ENOANO"),
            56 => Some("EBADRQC"),
            57 => Some("EBADSLT"),
            59 => Some("EBFONT"),
            60 => Some("ENOSTR"),
            61 => Some("ENODATA"),
            62 => Some("ETIME"),
            63 => Some("ENOSR"),
            64 => Some("ENONET"),
            65 => Some("ENOPKG"),
            66 => Some("EREMOTE"),
            67 => Some("ENOLINK"),
            68 => Some("EADV"),
            69 => Some("ESRMNT"),
            70 => Some("ECOMM"),
            71 => Some("EPROTO"),
            72 => Some("EMULTIHOP"),
            73 => Some("EDOTDOT"),
            74 => Some("EBADMSG"),
            75 => Some("EOVERFLOW"),
            76 => Some("ENOTUNIQ"),
            77 => Some("EBADFD"),
            78 => Some("EREMCHG"),
            79 => Some("ELIBACC"),
            80 => Some("ELIBBAD"),
            81 => Some("ELIBSCN"),
            82 => Some("ELIBMAX"),
            83 => Some("ELIBEXEC"),
            84 => Some("EILSEQ"),
            85 => Some("ERESTART"),
            86 => Some("ESTRPIPE"),
            87 => Some("EUSERS"),
            88 => Some("ENOTSOCK"),
            89 => Some("EDESTADDRREQ"),
            90 => Some("EMSGSIZE"),
            91 => Some("EPROTOTYPE"),
            92 => Some("ENOPROTOOPT"),
            93 => Some("EPROTONOSUPPORT"),
            94 => Some("ESOCKTNOSUPPORT"),
            95 => Some("EOPNOTSUPP"),
            96 => Some("EPFNOSUPPORT"),
            97 => Some("EAFNOSUPPORT"),
            98 => Some("EADDRINUSE"),
            99 => Some("EADDRNOTAVAIL"),
            100 => Some("ENETDOWN"),
            101 => Some("ENETUNREACH"),
            102 => Some("ENETRESET"),
            103 => Some("ECONNABORTED"),
            104 => Some("ECONNRESET"),
            105 => Some("ENOBUFS"),
            106 => Some("EISCONN"),
            107 => Some("ENOTCONN"),
            108 => Some("ESHUTDOWN"),
            109 => Some("ETOOMANYREFS"),
            110 => Some("ETIMEDOUT"),
            111 => Some("ECONNREFUSED"),
            112 => Some("EHOSTDOWN"),
            113 => Some("EHOSTUNREACH"),
            114 => Some("EALREADY"),
            115 => Some("EINPROGRESS"),
            116 => Some("ESTALE"),
            117 => Some("EUCLEAN"),
            118 => Some("ENOTNAM"),
            119 => Some("ENAVAIL"),
            120 => Some("EISNAM"),
            121 => Some("EREMOTEIO"),
            122 => Some("EDQUOT"),
            123 => Some("ENOMEDIUM"),
            124 => Some("EMEDIUMTYPE"),
            125 => Some("ECANCELED"),
            126 => Some("ENOKEY"),
            127 => Some("EKEYEXPIRED"),
            128 => Some("EKEYREVOKED"),
            129 => Some("EKEYREJECTED"),
            130 => Some("EOWNERDEAD"),
            131 => Some("ENOTRECOVERABLE"),
            132 => Some("ERFKILL"),
            133 => Some("EHWPOISON"),
            _ => None,
        }
    }
}

impl fmt::Display for LinuxErrno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{}({})", name, self.0),
            None => write!(f, "errno({})", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LinuxErrno;

    #[test]
    fn errno_accepts_linux_error_range() {
        assert_eq!(LinuxErrno::new(1), Some(LinuxErrno::EPERM));
        assert_eq!(
            LinuxErrno::new(LinuxErrno::MAX).map(LinuxErrno::raw),
            Some(4095)
        );
        assert_eq!(LinuxErrno::new(0), None);
        assert_eq!(LinuxErrno::new(4096), None);
    }

    #[test]
    fn errno_values_match_linux_x86_64() {
        assert_eq!(LinuxErrno::EAGAIN.raw(), 11);
        assert_eq!(LinuxErrno::EWOULDBLOCK.raw(), 11);
        assert_eq!(LinuxErrno::ENOSYS.raw(), 38);
        assert_eq!(LinuxErrno::ENOTSUP.raw(), 95);
    }
}
