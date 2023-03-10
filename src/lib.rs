#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}

mod liboverride;
use dns_lookup::lookup_host;
use libc::{
    addrinfo, c_char, c_int, c_void, dlsym, hostent, ifaddrs, in6_addr, in_addr, servent, sockaddr,
    sockaddr_in, sockaddr_in6, socklen_t, AF_INET, AF_INET6, IPPROTO_IP, IP_MULTICAST_IF, IP_TOS,
    RTLD_NEXT, SOL_IP, SOL_IPV6,
};
use std::ffi::CString;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// WKP = Well Known Prefix RFC6052
const WKP: [u8; 12] = [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];

// "IPv4-Compatible IPv6 address" prefix RFC3513. Deprecated by RFC4291.
const IPV4_COMPAT: [u8; 12] = [0u8; 12];

// IPv4-mapped Address prefix - RFC4291
const IPV4_MAPPED: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

fn pref64() -> [u8; 12] {
    let mut pref = WKP.clone();
    for ip in lookup_host("ipv4only.arpa.").unwrap().into_iter() {
        match ip {
            IpAddr::V6(ip) => {
                eprintln!(
                    "[sock464][debug] NAT64 prefix from 'ipv4only.arpa.' [{}]",
                    ip.to_string()
                );
                pref.copy_from_slice(&ip.octets()[..12]);
                break;
            }
            _ => (),
        }
    }
    pref
}

struct LibcOverride {}

impl LibcOverride {
    libc_override! {fn socket(socket_family: c_int, socket_type: c_int, protocol: c_int) -> c_int}
    libc_override! {fn connect(sockfd: c_int, addr: *const sockaddr, addrlen: socklen_t) -> c_int}
    libc_override! {fn bind(sockfd: c_int, addr: *const sockaddr, addrlen: socklen_t) -> c_int}
    libc_override! {fn accept(sockfd: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t) -> c_int}
    libc_override! {fn getsockname(sockfd: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t) -> c_int}
    libc_override! {fn getpeername(sockfd: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t) -> c_int}
    libc_override! {fn recvfrom(sockfd: c_int, buf: *mut c_void, len: usize, flags: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t) -> isize}
    libc_override! {fn sendto(sockfd: c_int, buf: *const c_void, len: usize, flags: c_int, dest_addr: *const sockaddr, addrlen: socklen_t) -> isize}
    libc_override! {fn getaddrinfo(node: *const libc::c_char, service: *const libc::c_char, hints: *const addrinfo, res: *mut *mut addrinfo) -> c_int}
    libc_override! {fn gethostbyname(name: *const c_char) -> *mut hostent}
    libc_override! {fn getservbyname(name: *const c_char, proto: *const c_char) -> *mut servent}
    libc_override! {fn getifaddrs(ifap: *mut *mut ifaddrs) -> c_int}
    libc_override! {fn setsockopt(sockfd: c_int, level: c_int, optname: c_int, optval: *const c_void, optlen: socklen_t) -> c_int}
}

trait SockAddrIn6or4
where
    Self: Copy,
{
    fn new() -> Self;
    fn family() -> u16;

    fn as_raw_ptr(&self) -> *const sockaddr {
        (self as *const Self).cast::<sockaddr>()
    }

    fn from_sockaddr_ptr(addr: *const sockaddr, addrlen: socklen_t) -> Self {
        if addr.is_null() {
            panic!("Null pointer!")
        }

        if size_of::<Self>() as u32 != addrlen {
            panic!("socklen_t - length mismatch!")
        }

        // Checks that addr: sockaddr is of the same address family as Self
        // SAFETY: Verified the pointer is not null
        if Self::family() != unsafe { (*addr).sa_family } {
            panic!("unsupported Address Family!")
        }

        // Casts the pointer `addr: *const sockaddr` as `*const Self` and dereferences
        // SAFETY: Verified the Address family of addr and Self are equal
        // and Self and addrlen are equal
        unsafe { *(addr as *const Self) }
    }
}

impl SockAddrIn6or4 for sockaddr_in6 {
    fn family() -> u16 {
        AF_INET6 as u16
    }
    fn new() -> Self {
        sockaddr_in6 {
            sin6_family: AF_INET6 as u16,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: in6_addr { s6_addr: [0u8; 16] },
            sin6_scope_id: 0,
        }
    }
}

impl SockAddrIn6or4 for sockaddr_in {
    fn family() -> u16 {
        AF_INET as u16
    }
    fn new() -> Self {
        sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: 0,
            sin_addr: in_addr { s_addr: 0u32 },
            sin_zero: [0; 8],
        }
    }
}

trait S464mapping {
    fn nat64(self) -> sockaddr_in6;
    fn is_mapped_ipv4(&self) -> bool;
}

impl S464mapping for sockaddr_in6 {
    fn nat64(self) -> sockaddr_in6 {
        if self.is_mapped_ipv4() {
            let mut r_sockaddr_in6 = self.clone();
            eprintln!("[sock464][debug] Mapping AF_INET6");

            eprintln!(
                "[sock464][debug] Original sockaddr_in6 [{}]:{}",
                Ipv6Addr::from(r_sockaddr_in6.sin6_addr.s6_addr).to_string(),
                r_sockaddr_in6.sin6_port.swap_bytes()
            );

            r_sockaddr_in6.sin6_addr.s6_addr[0..12].copy_from_slice(&(pref64()));

            eprintln!(
                "[sock464][debug] Mapped sockaddr_in6 [{}]:{}",
                Ipv6Addr::from(r_sockaddr_in6.sin6_addr.s6_addr).to_string(),
                r_sockaddr_in6.sin6_port.to_be()
            );
            r_sockaddr_in6
        } else {
            eprintln!(
                "[sock464][debug] Unmapped sockaddr_in6 [{}]:{}",
                Ipv6Addr::from(self.sin6_addr.s6_addr).to_string(),
                self.sin6_port.to_be()
            );
            self
        }
    }

    fn is_mapped_ipv4(&self) -> bool {
        let slice = &self.sin6_addr.s6_addr[0..12];

        slice == IPV4_COMPAT || slice == IPV4_MAPPED
    }
}

impl S464mapping for sockaddr_in {
    fn nat64(self) -> sockaddr_in6 {
        eprintln!("[sock464][debug] Mapping AF_INET");

        eprintln!(
            "[sock464][debug] Original sockaddr_in {}:{}",
            Ipv4Addr::from(self.sin_addr.s_addr.to_be()).to_string(),
            self.sin_port.to_be()
        );
        let mut s6_addr = [0u8; 16];
        s6_addr[0..12].copy_from_slice(&(pref64()));
        s6_addr[12..16].copy_from_slice(&self.sin_addr.s_addr.to_le_bytes());

        eprintln!(
            "[sock464][debug] Mapped sockaddr_in6 [{}]:{}",
            Ipv6Addr::from(s6_addr.clone()).to_string(),
            self.sin_port.to_be()
        );

        sockaddr_in6 {
            sin6_family: AF_INET6 as u16,
            sin6_port: self.sin_port,
            sin6_flowinfo: 0,
            sin6_addr: in6_addr { s6_addr: s6_addr },
            sin6_scope_id: 0,
        }
    }

    fn is_mapped_ipv4(&self) -> bool {
        true
    }
}

#[no_mangle]
unsafe extern "C" fn socket(socket_family: c_int, socket_type: c_int, protocol: c_int) -> c_int {
    eprintln!(
        "\n[sock464][debug] Called socket({}, {}, {})",
        socket_family, socket_type, protocol
    );

    let mut socket_family: c_int = socket_family;

    if matches!(socket_family, AF_INET) {
        socket_family = AF_INET6;
    }

    eprintln!(
        "[sock464][debug]  Mapped socket({}, {}, {})",
        socket_family, socket_type, protocol
    );

    // create a new socket
    let sockfd: c_int = LibcOverride::socket(socket_family, socket_type, protocol);
    if sockfd == -1 {
        eprintln!("[sock464][debug] Failed to create socket");
    }
    eprintln!("[sock464][debug] Returning socket FD {}", sockfd);
    sockfd
}

#[no_mangle]
unsafe extern "C" fn connect(sockfd: c_int, addr: *const sockaddr, addrlen: socklen_t) -> c_int {
    eprintln!(
        "[sock464][debug] Called connect({}, {:?}, {})",
        sockfd, addr, addrlen
    );

    // `sa` stores the translated sockaddr_in6 and is needed to guarentee the 'sa.as_raw_ptr()' pointer
    // lifetime will remain valid for the `LibcOverride::connect` call.
    let sa: sockaddr_in6;

    if addr.is_null() {
        return LibcOverride::connect(sockfd, addr, addrlen);
    }

    let (addr, addrlen) = match (*addr).sa_family as i32 {
        AF_INET => {
            eprintln!("[sock464][debug][connect] Match AF_INET");
            sa = sockaddr_in::from_sockaddr_ptr(addr, addrlen).nat64();
            (
                sa.as_raw_ptr() as *const sockaddr,
                size_of::<sockaddr_in6>() as socklen_t,
            )
        }
        AF_INET6 => {
            eprintln!("[sock464][debug][connect] Match AF_INET6");
            sa = sockaddr_in6::from_sockaddr_ptr(addr, addrlen).nat64();
            (
                sa.as_raw_ptr() as *const sockaddr,
                size_of::<sockaddr_in6>() as socklen_t,
            )
        }
        _ => (addr, addrlen),
    };

    LibcOverride::connect(sockfd, addr, addrlen)
}

#[no_mangle]
pub extern "C" fn setsockopt(
    sockfd: c_int,
    level: c_int,
    optname: c_int,
    optval: *const c_void,
    optlen: socklen_t,
) -> c_int {
    eprintln!(
        "[sock464][debug]Caught setsockopt({}, {}, {}, {:?}, {})",
        sockfd, level, optname, optval, optlen,
    );

    if level == IPPROTO_IP && optname == IP_TOS {
        // IP_TOS option is not applicable to AF_INET6 sockets
        eprintln!("[sock464][debug] IP_TOS option is not applicable to AF_INET6 sockets");
        return 0;
    }
    if level == IPPROTO_IP && optname == IP_MULTICAST_IF {
        // IP_MULTICAST_IF option is not applicable to AF_INET6 sockets
        eprintln!("[sock464][debug] IP_MULTICAST_IF option is not applicable to AF_INET6 sockets");
        return 0;
    }

    let level = if level == SOL_IP { SOL_IPV6 } else { level };

    LibcOverride::setsockopt(sockfd, level, optname, optval, optlen)
}

#[no_mangle]
pub extern "C" fn bind(sockfd: c_int, addr: *const sockaddr, addrlen: socklen_t) -> c_int {
    eprintln!("[sock464][debug] called bind");
    LibcOverride::bind(sockfd, addr, addrlen)
}

#[no_mangle]
pub extern "C" fn accept(sockfd: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t) -> c_int {
    eprintln!("[sock464][debug] called accept");
    LibcOverride::accept(sockfd, addr, addrlen)
}

#[no_mangle]
pub extern "C" fn getsockname(
    sockfd: c_int,
    addr: *mut sockaddr,
    addrlen: *mut socklen_t,
) -> c_int {
    eprintln!("[sock464][debug] called getsockname");
    LibcOverride::getsockname(sockfd, addr, addrlen)
}
#[no_mangle]
pub extern "C" fn getpeername(
    sockfd: c_int,
    addr: *mut sockaddr,
    addrlen: *mut socklen_t,
) -> c_int {
    eprintln!("[sock464][debug] called getpeername");
    LibcOverride::getpeername(sockfd, addr, addrlen)
}
#[no_mangle]
pub extern "C" fn recvfrom(
    sockfd: c_int,
    buf: *mut c_void,
    len: usize,
    flags: c_int,
    addr: *mut sockaddr,
    addrlen: *mut socklen_t,
) -> isize {
    eprintln!("[sock464][debug] called recvfrom");
    LibcOverride::recvfrom(sockfd, buf, len, flags, addr, addrlen)
}
#[no_mangle]
pub extern "C" fn sendto(
    sockfd: c_int,
    buf: *const c_void,
    len: usize,
    flags: c_int,
    dest_addr: *const sockaddr,
    addrlen: socklen_t,
) -> isize {
    eprintln!("[sock464][debug] called sendto");
    LibcOverride::sendto(sockfd, buf, len, flags, dest_addr, addrlen)
}
#[no_mangle]
pub extern "C" fn getaddrinfo(
    node: *const libc::c_char,
    service: *const libc::c_char,
    hints: *const addrinfo,
    res: *mut *mut addrinfo,
) -> c_int {
    eprintln!("[sock464][debug] called getaddrinfo");
    LibcOverride::getaddrinfo(node, service, hints, res)
}
#[no_mangle]
pub extern "C" fn gethostbyname(name: *const c_char) -> *mut hostent {
    eprintln!("[sock464][debug] called gethostbyname");
    LibcOverride::gethostbyname(name)
}
#[no_mangle]
pub extern "C" fn getservbyname(name: *const c_char, proto: *const c_char) -> *mut servent {
    eprintln!("[sock464][debug] called getservbyname");
    LibcOverride::getservbyname(name, proto)
}
#[no_mangle]
pub extern "C" fn getifaddrs(ifap: *mut *mut ifaddrs) -> c_int {
    eprintln!("[sock464][debug] called getifaddrs");
    LibcOverride::getifaddrs(ifap)
}
