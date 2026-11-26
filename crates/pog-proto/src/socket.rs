use crate::wire::{
    compute_challenge_mac, ChallengePacket, ProtoError, ResponsePacket, PACKET_SIZE,
};
use rand::RngCore;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct TimestampedDatagram {
    pub bytes: [u8; PACKET_SIZE],
    pub peer: SocketAddr,
    /// Monotonic receive instant (on Linux production anchors, upgraded via SO_TIMESTAMPNS kernel RX timestamp).
    pub received_at: Instant,
    /// Optional kernel RX timestamp in nanoseconds (epoch clock) when Linux SO_TIMESTAMPNS is active.
    pub kernel_rx_ns: Option<u64>,
}

/// Bind a low-latency UDP socket configured for minimal jitter:
/// - Non-blocking false with tight read timeout
/// - Linux best-effort `SO_TIMESTAMPNS` + `SO_BUSY_POLL` (50 us)
pub fn bind_low_latency_udp(addr: SocketAddr, read_timeout: Duration) -> std::io::Result<UdpSocket> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.bind(&addr.into())?;

    #[cfg(target_os = "linux")]
    unsafe {
        use std::os::unix::io::AsRawFd;
        let fd = sock.as_raw_fd();
        let on: libc::c_int = 1;
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPNS,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of_val(&on) as libc::socklen_t,
        );
        let busy_poll_us: libc::c_int = 50;
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BUSY_POLL,
            &busy_poll_us as *const _ as *const libc::c_void,
            std::mem::size_of_val(&busy_poll_us) as libc::socklen_t,
        );
    }

    let std_sock: UdpSocket = sock.into();
    std_sock.set_read_timeout(Some(read_timeout))?;
    Ok(std_sock)
}

/// Receive one 64-byte UDP packet with immediate timestamp capture.
/// On Linux with `SO_TIMESTAMPNS`, extracts the kernel socket RX timestamp via `recvmsg`.
#[cfg(target_os = "linux")]
pub fn recv_timestamped(sock: &UdpSocket) -> Result<TimestampedDatagram, ProtoError> {
    use std::os::unix::io::AsRawFd;

    let mut buf = [0u8; PACKET_SIZE];
    let mut cmsg_buf = [0u8; 128];
    let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut addr_storage as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len();

    let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) };
    let received_at = Instant::now();
    if n < 0 {
        return Err(ProtoError::Io(std::io::Error::last_os_error()));
    }
    if n as usize != PACKET_SIZE {
        return Err(ProtoError::InvalidPacketLength {
            expected: PACKET_SIZE,
            got: n as usize,
        });
    }

    let mut kernel_rx_ns = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_TIMESTAMPNS
            {
                let mut ts: libc::timespec = std::mem::zeroed();
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsg),
                    &mut ts as *mut _ as *mut u8,
                    std::mem::size_of::<libc::timespec>(),
                );
                kernel_rx_ns = Some((ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64));
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    let peer = sockaddr_to_socket_addr(&addr_storage)?;
    Ok(TimestampedDatagram {
        bytes: buf,
        peer,
        received_at,
        kernel_rx_ns,
    })
}

#[cfg(target_os = "linux")]
fn sockaddr_to_socket_addr(storage: &libc::sockaddr_storage) -> Result<SocketAddr, ProtoError> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin: &libc::sockaddr_in = unsafe { &*(storage as *const _ as *const _) };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            let sin6: &libc::sockaddr_in6 = unsafe { &*(storage as *const _ as *const _) };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => Err(ProtoError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported address family",
        ))),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn recv_timestamped(sock: &UdpSocket) -> Result<TimestampedDatagram, ProtoError> {
    let mut buf = [0u8; PACKET_SIZE];
    let (n, peer) = sock.recv_from(&mut buf)?;
    let received_at = Instant::now();
    if n != PACKET_SIZE {
        return Err(ProtoError::InvalidPacketLength {
            expected: PACKET_SIZE,
            got: n,
        });
    }
    Ok(TimestampedDatagram {
        bytes: buf,
        peer,
        received_at,
        kernel_rx_ns: None,
    })
}

/// Anchor-side single timed UDP distance-bounding round:
/// 1. Generates fresh unpredictable 256-bit nonce immediately before TX.
/// 2. Records monotonic TX time `t0` -> sends 64-byte ChallengePacket.
/// 3. Captures immediate RX timestamp `t1` BEFORE MAC verification.
/// 4. Verifies BLAKE3-MAC against `session_key` (derived from Prover TEE's attested ECDH key).
/// 5. Returns measured RTT in microseconds.
pub fn measure_udp_round(
    sock: &UdpSocket,
    prover_addr: SocketAddr,
    session_id: u64,
    round: u16,
    session_key: &[u8; 32],
    epoch_challenge: &[u8],
    cookie_prefix: [u8; 8],
) -> Result<u64, ProtoError> {
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let challenge = ChallengePacket {
        round,
        session_id,
        anchor_tx_ns: 0,
        nonce,
        cookie_prefix,
    };
    let wire_bytes = challenge.encode();

    let t0 = Instant::now();
    sock.send_to(&wire_bytes, prover_addr)?;
    let dgram = recv_timestamped(sock)?;
    let rtt_ns = dgram.received_at.saturating_duration_since(t0).as_nanos() as u64;

    let resp = ResponsePacket::decode(&dgram.bytes)?;
    if resp.session_id != session_id || resp.round != round || resp.nonce_echo != nonce[0..8] {
        return Err(ProtoError::InvalidPacketHeader);
    }

    let expected_mac =
        compute_challenge_mac(session_key, session_id, round, &nonce, epoch_challenge);
    if resp.mac != expected_mac {
        return Err(ProtoError::InvalidMac);
    }

    Ok((rtt_ns / 1_000).max(1))
}

/// Prover TEE-side fast-path: receives a 64-byte ChallengePacket, computes keyed BLAKE3-MAC
/// (< 2 microseconds), and immediately transmits the 64-byte ResponsePacket back over UDP.
pub fn respond_once_udp(
    sock: &UdpSocket,
    expected_session_id: u64,
    session_key: &[u8; 32],
    epoch_challenge: &[u8],
) -> Result<u64, ProtoError> {
    let dgram = recv_timestamped(sock)?;
    let t_start = Instant::now();
    let challenge = ChallengePacket::decode(&dgram.bytes)?;
    if challenge.session_id != expected_session_id {
        return Err(ProtoError::InvalidPacketHeader);
    }
    let mac = compute_challenge_mac(
        session_key,
        challenge.session_id,
        challenge.round,
        &challenge.nonce,
        epoch_challenge,
    );
    let proc_ns = t_start.elapsed().as_nanos() as u64;
    let resp = ResponsePacket {
        round: challenge.round,
        session_id: challenge.session_id,
        prover_proc_ns: proc_ns,
        mac,
        nonce_echo: challenge.nonce[0..8].try_into().unwrap(),
    };
    sock.send_to(&resp.encode(), dgram.peer)?;
    Ok(proc_ns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_live_local_udp_distance_bounding_roundtrip() {
        let anchor_sock =
            bind_low_latency_udp("127.0.0.1:0".parse().unwrap(), Duration::from_secs(2)).unwrap();
        let prover_sock =
            bind_low_latency_udp("127.0.0.1:0".parse().unwrap(), Duration::from_secs(2)).unwrap();
        let prover_addr = prover_sock.local_addr().unwrap();

        let key = [0x77u8; 32];
        let epoch = b"live-test-epoch";
        let sid = 42u64;

        let handle = thread::spawn(move || {
            for _ in 0..8 {
                respond_once_udp(&prover_sock, sid, &key, epoch).unwrap();
            }
        });

        let mut samples = Vec::new();
        for round in 0..8 {
            let rtt_us = measure_udp_round(
                &anchor_sock,
                prover_addr,
                sid,
                round,
                &key,
                epoch,
                [0u8; 8],
            )
            .unwrap();
            samples.push(rtt_us);
        }
        handle.join().unwrap();

        let min_us = *samples.iter().min().unwrap();
        // Local loopback BLAKE3-MAC roundtrip should comfortably be < 5 ms (typically 20-200 us).
        assert!(min_us < 5_000, "Local loopback RTT unexpectedly high: {min_us} us");
    }
}
