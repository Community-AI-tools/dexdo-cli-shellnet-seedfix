//! The one reservation primitive the tests use for an address that must stay DEAD.
//! `crates/dexdo/src/cli/` is compiled into the `dexdo` BINARY and `crates/dexdo/src/seller/` into
//! the `dexdo` LIBRARY, so a `#[cfg(test)]` item in one is invisible to the other. This file is
//! declared by BOTH crate roots, which keeps a single definition in the tree without putting a
//! test-only helper on the library's production surface.

/// An address that refuses every connection for as long as the returned socket is held.
/// The port is held by a **UDP** socket, which leaves TCP on that port genuinely closed: a SYN finds
/// no TCP control block at all and is answered with RST(`ECONNREFUSED`), exactly like a closed
/// port. Hold the socket for as long as the address must stay dead.
/// Binding a listener, reading `local_addr()` and dropping it hands the port straight back to the
/// kernel, and any concurrent `bind("127.0.0.1:0")` -- a neighbouring test, the second CI pipeline on
/// the same builder -- can be handed that exact port before the probe runs. The "dead" endpoint then
/// answers and the test fails, hangs on the handshake, or silently proves the wrong path.
/// Holding a TCP listener open instead is not equivalent: `listen(2)` completes the handshake out of
/// the backlog, so the connect would SUCCEED and the connection-refused path under test would never
/// be reached. A *connected* socket is not equivalent either -- Linux can reuse its local port as
/// the source of a connect to that same port, and the resulting TCP self-connection is accepted;
/// that shape measured 6 successful connections in 120,000.
/// # Why UDP and not a TCP socket bound without `listen`
/// That was this primitive's shape until 2026-08-17, and its refusal is **Linux-only**. On BSD the
/// bound socket still owns a TCP control block for the port, and a SYN that finds one in a
/// non-listening state is dropped in silence rather than reset -- so the connect does not refuse, it
/// hangs until the caller's deadline. Measured on both runners, connecting to a held port:
/// ```text
/// TCP bound, never listened Linux ECONNREFUSED 0.001s macos-latest TIMED OUT after 3.001s
/// UDP-held, TCP truly closed Linux ECONNREFUSED 0.000s macos-latest ECONNREFUSED 0.000s
/// ```
/// That is why four `seller::liveness` rows failed on `macos-latest` and nowhere else: every one of
/// them collapsed into `handshake_timeout`, so the rows asserting `stage: tcp_connect` saw the wrong
/// stage, and the two arms the matrix deliberately keeps apart -- a TRANSPORT fault and a probe
/// TIMEOUT -- became indistinguishable.
/// TCP and UDP are separate port spaces, so the hold does not stop a TCP `bind(0)` from being handed
/// the same number. Measured over 3,000 rounds: 0 collisions on Linux, 1 on `macos-latest`. That
/// residue is real and is the price of the trade -- and it is the price of a case that has to also
/// `listen` on the collided port inside the probe window to do any harm, against a shape that failed
/// every macOS run outright.
pub(crate) fn refusing_endpoint() -> (tokio::net::UdpSocket, String) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("hold a port with UDP");
    socket
        .set_nonblocking(true)
        .expect("the held socket is never read from");
    let addr = socket.local_addr().expect("bound address").to_string();
    let socket = tokio::net::UdpSocket::from_std(socket).expect("adopt the held socket");
    (socket, addr)
}
