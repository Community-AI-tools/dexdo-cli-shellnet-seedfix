//! The one reservation primitive the tests use for an address that must stay DEAD.
//! `crates/dexdo/src/cli/` is compiled into the `dexdo` BINARY and `crates/dexdo/src/seller/` into
//! the `dexdo` LIBRARY, so a `#[cfg(test)]` item in one is invisible to the other. This file is
//! declared by BOTH crate roots, which keeps a single definition in the tree without putting a
//! test-only helper on the library's production surface.

/// An address that refuses every connection for as long as the returned socket is held.
/// The socket is BOUND but never `listen`ed: nothing can accept there, so a SYN is answered with
/// RST(`ECONNREFUSED`, exactly like a closed port), and the kernel cannot hand the port to anybody
/// else while this reservation is alive. Hold it for as long as the address must stay dead.
/// Binding a listener, reading `local_addr()` and dropping it hands the port straight back to the
/// kernel, and any concurrent `bind("127.0.0.1:0")` -- a neighbouring test, the second CI pipeline on
/// the same builder -- can be handed that exact port before the probe runs. The "dead" endpoint then
/// answers and the test fails, hangs on the handshake, or silently proves the wrong path.
/// Holding the listener open instead is not equivalent: `listen(2)` completes the handshake out of
/// the backlog, so the connect would SUCCEED and the connection-refused path under test would never
/// be reached. A *connected* socket is not equivalent either -- Linux can reuse its local port as
/// the source of a connect to that same port, and the resulting TCP self-connection is accepted;
/// that shape measured 6 successful connections in 120,000, this one 0 in 120,000.
pub(crate) fn refusing_endpoint() -> (tokio::net::TcpSocket, String) {
    let socket = tokio::net::TcpSocket::new_v4().expect("v4 socket");
    socket
        .bind("127.0.0.1:0".parse().unwrap())
        .expect("bind without listening");
    let addr = socket.local_addr().expect("bound address").to_string();
    (socket, addr)
}
