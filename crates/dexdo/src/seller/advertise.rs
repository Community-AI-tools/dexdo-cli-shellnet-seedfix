//! Classification of the seller's advertised gateway address and the error codes used by
//! the `advertised_gateway` readiness probe.
//! The advertised address is what the seller encrypts into the buyer handover. The default
//! assumption is a REAL deployment -- seller and buyer on different machines -- so a non-routable
//! advertise(bind-all wildcard, loopback, RFC1918/ULA, link-local, CGNAT) is a footgun: the offer
//! rests in the book and no remote buyer can reach it. It is rejected fail-closed unless the
//! operator opts into local/LAN testing with `--allow-private-advertise`.
//! DNS names are NOT resolved here: resolution at startup would depend on the seller host's own
//! resolver(split-horizon DNS, VPN resolvers) and would make the check both slow and wrong. A name
//! is presumed publicly resolvable, except for the reserved special-use local names.
//! Error codes emitted from this area, rendered in the shape
//! (`error[CODE](kind): message` + `cause:` lines + a `hint:` line):
//! | code | kind | meaning |
//! |------|------|---------|
//! | `E_ADVERTISE_NOT_PUBLIC` | config | the advertised host cannot be reached by a remote buyer |
//! | `E_ADVERTISE_UNREACHABLE` | network | the advertised address did not answer the pinned-TLS(h2) self-probe |
//! | `E_ADVERTISE_WRONG_GATEWAY` | tls | the advertised address answered, but it is not this gateway |

use dexdo_core::{error_codes, DexdoError};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why an advertised host cannot be dialled by a remote buyer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonPublicReason {
    /// `0.0.0.0` / `::` -- a bind-all wildcard, not a connect target.
    BindAll,
    /// `127.0.0.0/8`, `::1`, `localhost` -- the seller's own host only.
    Loopback,
    /// RFC1918(`10/8`, `172.16/12`, `192.168/16`) or IPv6 ULA(`fc00::/7`) -- LAN only.
    Private,
    /// `169.254/16` / `fe80::/10` -- link-local only.
    LinkLocal,
    /// `100.64/10` -- carrier-grade NAT / overlay range, not internet-routable.
    Cgnat,
    /// A reserved special-use local name(`localhost`, `*.local`, `*.internal`, `*.home.arpa`).
    LocalName,
}

impl NonPublicReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BindAll => "bind-all wildcard",
            Self::Loopback => "loopback",
            Self::Private => "private (RFC1918/ULA)",
            Self::LinkLocal => "link-local",
            Self::Cgnat => "CGNAT (100.64/10)",
            Self::LocalName => "reserved local name",
        }
    }
}

/// Whether the advertised address can plausibly be dialled by a remote buyer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvertiseReachability {
    /// A globally scoped IP literal, or a DNS name(presumed publicly resolvable -- not resolved here).
    Public,
    NonPublic(NonPublicReason),
}

impl AdvertiseReachability {
    pub fn is_public(self) -> bool {
        matches!(self, Self::Public)
    }
}

/// Split `host:port`(also `[v6]:port`) into its host part.
fn advertise_host(addr: &str) -> &str {
    let addr = addr.trim();
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((host, _)) = rest.split_once(']') {
            return host;
        }
        return rest;
    }
    // An unbracketed IPv6 literal has more than one colon and is not a `host:port` pair.
    if addr.matches(':').count() > 1 {
        return addr;
    }
    match addr.rsplit_once(':') {
        Some((host, _)) => host,
        None => addr,
    }
}

fn classify_v4(ip: Ipv4Addr) -> AdvertiseReachability {
    let octets = ip.octets();
    if ip.is_unspecified() {
        return AdvertiseReachability::NonPublic(NonPublicReason::BindAll);
    }
    if ip.is_loopback() {
        return AdvertiseReachability::NonPublic(NonPublicReason::Loopback);
    }
    if ip.is_private() {
        return AdvertiseReachability::NonPublic(NonPublicReason::Private);
    }
    if ip.is_link_local() {
        return AdvertiseReachability::NonPublic(NonPublicReason::LinkLocal);
    }
    // 100.64.0.0/10(`Ipv4Addr::is_shared` is still unstable).
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return AdvertiseReachability::NonPublic(NonPublicReason::Cgnat);
    }
    AdvertiseReachability::Public
}

fn classify_v6(ip: Ipv6Addr) -> AdvertiseReachability {
    if ip.is_unspecified() {
        return AdvertiseReachability::NonPublic(NonPublicReason::BindAll);
    }
    if ip.is_loopback() {
        return AdvertiseReachability::NonPublic(NonPublicReason::Loopback);
    }
    let first = ip.segments()[0];
    // fe80::/10 and fc00::/7(`is_unicast_link_local`/`is_unique_local` are still unstable).
    if first & 0xffc0 == 0xfe80 {
        return AdvertiseReachability::NonPublic(NonPublicReason::LinkLocal);
    }
    if first & 0xfe00 == 0xfc00 {
        return AdvertiseReachability::NonPublic(NonPublicReason::Private);
    }
    AdvertiseReachability::Public
}

fn classify_name(host: &str) -> AdvertiseReachability {
    let name = host.trim_end_matches('.').to_ascii_lowercase();
    let local = name == "localhost"
        || name.ends_with(".localhost")
        || name.ends_with(".local")
        || name.ends_with(".internal")
        || name.ends_with(".home.arpa");
    if local {
        AdvertiseReachability::NonPublic(NonPublicReason::LocalName)
    } else {
        AdvertiseReachability::Public
    }
}

/// Classify the host part of an advertised `host:port`.
pub fn classify_advertise(addr: &str) -> AdvertiseReachability {
    let host = advertise_host(addr);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => classify_v4(v4),
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => classify_v4(v4),
            None => classify_v6(v6),
        },
        Err(_) => classify_name(host),
    }
}

/// `true` when a remote buyer can plausibly dial the advertised address.
pub fn advertise_is_public(addr: &str) -> bool {
    classify_advertise(addr).is_public()
}

/// Fail-closed validation of the advertised gateway address before any order is posted.
/// `defaulted_from_listen` only shapes the message: it says the operator never chose the address.
/// `allow_private` is the explicit `--allow-private-advertise` opt-in for same-host/LAN testing.
pub fn validate_advertise(
    advertised: &str,
    defaulted_from_listen: bool,
    allow_private: bool,
) -> Result<(), DexdoError> {
    if allow_private {
        return Ok(());
    }
    match classify_advertise(advertised) {
        AdvertiseReachability::Public => Ok(()),
        AdvertiseReachability::NonPublic(reason) => {
            let message = if defaulted_from_listen {
                format!(
                    "--gateway-advertise defaulted to --gateway-listen {advertised}, which is not \
                     reachable by remote buyers ({})",
                    reason.as_str()
                )
            } else {
                format!(
                    "--gateway-advertise {advertised} is not reachable by remote buyers ({})",
                    reason.as_str()
                )
            };
            Err(
                DexdoError::new(error_codes::E_ADVERTISE_NOT_PUBLIC, message)
                    .with_hint(error_codes::E_ADVERTISE_NOT_PUBLIC.fix()),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason(addr: &str) -> NonPublicReason {
        match classify_advertise(addr) {
            AdvertiseReachability::NonPublic(reason) => reason,
            AdvertiseReachability::Public => panic!("{addr} must not classify as public"),
        }
    }

    #[test]
    fn every_non_routable_class_is_rejected() {
        assert_eq!(reason("0.0.0.0:8443"), NonPublicReason::BindAll);
        assert_eq!(reason("[::]:8443"), NonPublicReason::BindAll);
        assert_eq!(reason("127.0.0.1:8443"), NonPublicReason::Loopback);
        assert_eq!(reason("127.10.20.30:8443"), NonPublicReason::Loopback);
        assert_eq!(reason("[::1]:8443"), NonPublicReason::Loopback);
        assert_eq!(reason("10.1.2.3:8443"), NonPublicReason::Private);
        assert_eq!(reason("172.16.0.1:8443"), NonPublicReason::Private);
        assert_eq!(reason("172.31.255.254:8443"), NonPublicReason::Private);
        assert_eq!(reason("192.168.1.10:8443"), NonPublicReason::Private);
        assert_eq!(reason("[fd00::1]:8443"), NonPublicReason::Private);
        assert_eq!(reason("169.254.10.1:8443"), NonPublicReason::LinkLocal);
        assert_eq!(reason("[fe80::1]:8443"), NonPublicReason::LinkLocal);
        assert_eq!(reason("100.64.0.1:8443"), NonPublicReason::Cgnat);
        assert_eq!(reason("100.127.255.254:8443"), NonPublicReason::Cgnat);
        assert_eq!(reason("localhost:8443"), NonPublicReason::LocalName);
        assert_eq!(reason("LocalHost.:8443"), NonPublicReason::LocalName);
        assert_eq!(reason("seller.local:8443"), NonPublicReason::LocalName);
        assert_eq!(reason("box.internal:8443"), NonPublicReason::LocalName);
        assert_eq!(reason("box.home.arpa:8443"), NonPublicReason::LocalName);
        // IPv4-mapped IPv6 must not smuggle a private address past the classifier.
        assert_eq!(
            reason("[::ffff:192.168.1.10]:8443"),
            NonPublicReason::Private
        );
        assert_eq!(reason("[::ffff:127.0.0.1]:8443"), NonPublicReason::Loopback);
    }

    #[test]
    fn public_addresses_and_names_are_allowed() {
        for addr in [
            "94.156.178.14:8443",
            "8.8.8.8:443",
            // 172.15/16 and 172.32/16 sit outside RFC1918; 100.128/9 sits outside CGNAT.
            "172.15.0.1:8443",
            "172.32.0.1:8443",
            "100.128.0.1:8443",
            "99.64.0.1:8443",
            "[2001:db8::1]:8443",
            "[2606:4700::1111]:443",
            "seller.example.net:443",
            "gw.internal.example.net:443",
            "laptop:8443",
        ] {
            assert!(
                advertise_is_public(addr),
                "{addr} must classify as publicly dialable"
            );
        }
    }

    #[test]
    fn allow_private_opt_in_accepts_every_rejected_class() {
        for addr in [
            "0.0.0.0:8443",
            "127.0.0.1:8443",
            "192.168.1.10:8443",
            "169.254.10.1:8443",
            "100.64.0.1:8443",
            "localhost:8443",
        ] {
            assert!(
                validate_advertise(addr, false, false).is_err(),
                "{addr} must fail closed by default"
            );
            assert!(
                validate_advertise(addr, false, true).is_ok(),
                "{addr} must be accepted with --allow-private-advertise"
            );
        }
        assert!(validate_advertise("seller.example.net:443", false, false).is_ok());
    }

    #[test]
    fn rejection_message_matches_the_750_shape() {
        let explicit = validate_advertise("192.168.1.10:8443", false, false)
            .expect_err("private advertise must fail");
        assert_eq!(
            explicit.to_string(),
            "error[E_ADVERTISE_NOT_PUBLIC] (config): --gateway-advertise 192.168.1.10:8443 is not \
             reachable by remote buyers (private (RFC1918/ULA))\n  \
             hint: pass a public host:port reachable from the internet, or run on a public host; \
             for local/LAN testing only, use --allow-private-advertise"
        );

        let defaulted = validate_advertise("0.0.0.0:8443", true, false)
            .expect_err("bind-all advertise must fail");
        assert_eq!(
            defaulted.to_string(),
            "error[E_ADVERTISE_NOT_PUBLIC] (config): --gateway-advertise defaulted to \
             --gateway-listen 0.0.0.0:8443, which is not reachable by remote buyers \
             (bind-all wildcard)\n  \
             hint: pass a public host:port reachable from the internet, or run on a public host; \
             for local/LAN testing only, use --allow-private-advertise"
        );
    }
}
