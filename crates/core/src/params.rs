//! Protocol parameters. Fixed constants and order book deploy parameters.
//! These are pure types without networking. Values are taken from the spec.

use std::time::Duration;

/// SHELL -- the system's settlement unit. Integer count of minimal units.
pub type Shell = u64;

/// Canonical ECC currency id used by every dexdo market-money path.
pub const SHELL_CURRENCY_ID: u32 = 2;

/// Canonical CLI label for the market settlement currency.
pub const SHELL_CURRENCY_LABEL: &str = "shell";

/// Canonical order-book price quantum: `1e9` raw ECC[2] units = 1 SHELL.
pub const PRICE_STEP: u128 = 1_000_000_000;

/// Minimum buy size, in ticks, needed for the probe tick plus one streaming tick.
pub const MIN_STREAM_BUY_TICKS: u128 = 2;

/// Exact byte length of the pinned Hermez K19 SRS used by `dexdo note deploy`.
pub const HERMEZ_SRS_SIZE_BYTES: u64 = 67_109_124;

/// Maximum HTTP attempts for one resumable Hermez SRS download invocation.
pub const HERMEZ_SRS_MAX_ATTEMPTS: usize = 5;

/// Initial retry delay for transient Hermez SRS download failures.
pub const HERMEZ_SRS_RETRY_INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Maximum one-based history-proof layer used by `dexdo note deploy` re-proof.
pub const NOTE_DEPLOY_PROOF_LAYER_MAX: u8 = 3;

/// Fixed protocol constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolConsts {
    /// Platform fee, bps(on the buyer side, by-fact). `PLATFORM_FEE_BPS = 250`.
    pub platform_fee_bps: u32,
    /// Optimistic tick-acceptance window. `SETTLE_WINDOW = 180s`.
    pub settle_window: Duration,
    /// Stream inactivity timeout(no new tokens). `STREAM_TIMEOUT = 600s`.
    pub stream_timeout: Duration,
    /// Dispute window; timeout burns equal buyer/seller `D/D`. `DISPUTE_WINDOW = 600s`.
    pub dispute_window: Duration,
    /// Rebate rate cap, bps; strictly < `platform_fee_bps`. `REBATE_MAX_BPS = 200`.
    pub rebate_max_bps: u32,
    /// Rebate rate slope, bps per tick. `REBATE_SLOPE_BPS = 4`.
    pub rebate_slope_bps: u32,
}

impl ProtocolConsts {
    /// Canonical values from / A.1.
    /// The invariant `rebate_max_bps < platform_fee_bps` is checked here:
    /// otherwise the net burn could become non-positive.
    pub const fn canonical() -> Self {
        let c = Self {
            platform_fee_bps: 250,
            settle_window: Duration::from_secs(180),
            stream_timeout: Duration::from_secs(600),
            dispute_window: Duration::from_secs(600),
            rebate_max_bps: 200,
            rebate_slope_bps: 4,
        };
        assert!(
            c.rebate_max_bps < c.platform_fee_bps,
            "anti-wash invariant: REBATE_MAX_BPS must be strictly < PLATFORM_FEE_BPS"
        );
        c
    }
}

impl Default for ProtocolConsts {
    fn default() -> Self {
        Self::canonical()
    }
}

/// Seller CLI liveness timings for a resting SELL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SellerLivenessParams {
    /// Time between complete gateway/upstream health cycles.
    pub health_interval: Duration,
    /// Per-cycle budget for gateway and exact-model upstream readiness.
    pub health_check_timeout: Duration,
    /// Maximum time from a completed failed health cycle to a terminal order fact.
    pub health_cycle_timeout: Duration,
    /// Standalone graceful-shutdown cancellation confirmation budget.
    pub cancel_confirmation_timeout: Duration,
    /// Poll interval while reconciling exact order state.
    pub cancel_confirmation_poll: Duration,
    /// Poll interval used only to notice a terminated gateway task.
    pub gateway_task_poll: Duration,
}

impl SellerLivenessParams {
    /// Canonical values from.
    pub const fn canonical() -> Self {
        Self {
            health_interval: Duration::from_secs(20),
            health_check_timeout: Duration::from_secs(20),
            health_cycle_timeout: Duration::from_secs(60),
            cancel_confirmation_timeout: Duration::from_secs(60),
            cancel_confirmation_poll: Duration::from_secs(2),
            gateway_task_poll: Duration::from_millis(100),
        }
    }
}

impl Default for SellerLivenessParams {
    fn default() -> Self {
        Self::canonical()
    }
}

/// Maximum wait for the authoritative buyer-owned `StreamStopped` receipt.
pub const SELLER_TERMINAL_RECEIPT_TIMEOUT: Duration = Duration::from_secs(120);
/// Poll interval while the exact `StreamStopped` receipt is not yet visible.
pub const SELLER_TERMINAL_RECEIPT_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Order book deploy parameters. In they are filled by a mock; in production they are read from on-chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DobParams {
    /// Tick size in tokens; reference value 1M.
    pub tick_size: u64,
}

impl DobParams {
    /// Canonical reference for: `TICK_SIZE = 1M`.
    pub const fn canonical() -> Self {
        Self {
            tick_size: 1_000_000,
        }
    }
}

impl Default for DobParams {
    fn default() -> Self {
        Self::canonical()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SellerLivenessParams, HERMEZ_SRS_MAX_ATTEMPTS, HERMEZ_SRS_RETRY_INITIAL_BACKOFF,
        HERMEZ_SRS_SIZE_BYTES, SELLER_TERMINAL_RECEIPT_POLL_INTERVAL,
        SELLER_TERMINAL_RECEIPT_TIMEOUT,
    };
    use std::time::Duration;

    #[test]
    fn seller_liveness_parameters_match_directive_668() {
        let params = SellerLivenessParams::canonical();
        assert_eq!(params.health_interval, Duration::from_secs(20));
        assert_eq!(params.health_check_timeout, Duration::from_secs(20));
        assert_eq!(params.health_cycle_timeout, Duration::from_secs(60));
        assert_eq!(params.cancel_confirmation_timeout, Duration::from_secs(60));
        assert_eq!(params.cancel_confirmation_poll, Duration::from_secs(2));
        assert_eq!(params.gateway_task_poll, Duration::from_millis(100));
    }

    #[test]
    fn seller_terminal_receipt_parameters_are_canonical() {
        assert_eq!(SELLER_TERMINAL_RECEIPT_TIMEOUT, Duration::from_secs(120));
        assert_eq!(
            SELLER_TERMINAL_RECEIPT_POLL_INTERVAL,
            Duration::from_secs(3)
        );
    }

    #[test]
    fn hermez_srs_download_parameters_match_the_directive() {
        assert_eq!(HERMEZ_SRS_SIZE_BYTES, 67_109_124);
        assert_eq!(HERMEZ_SRS_MAX_ATTEMPTS, 5);
        assert_eq!(HERMEZ_SRS_RETRY_INITIAL_BACKOFF, Duration::from_secs(1));
    }
}
