//! Client-side ModelRegistry policy for issue.
//! The registry is an on-chain authority. This module keeps the local pieces
//! reusable and testable: strict operator config, read-only registry facts, and
//! role-neutral validation against dexdo's own model hash/book derivation.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

#[cfg(feature = "shellnet")]
use serde_json::json;
#[cfg(feature = "shellnet")]
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};
#[cfg(feature = "shellnet")]
use tokio::sync::OnceCell;

#[cfg(feature = "shellnet")]
type RegistryAccountSnapshot = std::result::Result<String, String>;

pub const MODEL_REGISTRY_ABI_JSON: &str =
    include_str!("../../../contracts/compiled/airegistry/ModelRegistry.abi.json");
pub const MODEL_REGISTRY_VALIDATION_SCHEMA: &str = "dexdo.model_registry_validation.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryRole {
    Seller,
    Buyer,
}

impl RegistryRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Seller => "seller",
            Self::Buyer => "buyer",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegistryValidationInput {
    pub config_path: Option<PathBuf>,
    pub address_override: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryValidationPolicy {
    pub network: String,
    pub registry_address: Option<String>,
    pub seller_check_model_registry: bool,
    pub seller_deploy_missing_order_book: bool,
    pub buyer_check_model_registry: bool,
    pub source: Option<PathBuf>,
    pub address_overridden: bool,
}

impl RegistryValidationPolicy {
    pub fn load(input: &RegistryValidationInput, contracts: &Path) -> Result<Self> {
        if input.config_path.is_none() && input.address_override.is_none() {
            return Ok(Self::disabled());
        }
        let Some(path) = input.config_path.as_deref() else {
            bail!("--model-registry-address requires --model-registry-validation <config.json>");
        };
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read --model-registry-validation {}", path.display()))?;
        let raw = RawRegistryValidationConfig::from_json(&text)
            .with_context(|| format!("--model-registry-validation {}", path.display()))?;
        let mut address = raw.registry.address;
        let mut overridden = false;
        if let Some(override_addr) = input.address_override.as_deref() {
            address = Some(
                validate_registry_address(override_addr)
                    .with_context(|| format!("--model-registry-address {override_addr}"))?,
            );
            overridden = true;
        }
        if address.is_none() && (raw.seller.check_model_registry || raw.buyer.check_model_registry)
        {
            address = Some(default_registry_address(contracts).with_context(|| {
                format!(
                    "read default ModelRegistry address from {}",
                    contracts.display()
                )
            })?);
        }
        Ok(Self {
            network: raw.registry.network,
            registry_address: address,
            seller_check_model_registry: raw.seller.check_model_registry,
            seller_deploy_missing_order_book: raw.seller.deploy_missing_order_book,
            buyer_check_model_registry: raw.buyer.check_model_registry,
            source: Some(path.to_path_buf()),
            address_overridden: overridden,
        })
    }

    pub fn disabled() -> Self {
        Self {
            network: "shellnet".to_string(),
            registry_address: None,
            seller_check_model_registry: false,
            seller_deploy_missing_order_book: false,
            buyer_check_model_registry: false,
            source: None,
            address_overridden: false,
        }
    }

    pub fn check_enabled(&self, role: RegistryRole) -> bool {
        match role {
            RegistryRole::Seller => self.seller_check_model_registry,
            RegistryRole::Buyer => self.buyer_check_model_registry,
        }
    }

    pub fn required_address(&self, role: RegistryRole) -> Result<&str> {
        self.registry_address.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "{} model registry check enabled but no ModelRegistry address is configured",
                role.as_str()
            )
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRegistryValidationConfig {
    schema: String,
    registry: RawRegistrySection,
    seller: RawSellerSection,
    buyer: RawBuyerSection,
}

impl RawRegistryValidationConfig {
    fn from_json(text: &str) -> Result<Self> {
        let mut cfg: RawRegistryValidationConfig =
            serde_json::from_str(text).context("parse JSON")?;
        if cfg.schema != MODEL_REGISTRY_VALIDATION_SCHEMA {
            bail!(
                "schema must be `{MODEL_REGISTRY_VALIDATION_SCHEMA}`, got `{}`",
                cfg.schema
            );
        }
        if cfg.registry.network != "shellnet" {
            bail!(
                "registry.network `{}` is unsupported (only `shellnet` is supported)",
                cfg.registry.network
            );
        }
        if let Some(addr) = cfg.registry.address.as_deref() {
            cfg.registry.address = Some(validate_registry_address(addr)?);
        }
        Ok(cfg)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRegistrySection {
    #[serde(default)]
    address: Option<String>,
    network: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSellerSection {
    check_model_registry: bool,
    deploy_missing_order_book: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBuyerSection {
    check_model_registry: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelRegistryEntry {
    pub exists: bool,
    pub model_hash: String,
    pub order_book: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelRegistryFacts {
    pub frame_model: String,
    pub model_hash: String,
    pub order_book: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedModelIdentity {
    pub requested_model: String,
    pub registry_model: String,
    pub model_hash: String,
    pub order_book: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryBookAction {
    UseActive,
    SellerMayDeployMissing,
    BuyerHideMissing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuyerMissingBookPolicy {
    Reject,
    HideFromAvailableList,
}

#[async_trait]
pub trait ModelRegistryReader: Send + Sync {
    async fn model(&self, frame_model: &str) -> Result<Option<ModelRegistryEntry>>;

    async fn registered_model_names(&self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
}

const REGISTERED_MODEL_SUGGESTION_LIMIT: usize = 5;

pub async fn validate_registered_model(
    reader: &(dyn ModelRegistryReader + Send + Sync),
    role: RegistryRole,
    registry_address: &str,
    frame_model: &str,
    expected_order_book: &str,
) -> Result<ModelRegistryFacts> {
    let registry_display = dexdo_core::address::display(registry_address);
    let expected_model_hash = dexdo_core::model_hash_for(frame_model);
    let expected_order_book = validate_registry_address(expected_order_book)
        .with_context(|| format!("expected orderBook for frame_model {frame_model}"))?;
    let Some(entry) = reader.model(frame_model).await? else {
        bail!(
            "{} model registry check failed: frame_model {} is not registered in ModelRegistry {}",
            role.as_str(),
            frame_model,
            registry_display
        );
    };
    if !entry.exists {
        bail!(
            "{} model registry check failed: frame_model {} is not registered in ModelRegistry {}",
            role.as_str(),
            frame_model,
            registry_display
        );
    }
    if normalize_hash(&entry.model_hash) != normalize_hash(&expected_model_hash) {
        bail!(
            "{} model registry check failed: frame_model {} ModelRegistry {} modelHash {} != sha256(frame_model) {}",
            role.as_str(),
            frame_model,
            registry_display,
            entry.model_hash,
            expected_model_hash
        );
    }
    if let Some(registry_order_book) =
        nonzero_registry_order_book(&entry.order_book).with_context(|| {
            format!(
                "{} model registry check failed: frame_model {} ModelRegistry {} returned malformed orderBook",
                role.as_str(),
                frame_model,
                registry_display
            )
        })?
    {
        if registry_order_book != expected_order_book {
            bail!(
                "{} model registry check failed: frame_model {} ModelRegistry {} orderBook {} != dexdo derived orderBook {}",
                role.as_str(),
                frame_model,
                registry_display,
                dexdo_core::address::display(&registry_order_book),
                dexdo_core::address::display(&expected_order_book)
            );
        }
    }
    Ok(ModelRegistryFacts {
        frame_model: frame_model.to_string(),
        model_hash: expected_model_hash,
        order_book: expected_order_book,
    })
}

pub async fn resolve_registered_model_identity(
    reader: &(dyn ModelRegistryReader + Send + Sync),
    role: RegistryRole,
    registry_address: &str,
    claimed_model: &str,
) -> Result<ResolvedModelIdentity> {
    let registry_display = dexdo_core::address::display(registry_address);
    let candidates = registry_identity_candidates(claimed_model);
    let mut misses = Vec::new();
    for candidate in &candidates {
        match reader.model(candidate).await? {
            Some(entry) if entry.exists => {
                let expected_model_hash = dexdo_core::model_hash_for(candidate);
                if normalize_hash(&entry.model_hash) != normalize_hash(&expected_model_hash) {
                    bail!(
                        "{} content identity registry check failed: claimed model {} resolved to ModelRegistry {} entry {} but modelHash {} != sha256(entry) {}",
                        role.as_str(),
                        claimed_model,
                        registry_display,
                        candidate,
                        entry.model_hash,
                        expected_model_hash
                    );
                }
                let order_book =
                    nonzero_registry_order_book(&entry.order_book).with_context(|| {
                        format!(
                            "{} content identity registry check failed: ModelRegistry {} entry {} returned malformed orderBook",
                            role.as_str(),
                            registry_display,
                            candidate
                        )
                    })?;
                return Ok(ResolvedModelIdentity {
                    requested_model: claimed_model.to_string(),
                    registry_model: candidate.clone(),
                    model_hash: expected_model_hash,
                    order_book: order_book.unwrap_or_default(),
                });
            }
            _ => misses.push(candidate.clone()),
        }
    }
    let suggestions = registered_model_suggestions(reader, claimed_model)
        .await
        .unwrap_or_default();
    if !suggestions.is_empty() {
        bail!(
            "{} content identity registry check failed: claimed model {} does not resolve to a registered ModelRegistry {} identity; tried {:?}; registered canonical suggestions: {:?}",
            role.as_str(),
            claimed_model,
            registry_display,
            misses,
            suggestions
        );
    }
    bail!(
        "{} content identity registry check failed: claimed model {} does not resolve to a registered ModelRegistry {} identity; tried {:?}",
        role.as_str(),
        claimed_model,
        registry_display,
        misses
    )
}

async fn registered_model_suggestions(
    reader: &(dyn ModelRegistryReader + Send + Sync),
    claimed_model: &str,
) -> Result<Vec<String>> {
    let discovered = reader.registered_model_names().await?;
    let forbidden_aliases = served_model_suggestion_aliases(claimed_model);
    let comparison = claimed_model.trim().to_ascii_lowercase();
    let mut ranked = discovered
        .into_iter()
        .filter(|name| !name.is_empty())
        .filter(|name| {
            let comparison_name = name.to_ascii_lowercase();
            !forbidden_aliases
                .iter()
                .any(|alias| alias == &comparison_name)
        })
        .map(|name| {
            let distance = ascii_case_folded_levenshtein_distance(&comparison, &name);
            (distance, name)
        })
        .collect::<Vec<_>>();
    ranked.sort_unstable_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.as_bytes().cmp(right.1.as_bytes()))
    });
    ranked.dedup_by(|left, right| left.1 == right.1);
    ranked.truncate(REGISTERED_MODEL_SUGGESTION_LIMIT);

    let mut suggestions = Vec::new();
    for (_, name) in ranked {
        let Ok(Some(entry)) = reader.model(&name).await else {
            continue;
        };
        let expected_model_hash = dexdo_core::model_hash_for(&name);
        if !entry.exists
            || normalize_hash(&entry.model_hash) != normalize_hash(&expected_model_hash)
        {
            continue;
        }
        let Ok(Some(order_book)) = nonzero_registry_order_book(&entry.order_book) else {
            continue;
        };
        #[cfg(feature = "shellnet")]
        {
            let Ok(expected_order_book) =
                dexdo_core::RealChainBackend::canonical_inference_orderbook_address(
                    &expected_model_hash,
                )
            else {
                continue;
            };
            if order_book != expected_order_book.with_workchain() {
                continue;
            }
        }
        #[cfg(not(feature = "shellnet"))]
        let _ = order_book;
        suggestions.push(name);
    }
    Ok(suggestions)
}

#[cfg(any(feature = "shellnet", test))]
fn model_registry_names_from_storage_fields(fields: &Value) -> Result<Vec<String>> {
    let mut names = fields
        .get("_models")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("ModelRegistry storage exposes no _models map"))?
        .values()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow::anyhow!("ModelRegistry _models entry is not a string"))
        })
        .collect::<Result<Vec<_>>>()?;
    names.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    names.dedup();
    Ok(names)
}

fn served_model_suggestion_aliases(model_id: &str) -> Vec<String> {
    let normalized = model_id.trim().to_ascii_lowercase();
    let mut aliases = Vec::new();
    if normalized.contains('/') {
        push_candidate(&mut aliases, &normalized);
        if let Some(display_alias) = display_case_served_alias(&normalized) {
            push_candidate(&mut aliases, &display_alias);
        }
    }
    if let Some(alias) = frame_model_to_served_alias(&normalized) {
        push_candidate(&mut aliases, &alias);
        if let Some(display_alias) = display_case_served_alias(&alias) {
            push_candidate(&mut aliases, &display_alias);
        }
    }
    aliases
        .into_iter()
        .map(|alias| alias.to_ascii_lowercase())
        .collect()
}

fn ascii_case_folded_levenshtein_distance(left: &str, right: &str) -> usize {
    let left = left.as_bytes();
    let right = right.to_ascii_lowercase();
    let right = right.as_bytes();
    let mut previous = (0..=right.len()).collect::<Vec<_>>();
    let mut current = vec![0; right.len() + 1];
    for (left_index, left_byte) in left.iter().enumerate() {
        current[0] = left_index + 1;
        for (right_index, right_byte) in right.iter().enumerate() {
            current[right_index + 1] = if left_byte == right_byte {
                previous[right_index]
            } else {
                1 + previous[right_index]
                    .min(previous[right_index + 1])
                    .min(current[right_index])
            };
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right.len()]
}

pub fn registry_identity_candidates(model_id: &str) -> Vec<String> {
    let trimmed = model_id.trim();
    let mut out = Vec::new();
    push_candidate(&mut out, trimmed);

    let alias = model_id_alias(trimmed);
    push_candidate(&mut out, &alias);

    if let Some(display_alias) = display_case_served_alias(&alias) {
        push_candidate(&mut out, &display_alias);
    }
    out
}

pub fn model_id_alias(model_id: &str) -> String {
    let normalized = model_id.trim().to_ascii_lowercase();
    frame_model_to_served_alias(&normalized).unwrap_or(normalized)
}

fn frame_model_to_served_alias(model_id: &str) -> Option<String> {
    if let Ok(canonical) = dexdo_core::parse_canonical_model_id(model_id) {
        return Some(format!(
            "{}/{}-{}",
            canonical.producer, canonical.model, canonical.version
        ));
    }

    let (vendor, rest) = model_id.split_once("--")?;
    if vendor.is_empty() || rest.is_empty() {
        return None;
    }
    let rest = rest.replace("--", "-");
    if rest.is_empty() {
        return None;
    }
    Some(format!("{vendor}/{rest}"))
}

fn display_case_served_alias(model_id: &str) -> Option<String> {
    let (vendor, rest) = model_id.split_once('/')?;
    if vendor.is_empty() || rest.is_empty() {
        return None;
    }
    Some(format!(
        "{}/{}",
        display_case_token(vendor),
        rest.split('-')
            .map(display_case_token)
            .collect::<Vec<_>>()
            .join("-")
    ))
}

fn display_case_token(token: &str) -> String {
    let mut chars = token.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    if first.is_ascii_digit() {
        return token.to_ascii_uppercase();
    }
    format!("{}{}", first.to_uppercase(), chars.as_str())
}

fn push_candidate(out: &mut Vec<String>, candidate: &str) {
    let candidate = candidate.trim();
    if candidate.is_empty() || out.iter().any(|item| item == candidate) {
        return;
    }
    out.push(candidate.to_string());
}

pub async fn enforce_model_registry_policy(
    reader: &(dyn ModelRegistryReader + Send + Sync),
    role: RegistryRole,
    policy: &RegistryValidationPolicy,
    frame_model: &str,
    expected_order_book: &str,
    order_book_active: bool,
    buyer_missing_book_policy: BuyerMissingBookPolicy,
) -> Result<RegistryBookAction> {
    let registry_address = policy.required_address(role)?;
    validate_registered_model(
        reader,
        role,
        registry_address,
        frame_model,
        expected_order_book,
    )
    .await?;
    order_book_availability(
        role,
        registry_address,
        frame_model,
        expected_order_book,
        order_book_active,
        policy.seller_deploy_missing_order_book,
        buyer_missing_book_policy,
    )
}

pub fn validate_order_book_availability(
    role: RegistryRole,
    registry_address: &str,
    frame_model: &str,
    order_book: &str,
    active: bool,
    seller_deploy_missing_order_book: bool,
) -> Result<RegistryBookAction> {
    order_book_availability(
        role,
        registry_address,
        frame_model,
        order_book,
        active,
        seller_deploy_missing_order_book,
        BuyerMissingBookPolicy::Reject,
    )
}

pub fn order_book_availability(
    role: RegistryRole,
    registry_address: &str,
    frame_model: &str,
    order_book: &str,
    active: bool,
    seller_deploy_missing_order_book: bool,
    buyer_missing_book_policy: BuyerMissingBookPolicy,
) -> Result<RegistryBookAction> {
    if active {
        return Ok(RegistryBookAction::UseActive);
    }
    match role {
        RegistryRole::Seller if seller_deploy_missing_order_book => {
            Ok(RegistryBookAction::SellerMayDeployMissing)
        }
        RegistryRole::Seller => bail!(
            "seller model registry check failed: frame_model {frame_model} canonical order book {} from ModelRegistry {} is not deployed and seller.deploy_missing_order_book=false",
            dexdo_core::address::display(order_book),
            dexdo_core::address::display(registry_address)
        ),
        RegistryRole::Buyer
            if buyer_missing_book_policy == BuyerMissingBookPolicy::HideFromAvailableList =>
        {
            Ok(RegistryBookAction::BuyerHideMissing)
        }
        RegistryRole::Buyer => bail!(
            "buyer model registry check failed: frame_model {frame_model} canonical order book {} from ModelRegistry {} is not deployed; not available to buy now",
            dexdo_core::address::display(order_book),
            dexdo_core::address::display(registry_address)
        ),
    }
}

#[derive(Clone, Debug)]
pub struct UnavailableModelRegistryReader {
    reason: String,
}

impl UnavailableModelRegistryReader {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[async_trait]
impl ModelRegistryReader for UnavailableModelRegistryReader {
    async fn model(&self, _frame_model: &str) -> Result<Option<ModelRegistryEntry>> {
        bail!("{}", self.reason)
    }
}

#[cfg(feature = "shellnet")]
pub struct ShellnetModelRegistryReader {
    chain: dexdo_core::RealChainBackend,
    registry_address: dexdo_core::Address,
    abi_json: String,
    account_boc: Arc<OnceCell<RegistryAccountSnapshot>>,
    getter_runner: dexdo_core::airegistry::run::GetterRunner,
}

#[cfg(feature = "shellnet")]
impl ShellnetModelRegistryReader {
    pub fn from_manifest(contracts: &Path, registry_address: &str) -> Result<Self> {
        Self::from_manifest_with_endpoint(contracts, None, registry_address)
    }

    pub fn from_manifest_with_endpoint(
        contracts: &Path,
        endpoint: Option<&str>,
        registry_address: &str,
    ) -> Result<Self> {
        Self::from_manifest_abi_json(contracts, endpoint, registry_address, MODEL_REGISTRY_ABI_JSON)
    }

    pub fn from_manifest_abi_json(
        contracts: &Path,
        endpoint: Option<&str>,
        registry_address: &str,
        abi_json: &str,
    ) -> Result<Self> {
        validate_model_registry_abi_getters(abi_json).context("embedded ModelRegistry ABI")?;
        // The ModelRegistry is a shared-DApp account and this field is the chain address every
        // getter below is run against, so only the chain half is stored.
        let registry_address = dexdo_core::address::parse_chain_address(registry_address)
            .map_err(|e| anyhow::anyhow!("ModelRegistry address {registry_address}: {e}"))?
            .into_chain();
        let chain = dexdo_core::RealChainBackend::connect_with_endpoint(contracts, endpoint)
            .with_context(|| format!("connect shellnet using {}", contracts.display()))?;
        let snapshot_key = format!(
            "{}\0{}",
            chain.client().endpoint(),
            registry_address.with_workchain()
        );
        let account_boc = registry_account_snapshots()
            .lock()
            .map_err(|_| anyhow::anyhow!("ModelRegistry snapshot lock is poisoned"))?
            .entry(snapshot_key)
            .or_default()
            .clone();
        Ok(Self {
            chain,
            registry_address,
            abi_json: abi_json.to_string(),
            account_boc,
            getter_runner: dexdo_core::airegistry::run::GetterRunner::new()
                .context("create local ModelRegistry getter runner")?,
        })
    }

    /// Download this registry account once for the lifetime of the CLI process.
    /// Every getter then runs locally against this immutable startup snapshot.
    pub async fn read_account_once(&self) -> Result<()> {
        self.account_boc().await.map(|_| ())
    }

    async fn account_boc(&self) -> Result<&str> {
        let account = self
            .account_boc
            .get_or_init(|| async {
                let read = async {
                    let account = self
                        .chain
                        .client()
                        .get_account(&self.registry_address)
                        .await?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "ModelRegistry {} account was not found",
                                dexdo_core::address::display(
                                    &self.registry_address.with_workchain()
                                )
                            )
                        })?;
                    if !account.is_active() {
                        bail!(
                            "ModelRegistry {} is not active (status {})",
                            dexdo_core::address::display(&self.registry_address.with_workchain()),
                            account.status
                        );
                    }
                    account.boc.ok_or_else(|| {
                        anyhow::anyhow!(
                            "active ModelRegistry {} returned no account BOC",
                            dexdo_core::address::display(&self.registry_address.with_workchain())
                        )
                    })
                };
                read.await
                    .map_err(|error: anyhow::Error| format!("{error:#}"))
            })
            .await;
        account
            .as_deref()
            .map_err(|error| anyhow::anyhow!(error.clone()))
    }

    async fn getter(&self, method: &str, frame_model: &str) -> Result<Value> {
        self.getter_runner
            .run_getter(
                &self.abi_json,
                &self.registry_address.with_workchain(),
                self.account_boc().await?,
                method,
                json!({ "canonicalName": frame_model }),
            )
            .await
    }
}

#[cfg(feature = "shellnet")]
fn registry_account_snapshots(
) -> &'static Mutex<HashMap<String, Arc<OnceCell<RegistryAccountSnapshot>>>> {
    static SNAPSHOTS: OnceLock<Mutex<HashMap<String, Arc<OnceCell<RegistryAccountSnapshot>>>>> =
        OnceLock::new();
    SNAPSHOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(feature = "shellnet")]
#[async_trait]
impl ModelRegistryReader for ShellnetModelRegistryReader {
    async fn model(&self, frame_model: &str) -> Result<Option<ModelRegistryEntry>> {
        let has = self
            .getter("has", frame_model)
            .await
            .with_context(|| format!("ModelRegistry has({frame_model})"))?;
        if !getter_bool(&has, &["value0"]).context("ModelRegistry.has returned no bool")? {
            return Ok(None);
        }

        let model_hash_of = self
            .getter("modelHashOf", frame_model)
            .await
            .with_context(|| format!("ModelRegistry modelHashOf({frame_model})"))?;
        let model_hash = getter_hash(&model_hash_of, &["value0"])
            .context("modelHashOf returned no modelHash")?;

        let order_book_of = self
            .getter("orderBookOf", frame_model)
            .await
            .with_context(|| format!("ModelRegistry orderBookOf({frame_model})"))?;
        let raw_order_book = getter_address(&order_book_of, &["value0"])
            .context("orderBookOf returned no address")?;
        let order_book = nonzero_registry_order_book(&raw_order_book)
            .context("orderBookOf returned malformed address")?
            .ok_or_else(|| anyhow::anyhow!("orderBookOf returned zero address"))?;

        Ok(Some(ModelRegistryEntry {
            exists: true,
            model_hash,
            order_book,
        }))
    }

    async fn registered_model_names(&self) -> Result<Vec<String>> {
        let fields = dexdo_core::RealChainBackend::decode_account_storage_fields(
            self.account_boc().await?,
            &self.abi_json,
            "ModelRegistry",
        )?;
        model_registry_names_from_storage_fields(&fields)
    }
}

pub fn validate_model_registry_abi_getters(abi_json: &str) -> Result<()> {
    let abi: Value = serde_json::from_str(abi_json).context("parse JSON")?;
    let functions = abi
        .get("functions")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("ABI has no functions array"))?;
    for required in [
        "has",
        "modelHashOf",
        "orderBookOf",
        "count",
        "inferenceOrderBookCode",
    ] {
        let found = functions
            .iter()
            .any(|f| f.get("name").and_then(|v| v.as_str()) == Some(required));
        if !found {
            bail!("ABI is missing required getter `{required}`");
        }
    }
    Ok(())
}

fn validate_registry_address(address: &str) -> Result<String> {
    dexdo_core::normalize_wallet_address(address)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("malformed ModelRegistry address `{address}`"))
}

fn nonzero_registry_order_book(raw: &str) -> Result<Option<String>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || is_zero_address_like(trimmed) {
        return Ok(None);
    }
    validate_registry_address(trimmed).map(Some)
}

fn is_zero_address_like(raw: &str) -> bool {
    let bare = raw
        .trim()
        .strip_prefix("0:")
        .or_else(|| raw.trim().strip_prefix("0x"))
        .or_else(|| raw.trim().strip_prefix("0X"))
        .unwrap_or(raw.trim());
    !bare.is_empty() && bare.bytes().all(|b| b == b'0')
}

fn normalize_hash(hash: &str) -> String {
    hash.trim()
        .strip_prefix("0x")
        .or_else(|| hash.trim().strip_prefix("0X"))
        .unwrap_or(hash.trim())
        .to_ascii_lowercase()
}

fn default_registry_address(contracts: &Path) -> Result<String> {
    let text = std::fs::read_to_string(contracts)?;
    let json: serde_json::Value = serde_json::from_str(&text)?;
    let raw = json
        .get("model_registry")
        .or_else(|| json.get("modelRegistry"))
        .or_else(|| json.get("ModelRegistry"))
        .and_then(address_from_value)
        .or_else(|| {
            json.get("registry")
                .and_then(|v| v.get("model_registry").or_else(|| v.get("modelRegistry")))
                .and_then(address_from_value)
        })
        .ok_or_else(|| {
            anyhow::anyhow!("contracts manifest has no `model_registry` / `modelRegistry` address")
        })?;
    validate_registry_address(raw)
}

pub fn default_model_registry_address(contracts: &Path) -> Result<String> {
    default_registry_address(contracts)
}

fn address_from_value(value: &serde_json::Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.get("address").and_then(|v| v.as_str()))
}

#[cfg(feature = "shellnet")]
fn getter_bool(value: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|key| {
        let v = value.get(*key)?;
        v.as_bool().or_else(|| match v.as_str()?.trim() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
    })
}

#[cfg(feature = "shellnet")]
fn getter_hash(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        let v = value.get(*key)?;
        if let Some(s) = v.as_str() {
            let s = s.trim();
            if s.is_empty() {
                None
            } else if s.starts_with("0x") || s.starts_with("0X") {
                Some(format!("0x{}", normalize_hash(s)))
            } else if s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
                Some(format!("0x{}", s.to_ascii_lowercase()))
            } else {
                None
            }
        } else {
            v.as_u64().map(|n| format!("0x{n:064x}"))
        }
    })
}

#[cfg(feature = "shellnet")]
fn getter_address(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        let s = value.get(*key)?.as_str()?.trim();
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    const ADDR1: &str = "0:1111111111111111111111111111111111111111111111111111111111111111";
    const ADDR2: &str = "0:2222222222222222222222222222222222222222222222222222222222222222";
    const REG: &str = "0:9999999999999999999999999999999999999999999999999999999999999999";
    const ZERO_ADDR: &str = "0:0000000000000000000000000000000000000000000000000000000000000000";

    fn config(seller: bool, buyer: bool) -> String {
        format!(
            r#"{{
              "schema": "{MODEL_REGISTRY_VALIDATION_SCHEMA}",
              "registry": {{ "address": "{REG}", "network": "shellnet" }},
              "seller": {{ "check_model_registry": {seller}, "deploy_missing_order_book": false }},
              "buyer": {{ "check_model_registry": {buyer} }}
            }}"#
        )
    }

    #[test]
    fn parser_accepts_explicit_seller_buyer_booleans() {
        let dir = temp_dir("registry-config-ok");
        let dir = dir.path();
        let contracts = write_contracts(dir, ADDR1);
        let cfg_path = dir.join("registry.json");
        std::fs::write(&cfg_path, config(true, false)).unwrap();
        let policy = RegistryValidationPolicy::load(
            &RegistryValidationInput {
                config_path: Some(cfg_path),
                address_override: None,
            },
            &contracts,
        )
        .unwrap();
        assert!(policy.check_enabled(RegistryRole::Seller));
        assert!(!policy.check_enabled(RegistryRole::Buyer));
        assert!(!policy.seller_deploy_missing_order_book);
        assert_eq!(policy.required_address(RegistryRole::Seller).unwrap(), REG);
    }

    #[test]
    fn parser_accepts_seller_deploy_missing_book_independently() {
        let dir = temp_dir("registry-config-deploy-missing");
        let dir = dir.path();
        let contracts = write_contracts(dir, ADDR1);
        let cfg_path = dir.join("registry.json");
        std::fs::write(
            &cfg_path,
            config(false, true).replace(
                r#""deploy_missing_order_book": false"#,
                r#""deploy_missing_order_book": true"#,
            ),
        )
        .unwrap();
        let policy = RegistryValidationPolicy::load(
            &RegistryValidationInput {
                config_path: Some(cfg_path),
                address_override: None,
            },
            &contracts,
        )
        .unwrap();
        assert!(!policy.check_enabled(RegistryRole::Seller));
        assert!(policy.check_enabled(RegistryRole::Buyer));
        assert!(policy.seller_deploy_missing_order_book);
    }

    #[test]
    fn parser_rejects_malformed_config() {
        let bad_configs = vec![
            r#"{"registry":{"address":"0:aaaa","network":"shellnet"},"seller":{"check_model_registry":true},"buyer":{"check_model_registry":true}}"#.to_string(),
            config(true, true).replace(r#""buyer": {"#, r#""extra": 1, "buyer": {"#),
            config(true, true).replace(REG, "0:dead"),
            config(true, true)
                .replace(r#""check_model_registry": true"#, r#""check_model_registry": "yes""#),
            config(true, true).replace(r#""network": "shellnet""#, r#""network": "mainnet""#),
        ];
        for bad in bad_configs {
            assert!(
                RawRegistryValidationConfig::from_json(&bad).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn default_address_reads_contracts_manifest_when_enabled() {
        let dir = temp_dir("registry-config-default");
        let dir = dir.path();
        let contracts = write_contracts(dir, ADDR2);
        let cfg_path = dir.join("registry.json");
        std::fs::write(
            &cfg_path,
            format!(
                r#"{{
                  "schema": "{MODEL_REGISTRY_VALIDATION_SCHEMA}",
                  "registry": {{ "network": "shellnet" }},
                  "seller": {{ "check_model_registry": true, "deploy_missing_order_book": false }},
                  "buyer": {{ "check_model_registry": false }}
                }}"#
            ),
        )
        .unwrap();
        let policy = RegistryValidationPolicy::load(
            &RegistryValidationInput {
                config_path: Some(cfg_path),
                address_override: None,
            },
            &contracts,
        )
        .unwrap();
        assert_eq!(
            policy.required_address(RegistryRole::Seller).unwrap(),
            ADDR2
        );
    }

    #[test]
    fn default_address_reads_committed_shellnet_manifest() {
        let contracts = repo_path("contracts/deployed.shellnet.json");
        let address = default_registry_address(&contracts).unwrap();
        assert_eq!(
            address,
            "0:0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d"
        );
    }

    #[derive(Default)]
    struct FakeReader {
        entries: Mutex<BTreeMap<String, Option<ModelRegistryEntry>>>,
        queries: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl ModelRegistryReader for FakeReader {
        async fn model(&self, frame_model: &str) -> Result<Option<ModelRegistryEntry>> {
            self.queries.lock().unwrap().push(frame_model.to_string());
            Ok(self
                .entries
                .lock()
                .unwrap()
                .get(frame_model)
                .cloned()
                .unwrap_or(None))
        }
    }

    impl FakeReader {
        fn with(self, frame_model: &str, entry: Option<ModelRegistryEntry>) -> Self {
            self.entries
                .lock()
                .unwrap()
                .insert(frame_model.to_string(), entry);
            self
        }

        fn queries(&self) -> Vec<String> {
            self.queries.lock().unwrap().clone()
        }
    }

    fn registered_entry(frame_model: &str, order_book: &str) -> ModelRegistryEntry {
        ModelRegistryEntry {
            exists: true,
            model_hash: dexdo_core::model_hash_for(frame_model),
            order_book: order_book.to_string(),
        }
    }

    fn policy(seller_deploy_missing_order_book: bool) -> RegistryValidationPolicy {
        RegistryValidationPolicy {
            network: "shellnet".to_string(),
            registry_address: Some(REG.to_string()),
            seller_check_model_registry: true,
            seller_deploy_missing_order_book,
            buyer_check_model_registry: true,
            source: None,
            address_overridden: false,
        }
    }

    #[test]
    fn model_registry_abi_getter_shape_matches_4_0_18() {
        let abi = MODEL_REGISTRY_ABI_JSON;
        validate_model_registry_abi_getters(abi).unwrap();

        let parsed: Value = serde_json::from_str(abi).unwrap();
        let functions = parsed["functions"].as_array().unwrap();
        for removed in ["getModel", "getAll"] {
            assert!(
                !functions
                    .iter()
                    .any(|f| f.get("name").and_then(|v| v.as_str()) == Some(removed)),
                "4.0.18 ModelRegistry ABI must not expose removed getter {removed}"
            );
        }

        let missing = r#"{"functions":[{"name":"has"},{"name":"orderBookOf"},{"name":"count"},{"name":"inferenceOrderBookCode"}]}"#;
        let err = validate_model_registry_abi_getters(missing)
            .unwrap_err()
            .to_string();
        assert!(err.contains("modelHashOf"), "{err}");
    }

    #[test]
    fn model_registry_reader_uses_embedded_abi_not_filesystem_path() {
        let source = include_str!("registry.rs");
        let reader_impl = source
            .find("impl ShellnetModelRegistryReader")
            .expect("reader impl present");
        let impl_end = source[reader_impl..]
            .find("#[cfg(feature = \"shellnet\")]\n#[async_trait]")
            .map(|offset| reader_impl + offset)
            .expect("reader impl end marker present");
        let body = &source[reader_impl..impl_end];

        assert!(
            source.contains(
                "include_str!(\"../../../contracts/compiled/airegistry/ModelRegistry.abi.json\")"
            ),
            "ModelRegistry ABI must be embedded"
        );
        assert!(
            body.contains("pub fn from_manifest(contracts: &Path, registry_address: &str)"),
            "released binary constructor must not require an ABI path"
        );
        assert!(
            !body.contains("read_to_string(abi_path)"),
            "released binary reader must not read the ModelRegistry ABI from cwd/filesystem"
        );
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn model_registry_reader_prefers_explicit_endpoint_over_manifest() {
        let dir = temp_dir("registry-explicit-endpoint");
        let contracts = dir.path().join("deployed.shellnet.json");
        std::fs::write(
            &contracts,
            serde_json::json!({
                "network": "shellnet",
                "endpoint": "https://stale-manifest.example/graphql",
                "superroot": ZERO_ADDR,
                "dapp_config": "",
                "dapp_id": "0".repeat(64),
                "model_registry": REG
            })
            .to_string(),
        )
        .unwrap();

        let reader = ShellnetModelRegistryReader::from_manifest_with_endpoint(
            &contracts,
            Some("https://explicit.example/graphql"),
            REG,
        )
        .expect("construct registry reader without a chain request");

        assert_eq!(reader.chain.client().endpoint(), "https://explicit.example");
    }

    #[cfg(feature = "shellnet")]
    #[tokio::test]
    #[ignore = "read-only live shellnet evidence; requires current deployed.shellnet.json endpoint"]
    async fn live_shellnet_model_registry_reader_reads_seeded_model() {
        let contracts = repo_path("contracts/deployed.shellnet.json");
        let registry = default_registry_address(&contracts).unwrap();
        let registry_addr = dexdo_core::Address::parse(&registry).unwrap();
        let chain = dexdo_core::RealChainBackend::connect(&contracts).unwrap();
        let count = chain
            .client()
            .run_getter(&registry_addr, MODEL_REGISTRY_ABI_JSON, "count", json!({}))
            .await
            .expect("read live ModelRegistry count")
            .expect("ModelRegistry account active for count");
        let count_n = count
            .get("n")
            .or_else(|| count.get("value0"))
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            })
            .expect("ModelRegistry count returned no n/value0");
        assert!(count_n > 0, "live ModelRegistry count must be nonzero");
        let code = chain
            .client()
            .run_getter(
                &registry_addr,
                MODEL_REGISTRY_ABI_JSON,
                "inferenceOrderBookCode",
                json!({}),
            )
            .await
            .expect("read live ModelRegistry inferenceOrderBookCode")
            .expect("ModelRegistry account active for inferenceOrderBookCode");
        println!(
            "live ModelRegistry snapshot registry={} count={} inferenceOrderBookCode={}",
            registry, count_n, code
        );
        // These are live ModelRegistry seed names. They may differ from indexer
        // display refs such as normalized producer--model--version strings.
        let frame_models = ["Qwen/Qwen3-32B", "openai/gpt-oss-20b"];

        let reader = ShellnetModelRegistryReader::from_manifest(&contracts, &registry)
            .expect("shellnet ModelRegistry reader");
        let mut found = None;
        for frame_model in frame_models {
            if let Some(entry) = reader
                .model(frame_model)
                .await
                .unwrap_or_else(|e| panic!("read live ModelRegistry {frame_model}: {e}"))
            {
                found = Some((frame_model.to_string(), entry));
                break;
            }
        }
        let (frame_model, entry) =
            found.unwrap_or_else(|| panic!("no live seeded ModelRegistry entry found"));
        assert!(entry.exists);
        assert_eq!(
            normalize_hash(&entry.model_hash),
            normalize_hash(&dexdo_core::model_hash_for(&frame_model))
        );
        let order_book = nonzero_registry_order_book(&entry.order_book)
            .unwrap()
            .expect("seeded model exposes a derived orderBook");
        println!(
            "live ModelRegistry evidence registry={} frame_model={} model_hash={} order_book={}",
            registry, frame_model, entry.model_hash, order_book
        );
    }

    #[tokio::test]
    async fn validator_accepts_registered_matching_model() {
        let frame = "qwen--qwen3--32b";
        let reader = FakeReader::default().with(
            frame,
            Some(ModelRegistryEntry {
                exists: true,
                model_hash: dexdo_core::model_hash_for(frame),
                order_book: ADDR1.to_string(),
            }),
        );
        let facts = validate_registered_model(&reader, RegistryRole::Buyer, REG, frame, ADDR1)
            .await
            .unwrap();
        assert_eq!(facts.model_hash, dexdo_core::model_hash_for(frame));
        assert_eq!(facts.order_book, ADDR1);
    }

    #[tokio::test]
    async fn content_identity_resolves_each_qwen_alias_in_bounded_candidate_order() {
        for requested in ["qwen--qwen3--32b", "qwen/qwen3-32b", "Qwen/Qwen3-32B"] {
            let reader = FakeReader::default().with(
                "Qwen/Qwen3-32B",
                Some(registered_entry("Qwen/Qwen3-32B", ADDR1)),
            );
            let identity =
                resolve_registered_model_identity(&reader, RegistryRole::Buyer, REG, requested)
                    .await
                    .unwrap();
            assert_eq!(identity.requested_model, requested);
            assert_eq!(identity.registry_model, "Qwen/Qwen3-32B");
            assert_eq!(
                identity.model_hash,
                dexdo_core::model_hash_for("Qwen/Qwen3-32B")
            );
            assert_eq!(identity.order_book, ADDR1);
            let candidates = registry_identity_candidates(requested);
            let registered = candidates
                .iter()
                .position(|candidate| candidate == "Qwen/Qwen3-32B")
                .unwrap();
            assert!(candidates.len() <= 3);
            assert_eq!(reader.queries(), candidates[..=registered]);
        }
    }

    #[test]
    fn registry_identity_candidates_derive_served_aliases() {
        let cases = [
            ("qwen--qwen3--32b", "qwen/qwen3-32b"),
            ("openai--gpt-oss--20b", "openai/gpt-oss-20b"),
            ("openai--gpt--5.4-mini", "openai/gpt-5.4-mini"),
            ("vendor--family--variant", "vendor/family-variant"),
        ];
        for (input, served) in cases {
            let candidates = registry_identity_candidates(input);
            assert!(
                candidates.contains(&served.to_string()),
                "{input} candidates must include {served}: {candidates:?}"
            );
            assert_eq!(model_id_alias(input), served);
        }
    }

    #[test]
    fn issue_1227_model_alias_omits_canonical_flags() {
        assert_eq!(
            model_id_alias("qwen--qwen3--32b--w8k--tools"),
            "qwen/qwen3-32b"
        );
    }

    #[test]
    fn issue_1227_model_alias_preserves_three_part_output() {
        assert_eq!(model_id_alias("qwen--qwen3--32b"), "qwen/qwen3-32b");
    }

    #[test]
    fn issue_1227_model_alias_preserves_noncanonical_outputs() {
        let cases = [
            ("qwen/qwen3-32b", "qwen/qwen3-32b"),
            ("model-y", "model-y"),
            ("qwen--qwen3", "qwen/qwen3"),
            ("qwen--qwen3--32b--turbo", "qwen/qwen3-32b-turbo"),
        ];

        for (input, expected) in cases {
            assert_eq!(model_id_alias(input), expected, "input: {input}");
        }
    }

    #[tokio::test]
    async fn content_identity_rejects_unregistered_qwen_variant_without_family_fallback() {
        let reader = FakeReader::default().with(
            "Qwen/Qwen3-32B",
            Some(registered_entry("Qwen/Qwen3-32B", ADDR1)),
        );
        let err = resolve_registered_model_identity(
            &reader,
            RegistryRole::Buyer,
            REG,
            "qwen--qwen3.6--27b",
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("does not resolve"), "{err}");
        assert!(err.contains("buyer"), "{err}");
        // The registry address is rendered canonically now; identify it by account id.
        assert!(err.contains(REG.trim_start_matches("0:")), "{err}");
        assert!(
            err.contains("qwen--qwen3.6--27b"),
            "specific variant is reported: {err}"
        );
        for candidate in registry_identity_candidates("qwen--qwen3.6--27b") {
            assert!(
                err.contains(&candidate),
                "missing candidate {candidate}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn content_identity_resolves_openai_gpt_oss_seed_exactly() {
        let reader = FakeReader::default().with(
            "openai/gpt-oss-20b",
            Some(registered_entry("openai/gpt-oss-20b", ADDR1)),
        );
        let identity = resolve_registered_model_identity(
            &reader,
            RegistryRole::Buyer,
            REG,
            "openai--gpt-oss--20b",
        )
        .await
        .unwrap();
        assert_eq!(identity.registry_model, "openai/gpt-oss-20b");
    }

    #[tokio::test]
    async fn content_identity_resolves_openai_subscription_dash_id_to_registry_alias() {
        let reader = FakeReader::default().with(
            "openai/gpt-5.4-mini",
            Some(registered_entry("openai/gpt-5.4-mini", ADDR1)),
        );
        let identity = resolve_registered_model_identity(
            &reader,
            RegistryRole::Buyer,
            REG,
            "openai--gpt--5.4-mini",
        )
        .await
        .unwrap();
        assert_eq!(identity.registry_model, "openai/gpt-5.4-mini");
    }

    #[tokio::test]
    async fn validator_accepts_registered_name_hash_without_deployed_book_metadata() {
        let frame = "qwen--qwen3--32b";
        for registry_order_book in ["", ZERO_ADDR] {
            let reader = FakeReader::default()
                .with(frame, Some(registered_entry(frame, registry_order_book)));
            let facts = validate_registered_model(&reader, RegistryRole::Seller, REG, frame, ADDR1)
                .await
                .unwrap();
            assert_eq!(facts.model_hash, dexdo_core::model_hash_for(frame));
            assert_eq!(facts.order_book, ADDR1);
        }
    }

    #[tokio::test]
    async fn enforce_registry_policy_accepts_registered_active_book() {
        let frame = "qwen--qwen3--32b";
        let reader = FakeReader::default().with(
            frame,
            Some(ModelRegistryEntry {
                exists: true,
                model_hash: dexdo_core::model_hash_for(frame),
                order_book: ADDR1.to_string(),
            }),
        );
        let action = enforce_model_registry_policy(
            &reader,
            RegistryRole::Buyer,
            &policy(false),
            frame,
            ADDR1,
            true,
            BuyerMissingBookPolicy::Reject,
        )
        .await
        .unwrap();
        assert_eq!(action, RegistryBookAction::UseActive);
    }

    #[tokio::test]
    async fn seller_registered_missing_book_metadata_deploy_true_may_deploy_canonical_book() {
        let frame = "qwen--qwen3--32b";
        let reader = FakeReader::default().with(frame, Some(registered_entry(frame, "")));
        let action = enforce_model_registry_policy(
            &reader,
            RegistryRole::Seller,
            &policy(true),
            frame,
            ADDR1,
            false,
            BuyerMissingBookPolicy::Reject,
        )
        .await
        .unwrap();
        assert_eq!(action, RegistryBookAction::SellerMayDeployMissing);
    }

    #[tokio::test]
    async fn seller_registered_missing_book_metadata_deploy_false_fails_closed() {
        let frame = "qwen--qwen3--32b";
        let reader = FakeReader::default().with(frame, Some(registered_entry(frame, "")));
        let err = enforce_model_registry_policy(
            &reader,
            RegistryRole::Seller,
            &policy(false),
            frame,
            ADDR1,
            false,
            BuyerMissingBookPolicy::Reject,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("deploy_missing_order_book=false"), "{err}");
    }

    #[tokio::test]
    async fn buyer_registered_missing_book_metadata_hides_and_rejects_before_escrow() {
        let frame = "qwen--qwen3--32b";
        let hidden_reader = FakeReader::default().with(frame, Some(registered_entry(frame, "")));
        let action = enforce_model_registry_policy(
            &hidden_reader,
            RegistryRole::Buyer,
            &policy(false),
            frame,
            ADDR1,
            false,
            BuyerMissingBookPolicy::HideFromAvailableList,
        )
        .await
        .unwrap();
        assert_eq!(action, RegistryBookAction::BuyerHideMissing);

        let rejected_reader =
            FakeReader::default().with(frame, Some(registered_entry(frame, ZERO_ADDR)));
        let err = enforce_model_registry_policy(
            &rejected_reader,
            RegistryRole::Buyer,
            &policy(false),
            frame,
            ADDR1,
            false,
            BuyerMissingBookPolicy::Reject,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("not available to buy now"), "{err}");
    }

    #[tokio::test]
    async fn enforce_registry_policy_rejects_bad_registry_facts_before_money_move() {
        let frame = "qwen--qwen3--32b";
        let unregistered = FakeReader::default();
        let err = enforce_model_registry_policy(
            &unregistered,
            RegistryRole::Seller,
            &policy(true),
            frame,
            ADDR1,
            true,
            BuyerMissingBookPolicy::Reject,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("not registered"), "{err}");

        let bad_hash = FakeReader::default().with(
            frame,
            Some(ModelRegistryEntry {
                exists: true,
                model_hash: dexdo_core::model_hash_for("qwen--wrong--v1"),
                order_book: ADDR1.to_string(),
            }),
        );
        let err = enforce_model_registry_policy(
            &bad_hash,
            RegistryRole::Buyer,
            &policy(false),
            frame,
            ADDR1,
            true,
            BuyerMissingBookPolicy::Reject,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("modelHash"), "{err}");

        let bad_book = FakeReader::default().with(
            frame,
            Some(ModelRegistryEntry {
                exists: true,
                model_hash: dexdo_core::model_hash_for(frame),
                order_book: ADDR2.to_string(),
            }),
        );
        let err = enforce_model_registry_policy(
            &bad_book,
            RegistryRole::Buyer,
            &policy(false),
            frame,
            ADDR1,
            true,
            BuyerMissingBookPolicy::Reject,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("orderBook"), "{err}");
    }

    #[tokio::test]
    async fn validator_rejects_unregistered_before_money_move() {
        let err = validate_registered_model(
            &FakeReader::default(),
            RegistryRole::Seller,
            REG,
            "qwen--typo--v1",
            ADDR1,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("seller model registry check failed"), "{err}");
        assert!(err.contains("not registered"), "{err}");
    }

    #[tokio::test]
    async fn validator_rejects_exists_false_hash_and_book_mismatch() {
        let frame = "qwen--qwen3--32b";
        let exists_false = FakeReader::default().with(
            frame,
            Some(ModelRegistryEntry {
                exists: false,
                model_hash: dexdo_core::model_hash_for(frame),
                order_book: ADDR1.to_string(),
            }),
        );
        assert!(
            validate_registered_model(&exists_false, RegistryRole::Buyer, REG, frame, ADDR1)
                .await
                .unwrap_err()
                .to_string()
                .contains("not registered")
        );

        let bad_hash = FakeReader::default().with(
            frame,
            Some(ModelRegistryEntry {
                exists: true,
                model_hash: dexdo_core::model_hash_for("llama--llama3--8b"),
                order_book: ADDR1.to_string(),
            }),
        );
        assert!(
            validate_registered_model(&bad_hash, RegistryRole::Buyer, REG, frame, ADDR1)
                .await
                .unwrap_err()
                .to_string()
                .contains("modelHash")
        );

        let bad_book = FakeReader::default().with(
            frame,
            Some(ModelRegistryEntry {
                exists: true,
                model_hash: dexdo_core::model_hash_for(frame),
                order_book: ADDR2.to_string(),
            }),
        );
        assert!(
            validate_registered_model(&bad_book, RegistryRole::Buyer, REG, frame, ADDR1)
                .await
                .unwrap_err()
                .to_string()
                .contains("orderBook")
        );
    }

    #[test]
    fn active_canonical_book_is_available_to_seller_and_buyer() {
        assert_eq!(
            validate_order_book_availability(
                RegistryRole::Seller,
                REG,
                "qwen--qwen3--32b",
                ADDR1,
                true,
                false
            )
            .unwrap(),
            RegistryBookAction::UseActive
        );
        assert_eq!(
            validate_order_book_availability(
                RegistryRole::Buyer,
                REG,
                "qwen--qwen3--32b",
                ADDR1,
                true,
                false
            )
            .unwrap(),
            RegistryBookAction::UseActive
        );
    }

    #[test]
    fn seller_missing_book_with_deploy_true_may_deploy_canonical_book() {
        assert_eq!(
            validate_order_book_availability(
                RegistryRole::Seller,
                REG,
                "qwen--qwen3--32b",
                ADDR1,
                false,
                true
            )
            .unwrap(),
            RegistryBookAction::SellerMayDeployMissing
        );
    }

    #[test]
    fn seller_missing_book_with_deploy_false_fails_closed() {
        let err = validate_order_book_availability(
            RegistryRole::Seller,
            REG,
            "qwen--qwen3--32b",
            ADDR1,
            false,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("deploy_missing_order_book=false"), "{err}");
    }

    #[test]
    fn buyer_missing_book_rejects_for_verified_operations() {
        let err = validate_order_book_availability(
            RegistryRole::Buyer,
            REG,
            "qwen--qwen3--32b",
            ADDR1,
            false,
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not available to buy now"), "{err}");
    }

    #[test]
    fn buyer_missing_book_hides_from_available_market_list() {
        assert_eq!(
            order_book_availability(
                RegistryRole::Buyer,
                REG,
                "qwen--qwen3--32b",
                ADDR1,
                false,
                true,
                BuyerMissingBookPolicy::HideFromAvailableList,
            )
            .unwrap(),
            RegistryBookAction::BuyerHideMissing
        );
    }

    #[tokio::test]
    async fn disabled_checks_preserve_old_behavior() {
        let policy = RegistryValidationPolicy::disabled();
        assert!(!policy.check_enabled(RegistryRole::Seller));
        assert!(!policy.check_enabled(RegistryRole::Buyer));
    }

    fn write_contracts(dir: &Path, address: &str) -> PathBuf {
        let path = dir.join("deployed.shellnet.json");
        std::fs::write(
            &path,
            format!(r#"{{"network":"shellnet","model_registry":"{address}"}}"#),
        )
        .unwrap();
        path
    }

    /// the previous `<pid>-<nanos>` directory was never removed -- 3 per workspace run.
    fn temp_dir(name: &str) -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(name)
            .tempdir()
            .expect("registry test directory")
    }

    fn repo_path(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    }
}

#[cfg(test)]
mod issue_1076_tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    struct SuggestionReader {
        fields: Value,
        decode_failure: bool,
        entries: BTreeMap<String, ModelRegistryEntry>,
        model_queries: Mutex<Vec<String>>,
        discovery_queries: AtomicUsize,
    }

    impl SuggestionReader {
        fn new(fields: Value) -> Self {
            Self {
                fields,
                decode_failure: false,
                entries: BTreeMap::new(),
                model_queries: Mutex::new(Vec::new()),
                discovery_queries: AtomicUsize::new(0),
            }
        }

        fn decode_failure() -> Self {
            Self {
                fields: serde_json::json!({"_models": {}}),
                decode_failure: true,
                entries: BTreeMap::new(),
                model_queries: Mutex::new(Vec::new()),
                discovery_queries: AtomicUsize::new(0),
            }
        }

        fn with_entry(mut self, name: &str, model_hash: String) -> Self {
            let order_book = order_book_for_hash(&model_hash);
            self.entries.insert(
                name.to_string(),
                ModelRegistryEntry {
                    exists: true,
                    model_hash,
                    order_book,
                },
            );
            self
        }

        fn model_queries(&self) -> Vec<String> {
            self.model_queries.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ModelRegistryReader for SuggestionReader {
        async fn model(&self, frame_model: &str) -> Result<Option<ModelRegistryEntry>> {
            self.model_queries
                .lock()
                .unwrap()
                .push(frame_model.to_string());
            Ok(self.entries.get(frame_model).cloned())
        }

        async fn registered_model_names(&self) -> Result<Vec<String>> {
            self.discovery_queries.fetch_add(1, Ordering::SeqCst);
            if self.decode_failure {
                bail!("fixture ModelRegistry storage decode failed");
            }
            model_registry_names_from_storage_fields(&self.fields)
        }
    }

    fn valid_hash(name: &str) -> String {
        dexdo_core::model_hash_for(name)
    }

    fn registry_address() -> &'static str {
        "0:9999999999999999999999999999999999999999999999999999999999999999"
    }

    #[cfg(feature = "shellnet")]
    fn order_book_for_hash(model_hash: &str) -> String {
        dexdo_core::RealChainBackend::canonical_inference_orderbook_address(model_hash)
            .unwrap()
            .with_workchain()
    }

    #[cfg(not(feature = "shellnet"))]
    fn order_book_for_hash(_model_hash: &str) -> String {
        "0:1111111111111111111111111111111111111111111111111111111111111111".to_string()
    }

    fn suggestions_from_error(error: &str) -> Vec<String> {
        let (_, suggestions) = error
            .split_once("; registered canonical suggestions: ")
            .unwrap_or_else(|| panic!("suggestion suffix is absent: {error}"));
        serde_json::from_str(suggestions).expect("suggestions use a JSON-compatible string list")
    }

    #[tokio::test]
    async fn issue_1076_decoded_map_suggestions_are_deterministic_truncated_and_revalidated() {
        let fields = serde_json::json!({
            "_models": {
                "0x07": "unrelated-model",
                "0x06": "alpha-model-0005",
                "0x05": "alpha-model-0004",
                "0x04": "alpha-model-0003",
                "0x03": "alpha-model-0002",
                "0x02": "alpha-model-0001",
                "0x01": "alpha-model-0000"
            }
        });
        let reader = SuggestionReader::new(fields)
            .with_entry("alpha-model-0000", valid_hash("alpha-model-0000"))
            .with_entry("alpha-model-0001", valid_hash("alpha-model-0001"))
            .with_entry("alpha-model-0002", valid_hash("different-model"))
            .with_entry("alpha-model-0003", valid_hash("alpha-model-0003"))
            .with_entry("alpha-model-0004", valid_hash("alpha-model-0004"))
            .with_entry("alpha-model-0005", valid_hash("alpha-model-0005"));

        let error = resolve_registered_model_identity(
            &reader,
            RegistryRole::Seller,
            registry_address(),
            "alpha-model-000x",
        )
        .await
        .unwrap_err()
        .to_string();

        assert_eq!(
            suggestions_from_error(&error),
            [
                "alpha-model-0000",
                "alpha-model-0001",
                "alpha-model-0003",
                "alpha-model-0004"
            ]
        );
        assert!(error.contains("tried [\"alpha-model-000x\"]"), "{error}");
        assert_eq!(reader.discovery_queries.load(Ordering::SeqCst), 1);
        assert_eq!(
            &reader.model_queries()[1..],
            &[
                "alpha-model-0000",
                "alpha-model-0001",
                "alpha-model-0002",
                "alpha-model-0003",
                "alpha-model-0004"
            ],
            "only the deterministic top {REGISTERED_MODEL_SUGGESTION_LIMIT} finalists are revalidated"
        );
    }

    #[tokio::test]
    async fn issue_1076_served_model_aliases_are_never_suggested() {
        let fields = serde_json::json!({
            "_models": {
                "0x01": "openai/gpt-4o-mini",
                "0x02": "Openai/Gpt-4O-Mini",
                "0x03": "gpt-4o-mini"
            }
        });
        let reader = SuggestionReader::new(fields)
            .with_entry("openai/gpt-4o-mini", valid_hash("openai/gpt-4o-mini"))
            .with_entry("Openai/Gpt-4O-Mini", valid_hash("Openai/Gpt-4O-Mini"))
            .with_entry("gpt-4o-mini", valid_hash("gpt-4o-mini"));

        let suggestions = registered_model_suggestions(&reader, "openai--gpt-4o-mini")
            .await
            .unwrap();

        assert_eq!(suggestions, ["gpt-4o-mini"]);
        assert_eq!(reader.model_queries(), ["gpt-4o-mini"]);
    }

    #[tokio::test]
    async fn issue_1076_decode_failure_preserves_existing_error() {
        let requested = "missing-model";
        let baseline_reader = SuggestionReader::new(serde_json::json!({"_models": {}}));
        let baseline = resolve_registered_model_identity(
            &baseline_reader,
            RegistryRole::Buyer,
            registry_address(),
            requested,
        )
        .await
        .unwrap_err()
        .to_string();

        let reader = SuggestionReader::decode_failure();
        let error = resolve_registered_model_identity(
            &reader,
            RegistryRole::Buyer,
            registry_address(),
            requested,
        )
        .await
        .unwrap_err()
        .to_string();

        assert_eq!(error, baseline);
        assert!(
            !error.contains("registered canonical suggestions"),
            "{error}"
        );
        assert_eq!(reader.discovery_queries.load(Ordering::SeqCst), 1);
    }
}
