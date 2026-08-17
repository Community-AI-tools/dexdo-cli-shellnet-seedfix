use anyhow::{anyhow, Result};
use std::fs::File;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;

#[cfg(test)]
std::thread_local! {
    static INJECT_ACL_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(crate) fn protect_owner_only(file: &File, path: &Path) -> Result<()> {
    #[cfg(test)]
    if INJECT_ACL_FAILURE.with(|inject| inject.replace(false)) {
        let len = file
            .metadata()
            .map_err(|error| {
                anyhow!(
                    "inspect empty temp before protected owner-only DACL on {}: {error}",
                    path.display()
                )
            })?
            .len();
        return Err(anyhow!(
            "install protected owner-only DACL on {}: injected test failure; empty_temp_len={len}",
            path.display()
        ));
    }

    install_owner_only_dacl(file).map_err(|error| {
        anyhow!(
            "install protected owner-only DACL on {}: {error}",
            path.display()
        )
    })
}

#[cfg(test)]
pub(crate) fn inject_acl_failure_once() {
    INJECT_ACL_FAILURE.with(|inject| {
        assert!(!inject.replace(true), "ACL failure already injected");
    });
}

fn install_owner_only_dacl(file: &File) -> std::io::Result<()> {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        AddAccessAllowedAceEx, GetLengthSid, InitializeAcl, ACCESS_ALLOWED_ACE, ACL, ACL_REVISION,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    let mut owner = null_mut();
    let mut security_descriptor = null_mut();
    let get_result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut security_descriptor,
        )
    };
    if get_result != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(get_result as i32));
    }

    let result = (|| {
        if owner.is_null() {
            return Err(std::io::Error::other(
                "Windows returned no owner SID for the new secret temp file",
            ));
        }
        let owner_len = unsafe { GetLengthSid(owner) };
        if owner_len == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let acl_len = size_of::<ACL>()
            .checked_add(size_of::<ACCESS_ALLOWED_ACE>())
            .and_then(|len| len.checked_sub(size_of::<u32>()))
            .and_then(|len| len.checked_add(owner_len as usize))
            .ok_or_else(|| std::io::Error::other("owner-only ACL size overflow"))?;
        let acl_len = u32::try_from(acl_len)
            .map_err(|_| std::io::Error::other("owner-only ACL is too large"))?;
        let mut acl_storage = vec![0usize; (acl_len as usize).div_ceil(size_of::<usize>())];
        let acl = acl_storage.as_mut_ptr().cast::<ACL>();

        if unsafe { InitializeAcl(acl, acl_len, ACL_REVISION) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, 0, FILE_ALL_ACCESS, owner) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let set_result = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl,
                null(),
            )
        };
        if set_result != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(set_result as i32));
        }
        Ok(())
    })();

    unsafe {
        LocalFree(security_descriptor.cast::<c_void>());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{deals, note};
    use std::ffi::c_void;
    use std::io::Read as _;
    use std::mem::size_of;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::ptr::{addr_of, null, null_mut};
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Security::Authorization::{
        GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        AclSizeInformation, AddAccessAllowedAceEx, CreateWellKnownSid, EqualSid, GetAce,
        GetAclInformation, GetLengthSid, GetSecurityDescriptorControl, InitializeAcl, WinWorldSid,
        ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE,
        DACL_SECURITY_INFORMATION, INHERITED_ACE, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_MAX_SID_SIZE, SE_DACL_PROTECTED,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ALL_ACCESS, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ, FILE_SHARE_DELETE,
        READ_CONTROL, WRITE_DAC,
    };
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

    #[derive(Debug)]
    struct DaclSummary {
        protected: bool,
        ace_count: u32,
        inherited_ace_count: u32,
        owner_allow_ace_count: u32,
        owner_full_control_ace_count: u32,
        non_owner_allow_ace_count: u32,
        non_allow_ace_count: u32,
        allow_masks: Vec<u32>,
    }

    fn inspect_file_dacl(path: &Path) -> Result<DaclSummary> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| anyhow!("open ACL test file: {error}"))?;
        inspect_handle_dacl(&file)
    }

    fn inspect_handle_dacl(file: &File) -> Result<DaclSummary> {
        let mut owner: PSID = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut security_descriptor = null_mut();
        let get_result = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut security_descriptor,
            )
        };
        if get_result != ERROR_SUCCESS {
            return Err(anyhow!(
                "read file owner/DACL: {}",
                std::io::Error::from_raw_os_error(get_result as i32)
            ));
        }

        let result = (|| {
            if owner.is_null() || dacl.is_null() {
                return Err(anyhow!("Windows returned a null owner SID or DACL"));
            }
            let mut control = 0u16;
            let mut revision = 0u32;
            if unsafe {
                GetSecurityDescriptorControl(security_descriptor, &mut control, &mut revision)
            } == 0
            {
                return Err(anyhow!(
                    "read security descriptor control: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut acl_info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
            if unsafe {
                GetAclInformation(
                    dacl,
                    (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            } == 0
            {
                return Err(anyhow!(
                    "read DACL size information: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let mut inherited_ace_count = 0;
            let mut owner_allow_ace_count = 0;
            let mut owner_full_control_ace_count = 0;
            let mut non_owner_allow_ace_count = 0;
            let mut non_allow_ace_count = 0;
            let mut allow_masks = Vec::new();
            for index in 0..acl_info.AceCount {
                let mut ace = null_mut();
                if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
                    return Err(anyhow!(
                        "read DACL ACE {index}: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                let header = unsafe { &*ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
                if u32::from(header.AceFlags) & INHERITED_ACE != 0 {
                    inherited_ace_count += 1;
                }
                if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
                    non_allow_ace_count += 1;
                    continue;
                }
                let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                let sid = addr_of!(allowed.SidStart).cast_mut().cast::<c_void>();
                allow_masks.push(allowed.Mask);
                if unsafe { EqualSid(sid, owner) } != 0 {
                    owner_allow_ace_count += 1;
                    if allowed.Mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS {
                        owner_full_control_ace_count += 1;
                    }
                } else {
                    non_owner_allow_ace_count += 1;
                }
            }

            Ok(DaclSummary {
                protected: control & SE_DACL_PROTECTED != 0,
                ace_count: acl_info.AceCount,
                inherited_ace_count,
                owner_allow_ace_count,
                owner_full_control_ace_count,
                non_owner_allow_ace_count,
                non_allow_ace_count,
                allow_masks,
            })
        })();

        unsafe {
            LocalFree(security_descriptor);
        }
        result
    }

    fn print_acl_evidence(label: &str, summary: &DaclSummary) {
        let masks = summary
            .allow_masks
            .iter()
            .map(|mask| format!("0x{mask:08x}"))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "ACL_EVIDENCE label={label} protected={} ace_count={} inherited_aces={} \
             owner_allow_aces={} owner_full_control_aces={} non_owner_allow_aces={} \
             non_allow_aces={} allow_masks=[{masks}]",
            summary.protected,
            summary.ace_count,
            summary.inherited_ace_count,
            summary.owner_allow_ace_count,
            summary.owner_full_control_ace_count,
            summary.non_owner_allow_ace_count,
            summary.non_allow_ace_count,
        );
    }

    fn assert_owner_only(label: &str, summary: DaclSummary) {
        print_acl_evidence(label, &summary);
        assert!(summary.protected, "{label}: DACL must be protected");
        assert_eq!(summary.ace_count, 1, "{label}: exactly one ACE expected");
        assert_eq!(
            summary.inherited_ace_count, 0,
            "{label}: inherited ACEs are forbidden"
        );
        assert_eq!(
            summary.owner_allow_ace_count, 1,
            "{label}: owner allow ACE missing"
        );
        assert_eq!(
            summary.owner_full_control_ace_count, 1,
            "{label}: owner full-control ACE missing"
        );
        assert_eq!(
            summary.non_owner_allow_ace_count, 0,
            "{label}: non-owner allow ACE is forbidden"
        );
        assert_eq!(
            summary.non_allow_ace_count, 0,
            "{label}: unexpected non-allow ACE"
        );
    }

    fn open_empty_protected_temp(path: &Path) -> Result<File> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        options.access_mode(GENERIC_WRITE | READ_CONTROL | WRITE_DAC);
        options.share_mode(FILE_SHARE_DELETE);
        let file = options
            .open(path)
            .map_err(|error| anyhow!("create ACL test temp: {error}"))?;
        protect_owner_only(&file, path)?;
        Ok(file)
    }

    fn acl_storage_len(sid_lengths: &[u32]) -> Result<u32> {
        let mut len = size_of::<ACL>();
        for sid_len in sid_lengths {
            len = len
                .checked_add(size_of::<ACCESS_ALLOWED_ACE>())
                .and_then(|len| len.checked_sub(size_of::<u32>()))
                .and_then(|len| len.checked_add(*sid_len as usize))
                .ok_or_else(|| anyhow!("test ACL size overflow"))?;
        }
        u32::try_from(len).map_err(|_| anyhow!("test ACL is too large"))
    }

    fn install_broad_inheritable_read_acl(path: &Path) -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        options.access_mode(GENERIC_READ | READ_CONTROL | WRITE_DAC);
        options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
        let directory = options
            .open(path)
            .map_err(|error| anyhow!("open ACL test directory: {error}"))?;

        let mut owner: PSID = null_mut();
        let mut security_descriptor = null_mut();
        let get_result = unsafe {
            GetSecurityInfo(
                directory.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut security_descriptor,
            )
        };
        if get_result != ERROR_SUCCESS {
            return Err(anyhow!(
                "read ACL test directory owner: {}",
                std::io::Error::from_raw_os_error(get_result as i32)
            ));
        }

        let result = (|| {
            if owner.is_null() {
                return Err(anyhow!("Windows returned no ACL test directory owner"));
            }
            let owner_len = unsafe { GetLengthSid(owner) };
            if owner_len == 0 {
                return Err(anyhow!(
                    "read ACL test directory owner SID length: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut world_storage =
                vec![0usize; (SECURITY_MAX_SID_SIZE as usize).div_ceil(size_of::<usize>())];
            let world_sid = world_storage.as_mut_ptr().cast::<c_void>();
            let mut world_len = SECURITY_MAX_SID_SIZE;
            if unsafe { CreateWellKnownSid(WinWorldSid, null_mut(), world_sid, &mut world_len) }
                == 0
            {
                return Err(anyhow!(
                    "create Everyone SID for ACL test: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let acl_len = acl_storage_len(&[owner_len, world_len])?;
            let mut acl_storage = vec![0usize; (acl_len as usize).div_ceil(size_of::<usize>())];
            let acl = acl_storage.as_mut_ptr().cast::<ACL>();
            if unsafe { InitializeAcl(acl, acl_len, ACL_REVISION) } == 0 {
                return Err(anyhow!(
                    "initialize broad ACL test DACL: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let inherit_flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
            if unsafe {
                AddAccessAllowedAceEx(acl, ACL_REVISION, inherit_flags, FILE_ALL_ACCESS, owner)
            } == 0
            {
                return Err(anyhow!(
                    "add owner ACE to broad ACL test DACL: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if unsafe {
                AddAccessAllowedAceEx(
                    acl,
                    ACL_REVISION,
                    inherit_flags,
                    FILE_GENERIC_READ,
                    world_sid,
                )
            } == 0
            {
                return Err(anyhow!(
                    "add Everyone read ACE to broad ACL test DACL: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let set_result = unsafe {
                SetSecurityInfo(
                    directory.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    acl,
                    null(),
                )
            };
            if set_result != ERROR_SUCCESS {
                return Err(anyhow!(
                    "install broad ACL test DACL: {}",
                    std::io::Error::from_raw_os_error(set_result as i32)
                ));
            }
            Ok(())
        })();

        unsafe {
            LocalFree(security_descriptor);
        }
        result
    }

    fn sample_deal_handle() -> deals::DealHandle {
        let token_contract = format!("0:{}", "3".repeat(64));
        deals::DealHandle {
            version: deals::DEAL_HANDLE_VERSION,
            handle: deals::make_handle_id(&token_contract, deals::DealHandleRole::Buyer),
            role: deals::DealHandleRole::Buyer,
            network: "shellnet".into(),
            token_contract,
            note_addr: format!("0:{}", "4".repeat(64)),
            frame_model: "qwen/qwen3-32b".into(),
            model_hash: None,
            order_book: None,
            root_model: None,
            market: None,
            contracts: "contracts/deployed.shellnet.json".into(),
            endpoint: None,
            created_order_ids: vec![],
            created_at_unix: 1,
        }
    }

    #[cfg(feature = "shellnet")]
    #[test]
    fn windows_pool_temp_and_final_dacl_is_protected_owner_only() {
        let directory = tempfile::tempdir().expect("temp directory");
        let temp = directory.path().join(".pn_pool.json.tmp.acl-inspection");
        let file = open_empty_protected_temp(&temp).expect("protect empty pool temp");
        assert_eq!(file.metadata().expect("temp metadata").len(), 0);
        assert_owner_only(
            "pool-temp",
            inspect_handle_dacl(&file).expect("inspect pool temp DACL"),
        );
        drop(file);
        std::fs::remove_file(&temp).expect("remove inspected empty temp");

        let pool = directory.path().join("pn_pool.json");
        crate::cli::commands::write_pool_private(&pool, br#"{"notes":[]}"#).expect("write pool");
        assert_owner_only(
            "pool-final",
            inspect_file_dacl(&pool).expect("inspect pool final DACL"),
        );
        assert_eq!(
            std::fs::read(&pool).expect("current user reads pool"),
            br#"{"notes":[]}"#
        );
        let mut current_user = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pool)
            .expect("current user opens pool read/write");
        let mut bytes = Vec::new();
        current_user
            .read_to_end(&mut bytes)
            .expect("current user reads through open handle");
        assert_eq!(bytes, br#"{"notes":[]}"#);
        drop(current_user);
        std::fs::write(&pool, br#"{"notes":["overwritten"]}"#)
            .expect("current user overwrites pool");
        assert_eq!(
            std::fs::read(&pool).expect("read overwritten pool"),
            br#"{"notes":["overwritten"]}"#
        );
        assert_owner_only(
            "pool-current-user-overwrite",
            inspect_file_dacl(&pool).expect("inspect overwritten pool DACL"),
        );
    }

    #[test]
    fn windows_recovery_file_dacl_is_protected_owner_only() {
        let directory = tempfile::tempdir().expect("temp directory");
        let recovery = directory.path().join("pn_pool.json.recovery.json");
        let secret = "11".repeat(32);
        let public =
            note::derive_owner_pubkey_from_secret_hex(&secret).expect("derive recovery owner");
        let wallet = format!("0:{}", "a".repeat(64));
        let state = note::NoteDeployRecoveryState::new(
            note::NoteDeployRecoveryRequest {
                endpoint: "https://dd-shellnet.ackinacki.org",
                nominal: "N100",
                token_type: dexdo_core::params::SHELL_CURRENCY_ID,
                raw_value: 100_000_000_000,
                ecc_shell_deposit: 100_000_000_000,
                funding_multisig_address: &wallet,
            },
            &public,
            &secret,
        )
        .expect("build recovery state");

        note::write_note_deploy_recovery(&recovery, &state).expect("write recovery");
        assert_owner_only(
            "recovery-final",
            inspect_file_dacl(&recovery).expect("inspect recovery DACL"),
        );
    }

    #[test]
    fn windows_deal_handle_dacl_is_protected_owner_only() {
        let directory = tempfile::tempdir().expect("temp directory");
        let handle = sample_deal_handle();
        deals::validate_deal_handle(&handle).expect("valid deal handle");
        let path = deals::save_deal_handle(directory.path(), &handle).expect("write deal handle");

        assert_owner_only(
            "deal-final",
            inspect_file_dacl(&path).expect("inspect deal DACL"),
        );
    }

    #[test]
    fn windows_broad_parent_acl_is_not_inherited_by_secret_file() {
        let directory = tempfile::tempdir().expect("temp directory");
        install_broad_inheritable_read_acl(directory.path()).expect("install broad parent ACL");

        let control = directory.path().join("ordinary-control.txt");
        std::fs::write(&control, b"control").expect("write ordinary inherited-ACL control");
        let broad = inspect_file_dacl(&control).expect("inspect inherited-ACL control");
        print_acl_evidence("broad-parent-control", &broad);
        assert!(
            broad.inherited_ace_count >= 1 && broad.non_owner_allow_ace_count >= 1,
            "control file must prove broad inheritance was active: {broad:?}"
        );

        let secret = directory.path().join("pn_pool.json");
        note::write_private_atomic(&secret, b"complete-secret-content")
            .expect("write protected secret under broad parent");
        assert_eq!(
            std::fs::read(&secret).expect("read protected secret"),
            b"complete-secret-content"
        );
        assert_owner_only(
            "broad-parent-secret-final",
            inspect_file_dacl(&secret).expect("inspect protected secret DACL"),
        );
    }

    #[test]
    fn windows_acl_failure_removes_empty_temp_and_preserves_destination() {
        let directory = tempfile::tempdir().expect("temp directory");
        let destination = directory.path().join("pn_pool.json");
        let temp = directory
            .path()
            .join(".pn_pool.json.tmp.injected-acl-failure");
        note::write_private_atomic(&destination, b"previous-destination")
            .expect("write previous destination");

        inject_acl_failure_once();
        let error = note::write_private_atomic_via_temp(
            &destination,
            &temp,
            b"secret-must-never-be-written",
        )
        .expect_err("injected ACL failure must fail closed")
        .to_string();

        assert!(
            error.contains("install protected owner-only DACL"),
            "unexpected ACL error: {error}"
        );
        assert!(
            error.contains(&temp.display().to_string()),
            "ACL error must name the temp path: {error}"
        );
        assert!(
            error.contains("empty_temp_len=0"),
            "ACL failure was not observed on an empty temp: {error}"
        );
        assert!(
            !error.contains("secret-must-never-be-written"),
            "secret bytes leaked into ACL error: {error}"
        );
        assert!(
            !temp.exists(),
            "empty temp must be removed after ACL failure"
        );
        assert_eq!(
            std::fs::read(&destination).expect("read preserved destination"),
            b"previous-destination"
        );
    }

    #[test]
    fn windows_atomic_replacement_preserves_owner_only_dacl_and_full_content() {
        let directory = tempfile::tempdir().expect("temp directory");
        let destination = directory.path().join("pn_pool.json");
        note::write_private_atomic(&destination, b"first").expect("write initial secret");
        note::write_private_atomic(&destination, b"replacement-content-with-complete-tail")
            .expect("atomically replace secret");

        assert_eq!(
            std::fs::read(&destination).expect("read replaced secret"),
            b"replacement-content-with-complete-tail"
        );
        assert_owner_only(
            "atomic-replacement-final",
            inspect_file_dacl(&destination).expect("inspect replacement DACL"),
        );
    }
}
