//! Files and directories only their owner can open.
//!
//! On Unix that is mode 0600 for files and 0700 for directories. On Windows it
//! is a protected DACL (no inherited entries) granting full access to the
//! current user's SID and no one else. Either way the permissions are set as
//! the entry is created, so there is no moment where it exists with looser
//! ones. An existing entry keeps the permissions it has.

use std::fs::File;
use std::io;
use std::path::Path;

/// Create `path` owner-only, refusing any existing entry (`O_EXCL` /
/// `CREATE_NEW`), a symlink included, so nothing planted there is followed.
pub(crate) fn create_new(path: &Path) -> io::Result<File> {
    imp::create_new(path)
}

/// Open `path` read-write, creating it owner-only if it is missing.
pub(crate) fn open_or_create(path: &Path) -> io::Result<File> {
    imp::open_or_create(path)
}

/// Create `dir` and any missing parents. A directory this creates is
/// owner-only; one that already exists is left as it is.
pub(crate) fn create_dir_all(dir: &Path) -> io::Result<()> {
    imp::create_dir_all(dir)
}

#[cfg(unix)]
mod imp {
    use std::fs::{DirBuilder, File, OpenOptions};
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    use std::path::Path;

    pub(super) fn create_new(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }

    pub(super) fn open_or_create(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
    }

    pub(super) fn create_dir_all(dir: &Path) -> io::Result<()> {
        DirBuilder::new().recursive(true).mode(0o700).create(dir)
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use std::path::Path;

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, LocalFree, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL,
    };
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
        FILE_CREATION_DISPOSITION, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_ALWAYS,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub(super) fn create_new(path: &Path) -> io::Result<File> {
        create_file(path, GENERIC_WRITE.0, CREATE_NEW)
    }

    pub(super) fn open_or_create(path: &Path) -> io::Result<File> {
        create_file(path, GENERIC_READ.0 | GENERIC_WRITE.0, OPEN_ALWAYS)
    }

    pub(super) fn create_dir_all(dir: &Path) -> io::Result<()> {
        if dir.is_dir() {
            return Ok(());
        }
        if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        // Inheritable (OICI), so what is created inside starts owner-only too.
        let sd = OwnerOnly::new("OICI")?;
        let wide = wide(dir);
        match unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&sd.attributes())) } {
            Ok(()) => Ok(()),
            Err(e) => {
                let e = to_io(e);
                if e.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    fn create_file(
        path: &Path,
        access: u32,
        disposition: FILE_CREATION_DISPOSITION,
    ) -> io::Result<File> {
        let sd = OwnerOnly::new("")?;
        let wide = wide(path);
        // The security descriptor applies only when the file is created.
        // Sharing matches std's default, so the store can still be read, and
        // a file renamed over, while another process holds it open.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                Some(&sd.attributes()),
                disposition,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .map_err(to_io)?;
        // SAFETY: a valid handle that nothing else owns.
        Ok(unsafe { File::from_raw_handle(handle.0 as RawHandle) })
    }

    /// A self-relative security descriptor granting the current user full
    /// access and nothing to anyone else, freed on drop.
    struct OwnerOnly(PSECURITY_DESCRIPTOR);

    impl OwnerOnly {
        fn new(inherit: &str) -> io::Result<Self> {
            let sddl = format!("D:P(A;{inherit};FA;;;{})", current_user_sid()?);
            let sddl: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
            let mut sd = PSECURITY_DESCRIPTOR::default();
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(sddl.as_ptr()),
                    SDDL_REVISION_1,
                    &mut sd,
                    None,
                )
            }
            .map_err(to_io)?;
            Ok(OwnerOnly(sd))
        }

        fn attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.0 .0,
                bInheritHandle: false.into(),
            }
        }
    }

    impl Drop for OwnerOnly {
        fn drop(&mut self) {
            unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
        }
    }

    /// The SID of the user this process runs as, e.g. `S-1-5-21-…-1001`.
    pub(super) fn current_user_sid() -> io::Result<String> {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(to_io)?;
        let result = (|| {
            let mut len = 0u32;
            // The first call only reports the size it needs.
            let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut len) };
            // u64s, so the buffer is aligned for the pointer TOKEN_USER holds.
            let mut buf = vec![0u64; (len as usize).div_ceil(8)];
            unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    Some(buf.as_mut_ptr().cast::<c_void>()),
                    len,
                    &mut len,
                )
            }
            .map_err(to_io)?;
            // SAFETY: GetTokenInformation(TokenUser) filled `buf` with a
            // TOKEN_USER, and `buf` outlives this borrow.
            let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
            let mut s = PWSTR::null();
            unsafe { ConvertSidToStringSidW(user.User.Sid, &mut s) }.map_err(to_io)?;
            let sid = unsafe { s.to_string() };
            unsafe { LocalFree(Some(HLOCAL(s.0.cast()))) };
            sid.map_err(|_| io::Error::other("the user's SID is not valid UTF-16"))
        })();
        let _ = unsafe { CloseHandle(token) };
        result
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain([0]).collect()
    }

    /// A Win32 error as an `io::Error` whose `kind()` is right, so
    /// `ERROR_FILE_EXISTS` reads as `AlreadyExists`. (`windows`' own `From`
    /// keeps the HRESULT, which std does not decode.)
    pub(super) fn to_io(e: windows::core::Error) -> io::Error {
        let code = e.code().0 as u32;
        if code & 0xFFFF_0000 == 0x8007_0000 {
            io::Error::from_raw_os_error((code & 0xFFFF) as i32)
        } else {
            io::Error::other(e)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
            SE_FILE_OBJECT,
        };
        use windows::Win32::Security::DACL_SECURITY_INFORMATION;

        /// The DACL of `path`, as SDDL.
        fn dacl(path: &Path) -> String {
            let wide = wide(path);
            let mut sd = PSECURITY_DESCRIPTOR::default();
            let err = unsafe {
                GetNamedSecurityInfoW(
                    PCWSTR(wide.as_ptr()),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    None,
                    None,
                    &mut sd,
                )
            };
            assert!(err.is_ok(), "{err:?}");
            let out = dacl_sddl(sd);
            unsafe { LocalFree(Some(HLOCAL(sd.0))) };
            out
        }

        /// `sddl` as Windows itself writes it. It prints some well-known SIDs
        /// as aliases, e.g. the built-in Administrator (RID 500, which CI
        /// runners use) as `LA`, so compare after the same round trip.
        fn canonical(sddl: &str) -> String {
            let wide: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
            let mut sd = PSECURITY_DESCRIPTOR::default();
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(wide.as_ptr()),
                    SDDL_REVISION_1,
                    &mut sd,
                    None,
                )
            }
            .unwrap();
            let out = dacl_sddl(sd);
            unsafe { LocalFree(Some(HLOCAL(sd.0))) };
            out
        }

        fn dacl_sddl(sd: PSECURITY_DESCRIPTOR) -> String {
            let mut s = PWSTR::null();
            unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    sd,
                    SDDL_REVISION_1,
                    DACL_SECURITY_INFORMATION,
                    &mut s,
                    None,
                )
            }
            .unwrap();
            let out = unsafe { s.to_string() }.unwrap();
            unsafe { LocalFree(Some(HLOCAL(s.0.cast()))) };
            out
        }

        #[test]
        fn files_and_directories_grant_only_the_current_user() {
            let sid = current_user_sid().unwrap();
            let root = tempfile::tempdir().unwrap();
            let dir = root.path().join("a").join("cfg");
            super::super::create_dir_all(&dir).unwrap();
            assert_eq!(dacl(&dir), canonical(&format!("D:P(A;OICI;FA;;;{sid})")));

            let file = dir.join("secret");
            drop(super::super::create_new(&file).unwrap());
            assert_eq!(dacl(&file), canonical(&format!("D:P(A;;FA;;;{sid})")));

            let lock = dir.join("lock");
            drop(super::super::open_or_create(&lock).unwrap());
            assert_eq!(dacl(&lock), canonical(&format!("D:P(A;;FA;;;{sid})")));
        }

        #[test]
        fn an_existing_entry_is_refused_or_kept() {
            let root = tempfile::tempdir().unwrap();
            let file = root.path().join("f");
            std::fs::write(&file, "precious").unwrap();
            let before = dacl(&file);
            let err = super::super::create_new(&file).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
            drop(super::super::open_or_create(&file).unwrap());
            assert_eq!(std::fs::read_to_string(&file).unwrap(), "precious");
            assert_eq!(dacl(&file), before);

            super::super::create_dir_all(root.path()).unwrap();
        }
    }
}
