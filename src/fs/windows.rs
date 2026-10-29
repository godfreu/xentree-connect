use std::{
    ffi::{c_void, OsStr},
    fs::File,
    io,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr,
};

use windows_sys::Win32::{
    Foundation::{LocalFree, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE},
    Security::{
        AclSizeInformation,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
        },
        EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl, GetTokenInformation,
        TokenUser, ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

use super::FsError;

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Windows has no mode bits; new directories inherit their parent's ACL.
/// Only the key *file* gets an explicit protected DACL.
pub fn create_private_dir_all(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)
}

/// Current user's SID, kept alive alongside the buffer that backs it.
struct UserSid {
    buf: Vec<u8>,
}

impl UserSid {
    fn current() -> io::Result<Self> {
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: valid out-pointer; pseudo-handle from GetCurrentProcess needs no close.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: token was just returned by OpenProcessToken and is owned here.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let raw = token.as_raw_handle() as HANDLE;

        let mut needed = 0u32;
        // SAFETY: size query with a null buffer is the documented usage.
        unsafe { GetTokenInformation(raw, TokenUser, ptr::null_mut(), 0, &mut needed) };
        let mut buf = vec![0u8; needed as usize];
        // SAFETY: buf is `needed` bytes.
        if unsafe {
            GetTokenInformation(raw, TokenUser, buf.as_mut_ptr().cast(), needed, &mut needed)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { buf })
    }

    fn psid(&self) -> *mut c_void {
        // SAFETY: buf holds a TOKEN_USER written by GetTokenInformation (pointer may be unaligned-safe via read_unaligned).
        let tu = unsafe { ptr::read_unaligned(self.buf.as_ptr().cast::<TOKEN_USER>()) };
        tu.User.Sid
    }

    fn to_string(&self) -> io::Result<String> {
        let mut p: *mut u16 = ptr::null_mut();
        // SAFETY: psid is valid for the life of self; p receives a LocalAlloc'd string.
        if unsafe { ConvertSidToStringSidW(self.psid(), &mut p) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0;
        // SAFETY: p is a NUL-terminated wide string.
        while unsafe { *p.add(len) } != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) });
        unsafe { LocalFree(p.cast()) };
        Ok(s)
    }
}

/// Creates the file with a protected DACL granting FILE_ALL_ACCESS to the
/// current user only, set atomically at creation (no inherited ACEs).
pub fn create_private_new(path: &Path) -> io::Result<File> {
    let sid = UserSid::current()?.to_string()?;
    let sddl = wide(OsStr::new(&format!("D:P(A;;FA;;;{sid})")));

    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: sddl is NUL-terminated; sd receives a LocalAlloc'd descriptor.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let name = wide(path.as_os_str());
    // Share mode 0: exclusive while we write. CREATE_NEW fails if the path exists.
    // SAFETY: name is NUL-terminated; sa outlives the call.
    let h = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_GENERIC_WRITE,
            0,
            &sa,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    let err = io::Error::last_os_error();
    unsafe { LocalFree(sd.cast()) };
    if h == INVALID_HANDLE_VALUE {
        return Err(err);
    }
    // SAFETY: h is a fresh, valid file handle; File takes ownership.
    Ok(unsafe { File::from_raw_handle(h) })
}

/// The DACL must be protected (no inheritance) and contain exactly one
/// allow-ACE for the current user.
pub fn verify_private(file: &File, path: &Path) -> Result<(), FsError> {
    let bad = |reason: &str| FsError::InsecurePermissions {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    };
    let user = UserSid::current().map_err(|e| FsError::io(path, e))?;

    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: valid handle and out-pointers; sd is LocalAlloc'd and freed below.
    let rc = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(FsError::io(path, io::Error::from_raw_os_error(rc as i32)));
    }

    let result = (|| {
        let mut control = 0u16;
        let mut rev = 0u32;
        // SAFETY: sd was returned by GetSecurityInfo.
        if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut rev) } == 0 {
            return Err(FsError::io(path, io::Error::last_os_error()));
        }
        if control & SE_DACL_PROTECTED == 0 {
            return Err(bad("DACL inherits permissions from the parent directory"));
        }
        if dacl.is_null() {
            return Err(bad("null DACL grants everyone access"));
        }
        let mut info = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        // SAFETY: info is the size the class expects.
        if unsafe {
            GetAclInformation(
                dacl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(FsError::io(path, io::Error::last_os_error()));
        }
        if info.AceCount != 1 {
            return Err(bad(
                "DACL must contain exactly one entry (the current user)",
            ));
        }
        let mut ace: *mut c_void = ptr::null_mut();
        // SAFETY: index 0 exists (AceCount == 1).
        if unsafe { GetAce(dacl, 0, &mut ace) } == 0 {
            return Err(FsError::io(path, io::Error::last_os_error()));
        }
        let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
        // SAFETY: ace points inside the ACL; SidStart is the first DWORD of the trailing SID.
        let (ty, ace_sid) = unsafe {
            (
                (*ace).Header.AceType,
                ptr::addr_of_mut!((*ace).SidStart).cast::<c_void>(),
            )
        };
        if ty != ACCESS_ALLOWED_ACE_TYPE {
            return Err(bad("DACL entry is not an allow entry"));
        }
        // SAFETY: both pointers are valid SIDs.
        if unsafe { EqualSid(ace_sid, user.psid()) } == 0 {
            return Err(bad("DACL entry belongs to a different principal"));
        }
        Ok(())
    })();

    unsafe { LocalFree(sd.cast()) };
    result
}

pub fn sync_dir(_dir: &Path) {}
