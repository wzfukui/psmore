use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

fn temporary_path(parent: &Path, filename: &OsStr, attempt: u32) -> PathBuf {
    let filename = filename.to_string_lossy();
    parent.join(format!(
        ".{filename}.psmore-{}-{attempt}.tmp",
        std::process::id()
    ))
}

fn sync_directory(directory: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        OpenOptions::new().read(true).open(directory)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Ok(())
    }
}

pub(crate) fn write_secure_atomic(path: &Path, contents: &[u8], force: bool) -> io::Result<()> {
    let filename = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "output path must name a file")
        })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("output directory does not exist: {}", parent.display()),
        ));
    }

    let mut temporary = None;
    for attempt in 0..1_000_u32 {
        let candidate = temporary_path(parent, filename, attempt);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&candidate) {
            Ok(mut file) => {
                let write_result = (|| {
                    file.write_all(contents)?;
                    if !contents.ends_with(b"\n") {
                        file.write_all(b"\n")?;
                    }
                    file.sync_all()
                })();
                if let Err(error) = write_result {
                    let _ = fs::remove_file(&candidate);
                    return Err(error);
                }
                temporary = Some(candidate);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let temporary = temporary.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "cannot allocate a unique temporary output file",
        )
    })?;

    let publish_result = if force {
        fs::rename(&temporary, path)
    } else {
        fs::hard_link(&temporary, path).and_then(|()| fs::remove_file(&temporary))
    };
    if let Err(error) = publish_result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    sync_directory(parent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn test_directory() -> PathBuf {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "psmore-secure-output-{}-{timestamp}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn publishes_complete_private_file_without_overwrite_by_default() {
        let directory = test_directory();
        fs::create_dir(&directory).unwrap();
        let output = directory.join("doctor.json");
        write_secure_atomic(&output, br#"{"version":1}"#, false).unwrap();
        assert_eq!(fs::read_to_string(&output).unwrap(), "{\"version\":1}\n");
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let error = write_secure_atomic(&output, br#"{"version":2}"#, false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&output).unwrap(), "{\"version\":1}\n");
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);

        write_secure_atomic(&output, br#"{"version":2}"#, true).unwrap();
        assert_eq!(fs::read_to_string(&output).unwrap(), "{\"version\":2}\n");
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::remove_file(output).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn rejects_directory_targets_and_missing_parents_without_temp_leaks() {
        let directory = test_directory();
        fs::create_dir(&directory).unwrap();
        let directory_error = write_secure_atomic(&directory, b"data", true).unwrap_err();
        assert!(matches!(
            directory_error.kind(),
            io::ErrorKind::IsADirectory | io::ErrorKind::PermissionDenied | io::ErrorKind::Other
        ));
        let missing = directory.join("missing").join("doctor.json");
        let missing_error = write_secure_atomic(&missing, b"data", false).unwrap_err();
        assert_eq!(missing_error.kind(), io::ErrorKind::NotFound);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        fs::remove_dir(directory).unwrap();
    }
}
