use std::fs;
use std::io;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceLayout {
    pub root: PathBuf,
    pub data_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub control_port_file: PathBuf,
}

impl InstanceLayout {
    pub fn prepare(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        let data_dir = root.join("data");
        let runtime_dir = root.join("runtime");
        let control_port_file = runtime_dir.join("control.port");

        fs::create_dir_all(&data_dir)?;
        fs::create_dir_all(&runtime_dir)?;
        set_private_dir(&root)?;
        set_private_dir(&data_dir)?;
        set_private_dir(&runtime_dir)?;

        match fs::remove_file(&control_port_file) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        Ok(Self {
            root,
            data_dir,
            runtime_dir,
            control_port_file,
        })
    }
}

#[cfg(unix)]
fn set_private_dir(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)
}

#[cfg(not(unix))]
fn set_private_dir(_path: &std::path::Path) -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn unique_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    }

    #[test]
    fn instance_layout_creates_private_runtime_directories() {
        let root = std::env::temp_dir().join(format!(
            "torlane-layout-{}-{}",
            std::process::id(),
            unique_nanos()
        ));
        let stale_root = root.join("runtime");
        fs::create_dir_all(&stale_root).unwrap();
        let stale_port_file = stale_root.join("control.port");
        fs::write(&stale_port_file, b"stale").unwrap();

        let layout = InstanceLayout::prepare(&root).unwrap();

        assert_eq!(layout.data_dir, root.join("data"));
        assert_eq!(layout.runtime_dir, root.join("runtime"));
        assert_eq!(layout.control_port_file, root.join("runtime/control.port"));
        assert!(!layout.control_port_file.exists());

        for path in [&layout.root, &layout.data_dir, &layout.runtime_dir] {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }

        let _ = fs::remove_dir_all(root);
    }
}
