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
