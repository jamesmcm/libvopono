mod fork;

use futures::stream::TryStreamExt;
use nix::fcntl::{open, OFlag};
use nix::mount::{mount, umount, MsFlags};
use nix::sched::{setns, unshare, CloneFlags};
use nix::sys::signal::{kill, SIGKILL};
use nix::sys::stat::Mode;
use nix::sys::wait::waitpid;
use nix::unistd::{close, dup2, getpid, mkdir, pipe, unlink};
use nix::unistd::{execvp, fork, ForkResult};
use std::ffi::CString;
use std::io::Stdout;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::process::{Command, Stdio};
use std::thread::sleep;

use fork::fork_fn;

// Network namespace file descriptor is created at /proc/{pid}/ns/net
// To keep alive, we create a file at /var/run/netns/{name}
// then bind mount the namespace file descriptor to /var/run/netns/{name}
// To destroy, unmount /var/run/netns/{name} and delete the created file there
#[derive(Debug)]
struct RawNetworkNamespace {
    name: String,
    pid: i32,
}

// TODO: Implement exec, destroy (do not force on Drop here, that can be done in application if
// desired), veth brige networking
impl RawNetworkNamespace {
    fn new(name: &str) -> Self {
        // Namespace must be created as root (or setuid)
        // TODO: Check if possible with capabilities
        let child = fork_fn(
            || {
                let nsdir = "/var/run/netns";
                unshare(CloneFlags::CLONE_NEWNET).expect("Failed to unshare network namespace");
                mkdir(nsdir, Mode::empty()).ok();
                let ns_namepath = format!("{}/{}", nsdir, name);
                let ns_rawpath = "/proc/self/ns/net";
                let mut oflag: OFlag = OFlag::empty();
                oflag.insert(OFlag::O_RDONLY);
                oflag.insert(OFlag::O_EXCL);
                oflag.insert(OFlag::O_CREAT);
                close(
                    open(ns_namepath.as_str(), oflag, Mode::empty())
                        .expect("Failed to create (open) network namespace name file"),
                )
                .expect("Failed to create (close) network namespace name file");
                mount::<str, str, str, str>(
                    Some(ns_rawpath),
                    ns_namepath.as_str(),
                    None,
                    MsFlags::MS_BIND,
                    None,
                )
                .expect("Mount error");
                std::process::exit(0);
            },
            true,
        );
        Self {
            name: name.to_string(),
            pid: child.as_raw(),
        }
    }

    fn destroy(self) {
        let nsdir = "/var/run/netns";
        let ns_namepath = format!("{}/{}", nsdir, self.name);
        umount(ns_namepath.as_str()).expect("Unmount failed");
        unlink(ns_namepath.as_str()).expect("Unmount failed");
    }

    // TODO: Allow return value from Closure if blocking?
    fn run_in_namespace(&self, fun: impl FnOnce(), blocking: bool) -> nix::unistd::Pid {
        let handle = fork_fn(
            || {
                let nsdir = "/var/run/netns";
                let ns_namepath = format!("{}/{}", nsdir, self.name);
                let mut oflag: OFlag = OFlag::empty();
                oflag.insert(OFlag::O_RDONLY);
                oflag.insert(OFlag::O_EXCL);

                let fd = open(ns_namepath.as_str(), oflag, Mode::empty()).expect("Open failed");

                setns(fd, CloneFlags::CLONE_NEWNET).expect("setns failed");
                close(fd).expect("close failed");

                fun();
            },
            blocking,
        );
        handle
    }

    // TODO: Add blocking version, implement std::process::Command interface?
    fn exec_no_block(&self, command: &[&str], silent: bool) -> nix::unistd::Pid {
        let stdout = std::io::stdout();
        let raw_fd: RawFd = stdout.as_raw_fd();

        // TODO: current directory, user + group ID
        let handle = self.run_in_namespace(
            || {
                if silent {
                    // Redirect stdout to /dev/null
                    let stdout = std::io::stdout();
                    let stderr = std::io::stderr();

                    let raw_fd_stdout: RawFd = stdout.as_raw_fd();
                    let fd_null = open("/dev/null", OFlag::O_WRONLY, Mode::empty())
                        .expect("Failed to open /dev/null");
                    let raw_fd_stderr: RawFd = stderr.as_raw_fd();

                    dup2(fd_null, raw_fd_stdout).expect("Failed to overwrite stdout");
                    dup2(fd_null, raw_fd_stderr).expect("Failed to overwrite stderr");
                    close(fd_null).expect("Failed to close /dev/null fd");
                }

                let args_c: Result<Vec<CString>, _> =
                    command.iter().map(|&x| CString::new(x)).collect();
                let args_c = args_c.expect("Failed to convert args to CString");
                execvp(args_c.first().expect("No command"), args_c.as_slice())
                    .expect("Failed to exec command");
            },
            false,
        );
        handle
    }

    fn add_loopback(&mut self) {
        self.run_in_namespace(
            || {
                let mut rt =
                    tokio::runtime::Runtime::new().expect("Failed to construct Tokio runtime");
                rt.spawn_blocking(|| {
                    async {
                        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
                        // let conn = connection));
                        let mut links = handle
                            .link()
                            .get()
                            .set_name_filter("lo".to_string())
                            .execute();
                        let ip = ipnetwork::IpNetwork::new(
                            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                            8,
                        )
                        .expect("Failed to construct IP");
                        if let Some(link) = links.try_next().await.expect("Failed to get link") {
                            handle
                                .address()
                                .add(link.header.index, ip.ip(), ip.prefix())
                                .execute()
                                .await
                                .expect("Failed to add address")
                        }
                    }
                });
            },
            true,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn create_netns() {
        println!("test pid: {:?}", getpid().as_raw());
        let netns = RawNetworkNamespace::new("testns");
        println!("{:?}", netns);
        let out = std::process::Command::new("ip")
            .args(&["netns", "list"])
            .output()
            .unwrap();
        assert!(String::from_utf8(out.stdout).unwrap().contains("testns"));
        netns.destroy();

        let out = std::process::Command::new("ip")
            .args(&["netns", "list"])
            .output()
            .unwrap();
        assert!(!(String::from_utf8(out.stdout).unwrap().contains("testns")));
    }
    #[test]
    fn exec_netns() {
        println!("test pid: {:?}", getpid().as_raw());
        let netns = RawNetworkNamespace::new("execns");
        println!("{:?}", netns);
        let handle = netns.exec_no_block(&["ping", "-c", "1", "8.8.8.8"], false);
        std::thread::sleep(std::time::Duration::from_secs(2));
        kill(handle, SIGKILL).expect("kill failed");
        netns.destroy();
    }
    #[test]
    fn add_loopback() {
        let mut netns = RawNetworkNamespace::new("testlo");
        netns.add_loopback();
        // TODO: Make this blocking
        let handle = netns.exec_no_block(&["ip", "addr"], false);
        std::thread::sleep(std::time::Duration::from_secs(2));
        kill(handle, SIGKILL).expect("kill failed");
        netns.destroy();
    }
}
