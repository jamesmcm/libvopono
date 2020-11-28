mod fork;

use crossbeam::scope;
use nix::fcntl::{open, OFlag};
use nix::mount::{mount, umount, MsFlags};
use nix::sched::{setns, unshare, CloneFlags};
use nix::sys::signal::{kill, SIGKILL};
use nix::sys::stat::Mode;
use nix::sys::wait::waitpid;
use nix::unistd::{close, getpid, mkdir, unlink};
use nix::unistd::{fork, ForkResult};
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

    fn exec_no_block(&self, command: &str, args: &[&str], silent: bool) -> std::process::Child {
        let stdout = std::io::stdout();
        let raw_fd: RawFd = stdout.as_raw_fd();

        // TODO: Make this spawn from separate process, handle stdout
        // TODO: current directory, environment variables, user ID
        // TODO: Make this use fork_fn
        // let handle = scope(|s| {
        //     let thread = s.spawn(|_| {
        let nsdir = "/var/run/netns";
        let ns_namepath = format!("{}/{}", nsdir, self.name);
        println!("{}", ns_namepath);

        let mut oflag: OFlag = OFlag::empty();
        oflag.insert(OFlag::O_RDONLY);
        oflag.insert(OFlag::O_EXCL);

        let fd = open(ns_namepath.as_str(), oflag, Mode::empty()).expect("Open failed");

        setns(fd, CloneFlags::CLONE_NEWNET).expect("setns failed");
        close(fd).expect("close failed");
        let mut handle = Command::new(command);
        handle.args(args);
        if silent {
            handle.stdout(Stdio::null());
            handle.stderr(Stdio::null());
        } else {
            unsafe {
                handle.stdout(Stdio::from_raw_fd(raw_fd));
                handle.stderr(Stdio::from_raw_fd(raw_fd));
            }
        }

        let handle = handle.spawn().expect("Spawn failed");
        // });
        // thread.join().unwrap()
        // })
        // .unwrap();
        println!("{:?}", handle);
        handle
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
        let mut handle = netns.exec_no_block("ping", &["-c", "1", "8.8.8.8"], false);
        // handle.kill().expect("kill failed");
        // netns.destroy();
    }
}
