use crossbeam::scope;
use nix::fcntl::{open, OFlag};
use nix::mount::{mount, MsFlags};
use nix::sched::{setns, unshare, CloneFlags};
use nix::sys::stat::Mode;
use nix::unistd::{close, getpid, mkdir};
use std::os::unix::io::RawFd;

#[derive(Debug)]
struct RawNetworkNamespace {
    name: String,
    pid: i32,
}

impl RawNetworkNamespace {
    fn new(name: &str) -> Self {
        let pid = scope(|s| {
            let thread = s.spawn(|_| {
                unshare(CloneFlags::CLONE_NEWNET).expect("Failed to unshare network namespace");
                let nsdir = "/var/run/netns";
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
                getpid().as_raw()
            });
            let pid: i32 = thread.join().expect("Thread error");
            pid
        })
        .expect("Crossbeam error");
        Self {
            name: name.to_string(),
            pid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn create_netns() {
        let netns = RawNetworkNamespace::new("testns");
        println!("{:?}", netns);
    }
}
