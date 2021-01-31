mod errors;
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
use nftnl::{nft_expr, nftnl_sys::libc, Batch, Chain, FinalizedBatch, ProtoFamily, Rule, Table};
use sysctl::Sysctl;

/// Network namespace file descriptor is created at /proc/{pid}/ns/net
/// To keep alive, we create a file at /var/run/netns/{name}
/// then bind mount the namespace file descriptor to /var/run/netns/{name}
/// To destroy, unmount /var/run/netns/{name} and delete the created file there
#[derive(Debug)]
pub struct RawNetworkNamespace {
    name: String,
    pid: i32,
}

// TODO: Implement exec, destroy (do not force on Drop here, that can be done in application if
// desired), veth brige networking
impl RawNetworkNamespace {
    pub fn new(name: &str) -> Self {
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

    pub fn destroy(self) {
        let nsdir = "/var/run/netns";
        let ns_namepath = format!("{}/{}", nsdir, self.name);
        umount(ns_namepath.as_str()).expect("Unmount failed");
        unlink(ns_namepath.as_str()).expect("Unmount failed");
    }

    // TODO: Allow return value from Closure if blocking?
    // TODO: Can we do better than spawning a new process for every operation?
    // Consider maintaining one process inside namespace with inter-process communication
    // But need to handle possibility of many network namespaces
    pub fn run_in_namespace(&self, fun: impl FnOnce(), blocking: bool) -> nix::unistd::Pid {
        fork_fn(
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
        )
    }

    // TODO: Add blocking version, implement std::process::Command interface? + IPC?
    pub fn exec_no_block(&self, command: &[&str], silent: bool) -> nix::unistd::Pid {
        // let stdout = std::io::stdout();
        // let raw_fd: RawFd = stdout.as_raw_fd();

        // TODO: current directory, user + group ID
        self.run_in_namespace(
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
        )
    }

    /// Create loopback and set up
    /// Equivalent of:
    /// ip netns exec netns ip addr add 127.0.0.1/8 dev lo
    /// ip netns exec netns ip link set lo up
    pub fn add_loopback(&mut self) {
        self.run_in_namespace(
            || {
                let rt = tokio::runtime::Runtime::new().expect("Failed to construct Tokio runtime");
                rt.block_on(async {
                    let (connection, handle, _) = rtnetlink::new_connection().unwrap();

                    rt.spawn(connection);
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
                            .expect("Failed to add address");

                        handle
                            .link()
                            .set(link.header.index)
                            .up()
                            .execute()
                            .await
                            .expect("Failed to set link up");
                    }
                });

                std::process::exit(0);
            },
            false,
        );
    }

    pub fn add_veth_bridge(
        &mut self,
        src_name: &str,
        dest_name: &str,
        src_ip: &ipnetwork::IpNetwork,
        dest_ip: &ipnetwork::IpNetwork,
    ) {
        // TODO: Refactor this to get device indices only once!
        // On host - dest veth
        let rt = tokio::runtime::Runtime::new().expect("Failed to construct Tokio runtime");
        rt.block_on(async {
            let (connection, handle, _) = rtnetlink::new_connection().unwrap();

            rt.spawn(connection);
            handle
                .link()
                .add()
                .veth(dest_name.to_string(), src_name.to_string())
                .execute()
                .await
                .expect("Failed to create veth link");

            let mut links = handle
                .link()
                .get()
                .set_name_filter(dest_name.to_string())
                .execute();
            if let Some(link) = links.try_next().await.expect("Failed to get dest link") {
                handle
                    .address()
                    .add(link.header.index, dest_ip.ip(), dest_ip.prefix())
                    .execute()
                    .await
                    .expect("Failed to add dest address");
                handle
                    .link()
                    .set(link.header.index)
                    .up()
                    .execute()
                    .await
                    .expect("Failed to set link up");
            }

            // Move src to namespace
            let mut links = handle
                .link()
                .get()
                .set_name_filter(src_name.to_string())
                .execute();

            let fd_netns = open(
                format!("/var/run/netns/{}", self.name).as_str(),
                OFlag::O_RDONLY,
                Mode::empty(),
            )
            .expect("Failed to open netns fd");
            if let Some(link) = links.try_next().await.expect("Failed to get src link") {
                println!("pid: {:?}", self.pid);
                handle
                    .link()
                    .set(link.header.index)
                    .setns_by_fd(fd_netns)
                    .execute()
                    .await
                    .expect("Failed to move and set src link up");
            }
            close(fd_netns).expect("Failed to close netns fd");
        });

        // In netns - src veth
        self.run_in_namespace(
            || {
                let rt = tokio::runtime::Runtime::new().expect("Failed to construct Tokio runtime");
                rt.block_on(async {
                    let (connection, handle, _) = rtnetlink::new_connection().unwrap();

                    rt.spawn(connection);

                    let mut links = handle
                        .link()
                        .get()
                        .set_name_filter(src_name.to_string())
                        .execute();
                    if let Some(link) = links.try_next().await.expect("Failed to get src link") {
                        handle
                            .address()
                            .add(link.header.index, src_ip.ip(), src_ip.prefix())
                            .execute()
                            .await
                            .expect("Failed to add src address");

                        // May be unnecessary since we set up when moving in to this namespace
                        handle
                            .link()
                            .set(link.header.index)
                            .up()
                            .execute()
                            .await
                            .expect("Failed to set link up");

                        // Route default gateway - ip netns exec piavpn ip route add default via 10.200.200.1 dev vpn1
                        let route = handle.route();
                        let dest_ipv4 = if let std::net::IpAddr::V4(ip) = dest_ip.ip() {
                            ip
                        } else {
                            panic!("Bad ipv4 IP for veth gateway");
                        };
                        route
                            .add()
                            .input_interface(link.header.index)
                            .v4()
                            .gateway(dest_ipv4)
                            .execute()
                            .await
                            .expect("Failed to add veth route");
                    }
                });

                std::process::exit(0);
            },
            false,
        );
    }
}

pub fn host_add_masquerade_nft(
    table_name: &str,
    chain_name: &str,
    interface_name: &str,
    ip_mask: &str,
) {
    // TODO: Finish this and add Error types
    // Get interface index with rtnetlink instead?

    let mut batch = Batch::new();

    // Add table: nft add table inet vopono_nat
    let table = Table::new(&CString::new(table_name).unwrap(), ProtoFamily::Inet);
    batch.add(&table, nftnl::MsgType::Add);

    // Add postrouting chain: nft add chain inet vopono_nat postrouting { type nat hook postrouting priority 100 ; }
    // // TODO update this to set nat type etc.
    let mut out_chain = Chain::new(&CString::new(chain_name).unwrap(), &table);
    out_chain.set_hook(nftnl::Hook::PostRouting, 100);
    out_chain.set_type(nftnl::ChainType::Nat);
    // out_chain.set_policy(nftnl::Policy::Accept);
    batch.add(&out_chain, nftnl::MsgType::Add);

    // Add masquerade rule: nft add rule inet vopono_nat postrouting oifname &interface.name ip saddr &ip_mask counter masquerade
    let mut allow_loopback_in_rule = Rule::new(&out_chain);
    // TODO: Get index from rtnetlink?
    // let lo_iface_index = iface_index(interface_name).expect("TODO ERROR");

    // TODO Fix below vs. vopono, currently gives:
    // table inet vopono_nat {
    //         chain vopono_nat {
    //                 type nat hook postrouting priority srcnat; policy accept;
    //                 oifname "e*" counter packets 0 bytes 0 masquerade
    //         }
    // }
    // netlink: Error: Relational expression size mismatch
    allow_loopback_in_rule.add_expr(&nft_expr!(meta oifname));
    allow_loopback_in_rule.add_expr(&nft_expr!(cmp == interface_name));
    // TODO: Does this work on non-ethernet output interfaces?
    allow_loopback_in_rule.add_expr(&nft_expr!(payload ethernet saddr));
    allow_loopback_in_rule.add_expr(&nft_expr!(cmp == ip_mask));
    allow_loopback_in_rule.add_expr(&nft_expr!(counter));
    allow_loopback_in_rule.add_expr(&nft_expr!(masquerade));

    batch.add(&allow_loopback_in_rule, nftnl::MsgType::Add);
    let finalized_batch = batch.finalize();

    // TODO: Error handling
    send_and_process(&finalized_batch);
}

fn send_and_process(batch: &FinalizedBatch) {
    // Create a netlink socket to netfilter.
    let socket = mnl::Socket::new(mnl::Bus::Netfilter).expect("TODO ERROR");
    // Send all the bytes in the batch.
    socket.send_all(batch).expect("TODO ERROR");

    // Try to parse the messages coming back from netfilter. This part is still very unclear.
    let portid = socket.portid();
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let very_unclear_what_this_is_for = 2;
    while let Some(message) = socket_recv(&socket, &mut buffer[..]).expect("TODO ERROR") {
        match mnl::cb_run(message, very_unclear_what_this_is_for, portid).expect("TODO ERROR") {
            mnl::CbResult::Stop => {
                break;
            }
            mnl::CbResult::Ok => (),
        }
    }
    // Ok(())
}

// TODO - replace this with rtnetlink calls?
fn iface_index(name: &str) -> Result<libc::c_uint, std::io::Error> {
    let c_name = CString::new(name)?;
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(index)
    }
}

fn socket_recv<'a>(
    socket: &mnl::Socket,
    buf: &'a mut [u8],
) -> Result<Option<&'a [u8]>, Box<dyn std::error::Error>> {
    let ret = socket.recv(buf)?;
    if ret > 0 {
        Ok(Some(&buf[..ret]))
    } else {
        Ok(None)
    }
}

pub fn host_enable_ipv4_forwarding() {
    // sysctl -q net.ipv4.ip_forward=1
    let ctl = sysctl::Ctl::new("net.ipv4.ip_forward").expect("TODO ERROR sysctl");
    let org = ctl.value().unwrap();
    println!("original sysctl val: {}", org);
    let set = ctl
        .set_value(sysctl::CtlValue::String("1".to_string()))
        .expect("TODO ERROR sysctl");
}

#[cfg(test)]
mod tests {
    // Tests must be run with superuser privileges :(
    // sudo -E cargo test
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
        std::thread::sleep(std::time::Duration::from_secs(5));
        let handle = netns.exec_no_block(&["ip", "addr"], false);
        std::thread::sleep(std::time::Duration::from_secs(2));
        kill(handle, SIGKILL).expect("kill failed");
        netns.destroy();
    }
}
