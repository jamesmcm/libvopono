mod errors;
mod fork;
mod wg_config;

use futures::stream::TryStreamExt;
use ipnetwork::Ipv4Network;
use nix::fcntl::{open, OFlag};
use nix::mount::{mount, umount, MsFlags};
use nix::sched::{setns, unshare, CloneFlags};
use nix::sys::signal::{kill, SIGKILL};
use nix::sys::stat::Mode;
use nix::sys::wait::waitpid;
use nix::unistd::{close, dup2, getpid, mkdir, pipe, unlink};
use nix::unistd::{execvp, fork, ForkResult};
use regex::Regex;
use std::convert::TryInto;
use std::ffi::CString;
use std::io::Stdout;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::sleep;
use wireguard_uapi::{RouteSocket, WgSocket};

use wg_config::WireguardConfig;

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
                            .output_interface(link.header.index)
                            .v4()
                            .gateway(dest_ipv4)
                            .protocol(0)
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

    pub fn add_wireguard_device(&self, name: &str) {
        self.run_in_namespace(|| add_wireguard_device(name), true);
    }

    pub fn set_wireguard_device(&self, name: &str, config: &WireguardConfig) {
        self.run_in_namespace(|| set_wireguard_device(name, config), true);
    }

    /// Equivalent of:
    /// ip -6 address add {address} dev {name}
    /// ip -4 address add {address} dev {name}
    /// ip link set mtu 1420 up dev {name}
    pub fn wg_dev_up(&self, name: &str, config: &WireguardConfig) {
        self.run_in_namespace(
            || {
                let rt = tokio::runtime::Runtime::new().expect("Failed to construct Tokio runtime");
                rt.block_on(async {
                    let (connection, handle, _) = rtnetlink::new_connection().unwrap();

                    rt.spawn(connection);
                    let mut links = handle
                        .link()
                        .get()
                        .set_name_filter(name.to_string())
                        .execute();

                    if let Some(link) = links.try_next().await.expect("Failed to get link") {
                        for address in config.interface.address.iter() {
                            // TODO: device is not specified here?
                            handle
                                .address()
                                .add(link.header.index, address.addr(), 32)
                                .execute()
                                .await
                                .expect("Failed to add address");

                            // TODO: custom MTU
                            handle
                                .link()
                                .set(link.header.index)
                                .mtu(1420)
                                .up()
                                .execute()
                                .await
                                .expect("Failed to set link up");
                        }

                        // ip -4 route add 0.0.0.0/0 dev {if_name} table {fwmark}
                        let route = handle.route();
                        route
                            .add()
                            // TODO: This gets a cryptic error when this is input_interface and no
                            // error from the rtnetlink crate!
                            // Would it be possible to improve this API to catch bad requests
                            // at build time?
                            .output_interface(link.header.index)
                            .v4()
                            .table(111)
                            .destination_prefix(Ipv4Addr::new(0, 0, 0, 0), 0)
                            .execute()
                            .await
                            .expect("Failed to add Wireguard route");
                    }
                    //TODO:
                    // "ip", "-4", "rule", "add", "not", "fwmark", fwmark, "table", fwmark
                    // https://github.com/svinota/pyroute2/issues/756
                    // Also need NLAs? :(
                    // "ip","-4","rule","add","table","main","suppress_prefixlength","0",
                    // Probably not needed inside netns: but can try to implement with attributes
                    // https://stackoverflow.com/questions/65178004/what-does-ip-4-rule-add-table-main-suppress-prefixlength-0-meaning
                    // Added as attribute
                    // addattr32(&req.n, sizeof(req), FRA_SUPPRESS_PREFIXLEN, pl);
                    // append to request NLAs directly?
                    // https://docs.rs/netlink-packet-route/0.7.1/netlink_packet_route/rtnl/route/nlas/enum.Nla.html
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
    ip_mask: ipnetwork::IpNetwork,
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

    let ipnet = ip_mask;
    allow_loopback_in_rule.add_expr(&nft_expr!(meta oifname));
    allow_loopback_in_rule.add_expr(&nft_expr!(
        cmp == nftnl::expr::InterfaceName::Exact(
            CString::new(interface_name).expect("Bad interface name to CString conversion")
        )
    ));

    allow_loopback_in_rule.add_expr(&nft_expr!(meta nfproto));
    allow_loopback_in_rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV4 as u8));

    allow_loopback_in_rule.add_expr(&nft_expr!(payload ipv4 saddr));
    allow_loopback_in_rule.add_expr(&nft_expr!(bitwise mask ipnet.mask(), xor 0));
    allow_loopback_in_rule.add_expr(&nft_expr!(cmp == ipnet.ip()));

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
    let _set = ctl
        .set_value(sysctl::CtlValue::String("1".to_string()))
        .expect("TODO ERROR sysctl");
}

/// Equivalent of: ip link add {name} type wireguard
pub fn add_wireguard_device(name: &str) {
    wireguard_uapi::RouteSocket::connect()
        .expect("failed to connect route socket")
        .add_device(name)
        .expect("Failed to add wg device")
}

pub fn read_wg_config(config_file: &Path) -> WireguardConfig {
    let config_string = std::fs::read_to_string(&config_file).unwrap();

    // TODO: Avoid hacky regex for valid toml
    let re = Regex::new(r"(?P<key>[^\s]+) = (?P<value>[^\s]+)").unwrap();
    let mut config_string = re
        .replace_all(&config_string, "$key = \"$value\"")
        .to_string();
    config_string.push('\n');
    toml::from_str(&config_string).unwrap()
}

// TODO: Change wireguard_uapi api to use &mut here for chaining?
// TODO: Change API to make AllowedIP take ownership
// TODO: Change API to accept Vec instead of only 32-bit array for keys
/// Equivalent of: wg setconf {name} {config_file}
pub fn set_wireguard_device(name: &str, config: &WireguardConfig) {
    let mut dev = wireguard_uapi::linux::set::Device::from_ifname(name);
    let private_key_vec = base64::decode(config.interface.private_key.clone()).unwrap();
    let mut privkey: [u8; 32] = [0; 32];
    for i in 0..privkey.len() {
        privkey[i] = private_key_vec[i];
    }

    let mut dev = dev.private_key(&privkey);
    // TODO: Are we assuming only one peer here?
    let mut dev = dev.flags(vec![wireguard_uapi::linux::set::WgDeviceF::ReplacePeers]);
    let mut dev = dev.listen_port(0);
    // TODO: is it okay to set this here?
    let mut dev = dev.fwmark(111);

    let public_key_vec = base64::decode(config.peer.public_key.clone()).unwrap();
    let mut pubkey: [u8; 32] = [0; 32];
    for i in 0..pubkey.len() {
        pubkey[i] = public_key_vec[i];
    }
    let mut peer = wireguard_uapi::linux::set::Peer::from_public_key(&pubkey);
    let mut peer = peer.flags(vec![wireguard_uapi::linux::set::WgPeerF::ReplaceAllowedIps]);
    let mut peer = peer.endpoint(&config.peer.endpoint);

    let addrs: Vec<IpAddr> = config.peer.allowed_ips.iter().map(|x| x.addr()).collect();

    let allowed_ips = addrs
        .iter()
        .map(|x| {
            let mut ip = wireguard_uapi::linux::set::AllowedIp::from_ipaddr(&x);
            ip.cidr_mask = Some(0);
            ip
        })
        .collect::<Vec<_>>();
    let mut peer = peer.allowed_ips(allowed_ips);
    let mut dev = dev.peers(vec![peer]);
    let mut socket = wireguard_uapi::WgSocket::connect().unwrap();
    socket.set_device(dev).unwrap();
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
