use ipnetwork::{IpNetwork, Ipv4Network};
use libvopono::*;
use nix::sys::signal::{kill, SIGKILL};
use std::net::Ipv4Addr;
fn main() {
    let mut netns = RawNetworkNamespace::new("testlobin");
    let handle = netns.exec_no_block(&["ip", "addr"], false);
    std::thread::sleep(std::time::Duration::from_secs(2));
    kill(handle, SIGKILL).expect("kill failed");
    netns.add_loopback();

    let srcip = ipnetwork::IpNetwork::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 200, 200, 2)),
        24,
    )
    .expect("Failed to construct IP");

    let dstip = ipnetwork::IpNetwork::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 200, 200, 1)),
        24,
    )
    .expect("Failed to construct IP");
    netns.add_veth_bridge("vpnsrc", "vpndst", &srcip, &dstip);
    std::thread::sleep(std::time::Duration::from_secs(1));
    // let handle = netns.exec_no_block(&["ip", "addr"], false);
    // std::thread::sleep(std::time::Duration::from_secs(2));
    // let handle = netns.exec_no_block(&["ip", "link"], false);
    // std::thread::sleep(std::time::Duration::from_secs(2));
    // let handle = netns.exec_no_block(&["ip", "route"], false);
    // std::thread::sleep(std::time::Duration::from_secs(2));

    // Note network passed to nftable rule with netlink must have 0s for insignificant bits!
    let ipnet = ipnetwork::IpNetwork::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 200, 200, 0)),
        24,
    )
    .expect("Failed to construct IP");
    host_add_masquerade_nft("vopono_nat", "vopono_nat", "wlp1s0", ipnet);
    host_enable_ipv4_forwarding();

    // Standard internet connection should work at this point

    // Create Wireguard device - ip link
    // TODO: Wrap this so we can destroy it later
    netns.add_wireguard_device("vopono_wg");
    // Set Wireguard device config
    let config = read_wg_config(std::path::Path::new(
        "/home/archie/.config/vopono/mv/wireguard/usa-us4.conf",
    ));
    netns.set_wireguard_device("vopono_wg", &config);
    netns.wg_dev_up("vopono_wg", &config);

    // Set up routing
    // Set up DNS
    // Set firewall rules

    // kill(handle, SIGKILL).expect("kill failed");
    // netns.destroy();
}
