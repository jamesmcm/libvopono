use libvopono::RawNetworkNamespace;
use nix::sys::signal::{kill, SIGKILL};
fn main() {
    let mut netns = RawNetworkNamespace::new("testlobin");
    let handle = netns.exec_no_block(&["ip", "addr"], false);
    std::thread::sleep(std::time::Duration::from_secs(12));
    kill(handle, SIGKILL).expect("kill failed");
    netns.add_loopback();

    let srcip = ipnetwork::IpNetwork::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 200, 200, 1)),
        24,
    )
    .expect("Failed to construct IP");

    let dstip = ipnetwork::IpNetwork::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 200, 200, 2)),
        24,
    )
    .expect("Failed to construct IP");
    netns.add_veth_bridge("vpnsrc", "vpndst", &srcip, &dstip);
    std::thread::sleep(std::time::Duration::from_secs(5));
    let handle = netns.exec_no_block(&["ip", "addr"], false);
    std::thread::sleep(std::time::Duration::from_secs(2));
    let handle = netns.exec_no_block(&["ip", "link"], false);
    std::thread::sleep(std::time::Duration::from_secs(2));
    // kill(handle, SIGKILL).expect("kill failed");
    // netns.destroy();
}
