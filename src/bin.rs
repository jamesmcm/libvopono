use libvopono::RawNetworkNamespace;
use nix::sys::signal::{kill, SIGKILL};

fn main() {
    let mut netns = RawNetworkNamespace::new("testlobin");
    let handle = netns.exec_no_block(&["ip", "addr"], false);
    std::thread::sleep(std::time::Duration::from_secs(2));
    kill(handle, SIGKILL).expect("kill failed");
    netns.add_loopback();
    std::thread::sleep(std::time::Duration::from_secs(5));
    let handle = netns.exec_no_block(&["ip", "addr"], false);
    std::thread::sleep(std::time::Duration::from_secs(2));
    // kill(handle, SIGKILL).expect("kill failed");
    // netns.destroy();
}
