use log::debug;
use nix::sys::wait::waitpid;
use nix::unistd::{fork, ForkResult};

// TODO: Fix sharing of pipes - stdout
pub fn fork_fn(child_fun: impl FnOnce(), blocking: bool) -> nix::unistd::Pid {
    let child = match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            debug!(
                "Continuing execution in parent process, new child has pid: {}",
                child
            );
            if blocking {
                loop {
                    match waitpid(child, None).expect("wait failed") {
                        nix::sys::wait::WaitStatus::StillAlive => (),
                        _ => break,
                    }
                }
            }
            child
        }
        Ok(ForkResult::Child) => {
            child_fun();
            std::process::exit(0);
        }
        Err(_) => panic!("Fork failed"),
    };
    child
}
