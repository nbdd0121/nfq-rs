use nfq::{Queue, Verdict};

fn main() -> std::io::Result<()> {
    let mut queue = Queue::open()?;
    queue.bind(0)?;
    queue.set_recv_conntrack(0, true)?;
    queue.set_recv_security_context(0, true)?;
    queue.set_recv_uid_gid(0, true)?;
    loop {
        let mut msg = queue.recv()?;
        println!("{:#?}", msg);
        msg.set_verdict(Verdict::Accept);
        queue.verdict(msg)?;
    }
}
