//! nfq - NetFilter queue for Rust
//!
//! `nfq` is Rust library for performing userspace handling of packets queued by the kernel packet
//! packet filter chains.
//! 
//! # License
//! In contrast to `libnetfilter_queue` which is licensed under GPL 2.0, which will require all
//! binaries using that library to be bound by GPL, `nfq` is dual-licensed under MIT/Apache-2.0.
//! To achieve this, `nfq` does not use `libnetfilter_queue`. Instead, `nfq` communicates using
//! libmnl directly, which is licensed under LGPL.
//!
//! # Example
//!
//! Here is an example which accepts all packets.
//! ```rust,ignore
//! use nfq::{Queue, Verdict};
//!
//! fn main() -> std::io::Result<()> {
//!    let mut queue = Queue::open()?; 
//!    queue.bind(0)?;
//!    loop {
//!        let msg = queue.recv()?;
//!        queue.verdict(msg, Verdict::Accept)?;
//!    }
//!    Ok(())
//! }
//! ```

mod binding;

use libc::*;
use mnl_sys::{self, *};
use binding::*;
use std::sync::Arc;
use std::io::Result;
use std::time::{Duration, SystemTime};
use std::collections::VecDeque;

fn be16_to_cpu(x: u16) -> u16 {
    u16::from_ne_bytes(x.to_be_bytes())
}
fn be32_to_cpu(x: u32) -> u32 {
    u32::from_ne_bytes(x.to_be_bytes())
}
fn be64_to_cpu(x: u64) -> u64 {
    u64::from_ne_bytes(x.to_be_bytes())
}

/// Decision made on a specific packet.
#[derive(Clone, Copy)]
pub enum Verdict {
    /// Discard the packet
    Drop,
    /// Accept the packet, continue iterations
    Accept,
    /// Inject the packet into a different queue
    Queue(u16),
    /// Iterate the same cycle once more
    Repeat,
    /// Accept the packet, but don't continue iterations
    Stop,
}

unsafe fn nfq_hdr_put(buf: &mut [u8], typ: u16, queue_num: u16) -> *mut nlmsghdr {
    let nlh = mnl_sys::mnl_nlmsg_put_header(buf.as_mut_ptr() as _);
    (*nlh).nlmsg_type = ((NFNL_SUBSYS_QUEUE as u16) << 8) | typ;
    (*nlh).nlmsg_flags = NLM_F_REQUEST as u16;
    let nfg = mnl_sys::mnl_nlmsg_put_extra_header(nlh, std::mem::size_of::<nfgenmsg>()) as *mut nfgenmsg;
    (*nfg).nfgen_family = libc::AF_UNSPEC as u8;
    (*nfg).version = NFNETLINK_V0 as u8;
    (*nfg).res_id = be16_to_cpu(queue_num);
    nlh
}

/// A network packet with associated metadata.
pub struct Message {
    /// This is here for lifetime requirements, but we're not using it directly.
    #[allow(dead_code)]
    buffer: Arc<Vec<u8>>,
    nlh: *const nlmsghdr,
    nfmark: u32,
    indev: u32,
    outdev: u32,
    physindev: u32,
    physoutdev: u32,
    orig_len: u32,
    skbinfo: u32,
    secctx: Option<&'static str>,
    uid: Option<u32>,
    gid: Option<u32>,
    timestamp: Option<SystemTime>,
    hwaddr: *const nfqnl_msg_packet_hw,
    hdr: *const nfqnl_msg_packet_hdr,
    /// The actual lifetime is 'buffer
    payload: &'static [u8],
}

unsafe impl Send for Message {}

impl Message {
    /// Get the nfmark (fwmark) of the packet.
    pub fn nfmark(&self) -> u32 { self.nfmark }

    /// Get the interface index of the interface the packet arrived on. If the packet is locally
    /// generated, or the input interface is no longer known (e.g. `POSTROUTING` chain), 0 is
    /// returned.
    pub fn indev(&self) -> u32 { self.indev }

    /// Get the interface index of the bridge port the packet arrived on. If the packet is locally
    /// generated, or the input interface is no longer known (e.g. `POSTROUTING` chain), 0 is
    /// returned.
    pub fn physindev(&self) -> u32 { self.physindev }

    /// Get the interface index of the interface the packet is to be transmitted from. If the
    /// packet is locally destinated, or the output interface is unknown (e.g. `PREROUTING` chain),
    /// 0 is returned.
    pub fn outdev(&self) -> u32 { self.outdev }

    /// Get the interface index of the bridge port the packet is to be transmitted from. If the
    /// packet is locally destinated, or the output interface is unknown (e.g. `PREROUTING` chain),
    /// 0 is returned.
    pub fn physoutdev(&self) -> u32 { self.physoutdev }

    /// Get the original length of the packet.
    pub fn original_len(&self) -> usize {
        if self.orig_len == 0 { self.payload.len() } else { self.orig_len as usize }
    }

    /// Check if the packet is GSO-offloaded.
    pub fn seg_offload(&self) -> bool {
        self.skbinfo & NFQA_SKB_GSO != 0
    }

    /// Check if the checksums are ready, e.g. due to offload.
    pub fn csum_ready(&self) -> bool {
        self.skbinfo & NFQA_SKB_CSUMNOTREADY == 0
    }

    /// Get the security context string of the local process sending the packet. If not applicable,
    /// `None` is returned.
    pub fn security_context(&self) -> Option<&str> { self.secctx }
    
    /// Get the UID of the local process sending the packet. If not applicable, `None` is returned.
    pub fn uid(&self) -> Option<u32> { self.uid }

    /// Get the GID of the local process sending the packet. If not applicable, `None` is returned.
    pub fn gid(&self) -> Option<u32> { self.gid }
    
    /// Get the timestamp of the packet.
    pub fn timestamp(&self) -> Option<SystemTime> { self.timestamp }

    /// Get the hardware address associated with the packet. For Ethernet packets, the hardware
    /// address returned will be the MAC address of the packet source host, if any.
    pub fn hw_addr(&self) -> Option<&[u8]> {
        if self.hwaddr.is_null() { return None }
        unsafe {
            let len = be16_to_cpu((*self.hwaddr).hw_addrlen) as usize;
            Some(&(*self.hwaddr).hw_addr[..len])
        }
    }

    /// Get the link layer protocol number, e.g. the EtherType field on Ethernet links.
    pub fn hw_protocol(&self) -> u16 {
        be16_to_cpu(unsafe { (*self.hdr).hw_protocol })
    }

    /// Get the netfilter hook number that handles this packet.
    pub fn hook(&self) -> u8 {
        unsafe { (*self.hdr).hook }
    }

    /// Get the content of the payload.
    pub fn payload(&self) -> &[u8] {
        self.payload
    }
}

unsafe extern "C" fn parse_attr(attr: *const nlattr, data: *mut c_void) -> c_int {
    let message = &mut *(data as *mut Message);
    let typ = mnl_attr_get_type(attr) as c_uint;
    match typ {
        NFQA_MARK => message.nfmark = be32_to_cpu(mnl_attr_get_u32(attr)),
        NFQA_IFINDEX_INDEV => message.indev = be32_to_cpu(mnl_attr_get_u32(attr)),
        NFQA_IFINDEX_OUTDEV => message.outdev = be32_to_cpu(mnl_attr_get_u32(attr)),
        NFQA_IFINDEX_PHYSINDEV => message.physindev = be32_to_cpu(mnl_attr_get_u32(attr)),
        NFQA_IFINDEX_PHYSOUTDEV => message.physoutdev = be32_to_cpu(mnl_attr_get_u32(attr)),
        NFQA_HWADDR => {
            if mnl_attr_validate2(attr, MNL_TYPE_UNSPEC, std::mem::size_of::<nfqnl_msg_packet_hw>()) < 0 {
                return mnl_sys::MNL_CB_ERROR
            }
            message.hwaddr = mnl_attr_get_payload(attr) as _;
        }
        NFQA_CAP_LEN => message.orig_len = be32_to_cpu(mnl_attr_get_u32(attr)),
        NFQA_SKB_INFO => message.skbinfo = be32_to_cpu(mnl_attr_get_u32(attr)),
        NFQA_SECCTX => message.secctx = Some(std::ffi::CStr::from_ptr(mnl_attr_get_str(attr)).to_str().unwrap()),
        NFQA_UID => message.uid = Some(be32_to_cpu(mnl_attr_get_u32(attr))),
        NFQA_GID => message.gid = Some(be32_to_cpu(mnl_attr_get_u32(attr))),
        NFQA_TIMESTAMP => {
            let timeval = mnl_attr_get_payload(attr) as *const nfqnl_msg_packet_timestamp;
            let duration = Duration::from_secs(be64_to_cpu((*timeval).sec)) +
                Duration::from_micros(be64_to_cpu((*timeval).usec));
            message.timestamp = Some(SystemTime::UNIX_EPOCH + duration);
        }
        NFQA_PACKET_HDR => {
            if mnl_attr_validate2(attr, MNL_TYPE_UNSPEC, std::mem::size_of::<nfqnl_msg_packet_hdr>()) < 0 {
                return mnl_sys::MNL_CB_ERROR
            }
            message.hdr = mnl_attr_get_payload(attr) as _;
        }
        NFQA_PAYLOAD => {
            let len = mnl_attr_get_payload_len(attr);
            let payload = mnl_attr_get_payload(attr);
            message.payload = std::slice::from_raw_parts(payload as *const u8, len as usize);
        }
        _ => (),
    }
    mnl_sys::MNL_CB_OK
}

unsafe extern "C" fn queue_cb(nlh: *const nlmsghdr, data: *mut c_void) -> c_int {
    let queue = &mut *(data as *mut Queue);
    let mut message = Message {
        buffer: Arc::clone(&queue.buffer),
        nlh,
        hdr: std::ptr::null(),
        nfmark: 0,
        indev: 0,
        outdev: 0,
        physindev: 0,
        physoutdev: 0,
        orig_len: 0,
        skbinfo: 0,
        uid: None,
        gid: None,
        secctx: None,
        timestamp: None,
        hwaddr: std::ptr::null(),
        payload: &[],
    };

    if mnl_attr_parse(nlh, std::mem::size_of::<nfgenmsg>() as _, Some(parse_attr), &mut message as *mut Message as _) < 0 {
        return MNL_CB_ERROR;
    }

    assert!(!message.hdr.is_null());

    queue.queue.push_back(message);
    return MNL_CB_OK;
}

/// A NetFilter queue.
pub struct Queue {
    /// NetLink socket
    nl: *mut mnl_sys::mnl_socket,
    portid: libc::c_uint,
    /// In order to support out-of-order verdict and batch recv, we need to carefully manage the
    /// lifetime of buffer, so that buffer is never freed before all messages are dropped.
    /// We use Arc for this case, and keep an extra copy here, so that if all messages are handled
    /// before call to `recv`, we can re-use the buffer.
    buffer: Arc<Vec<u8>>,
    /// We can receive multiple messages from kernel in a single recv, so we keep a queue
    /// internally before everything is consumed.
    queue: VecDeque<Message>,
}

unsafe impl Send for Queue {}

impl Queue {
    /// Open a NetFilter socket and queue connection.
    pub fn open() -> std::io::Result<Queue> {
        let nl = unsafe { mnl_socket_open(NETLINK_NETFILTER) };
        if nl.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        let mut queue = Queue {
            nl,
            portid: 0,
            buffer: Arc::new(Vec::with_capacity(8192 + 0xffff)),
            queue: VecDeque::new(),
        };

        if unsafe { mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) } < 0 {
            return Err(std::io::Error::last_os_error());
        }

        queue.portid = unsafe { mnl_socket_get_portid(nl) };
        queue.set_recv_enobufs(false)?;
        Ok(queue)
    }

    /// Change whether ENOBUFS should be received by the application if the kenrel queue is full.
    /// As user-space usually cannot do any special about this, `Queue::open()` will turn this off
    /// by default.
    pub fn set_recv_enobufs(&mut self, enable: bool) -> std::io::Result<()> {
        let val = (!enable) as libc::c_int;
        if unsafe { mnl_socket_setsockopt(
                self.nl, NETLINK_NO_ENOBUFS,
                &val as *const c_int as _, std::mem::size_of::<c_int>() as _
        ) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }


    unsafe fn send_nlmsg(&self, nlh: *mut nlmsghdr) -> std::io::Result<()> {
        if mnl_socket_sendto(self.nl, nlh as _, (*nlh).nlmsg_len as _) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Bind to a specific protocol and queue number.
    /// 
    /// Currently this method will also initialise the queue with COPY_PACKET mode, and will
    /// indicate the capability of accepting offloaded packets.
    pub fn bind(&mut self, queue_num: u16) -> Result<()> {
        unsafe {
            let mut buf = [0; 8192];
            let nlh = nfq_hdr_put(&mut buf, NFQNL_MSG_CONFIG as u16, queue_num);
            let command = nfqnl_msg_config_cmd {
                command: NFQNL_CFG_CMD_BIND as u8,
                pf: 0,
                _pad: 0,
            };
            mnl_attr_put(
                nlh, NFQA_CFG_CMD as u16,
                std::mem::size_of::<nfqnl_msg_config_cmd>(),
                &command as *const nfqnl_msg_config_cmd as _
            );
            self.send_nlmsg(nlh)?;

            // Maybe we should make this configurable
            let nlh = nfq_hdr_put(&mut buf, NFQNL_MSG_CONFIG as u16, queue_num);
            let params = nfqnl_msg_config_params {
                copy_range: be32_to_cpu(0xffff),
                copy_mode: NFQNL_COPY_PACKET as u8,
            };
            mnl_attr_put(
                nlh, NFQA_CFG_PARAMS as u16,
                std::mem::size_of::<nfqnl_msg_config_params>(),
                &params as *const nfqnl_msg_config_params as _
            );
            self.send_nlmsg(nlh)
        }
    }

    /// Set whether the kernel should drop or accept a packet if the queue is full.
    pub fn set_fail_open(&mut self, queue_num: u16, enabled: bool) -> Result<()> {
        unsafe {
            let mut buf = [0; 8192];
            let nlh = nfq_hdr_put(&mut buf, NFQNL_MSG_CONFIG as u16, queue_num);
            mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS as u16, if enabled { be32_to_cpu(NFQA_CFG_F_FAIL_OPEN) } else { 0 });
            mnl_attr_put_u32(nlh, NFQA_CFG_MASK as u16, be32_to_cpu(NFQA_CFG_F_FAIL_OPEN));
            self.send_nlmsg(nlh)
        }
    }

    /// Set whether we should receive GSO-enabled and partial checksum packets.
    pub fn set_recv_gso(&mut self, queue_num: u16, enabled: bool) -> Result<()> {
        unsafe {
            let mut buf = [0; 8192];
            let nlh = nfq_hdr_put(&mut buf, NFQNL_MSG_CONFIG as u16, queue_num);
            mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS as u16, if enabled { be32_to_cpu(NFQA_CFG_F_GSO) } else { 0 });
            mnl_attr_put_u32(nlh, NFQA_CFG_MASK as u16, be32_to_cpu(NFQA_CFG_F_GSO));
            self.send_nlmsg(nlh)
        }
    }

    /// Set whether we should receive UID/GID along with packets.
    pub fn set_recv_uid_gid(&mut self, queue_num: u16, enabled: bool) -> Result<()> {
        unsafe {
            let mut buf = [0; 8192];
            let nlh = nfq_hdr_put(&mut buf, NFQNL_MSG_CONFIG as u16, queue_num);
            mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS as u16, if enabled { be32_to_cpu(NFQA_CFG_F_UID_GID) } else { 0 });
            mnl_attr_put_u32(nlh, NFQA_CFG_MASK as u16, be32_to_cpu(NFQA_CFG_F_UID_GID));
            self.send_nlmsg(nlh)
        }
    }

    /// Set whether we should receive security context strings along with packets.
    pub fn set_recv_security_context(&mut self, queue_num: u16, enabled: bool) -> Result<()> {
        unsafe {
            let mut buf = [0; 8192];
            let nlh = nfq_hdr_put(&mut buf, NFQNL_MSG_CONFIG as u16, queue_num);
            mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS as u16, if enabled { be32_to_cpu(NFQA_CFG_F_SECCTX) } else { 0 });
            mnl_attr_put_u32(nlh, NFQA_CFG_MASK as u16, be32_to_cpu(NFQA_CFG_F_SECCTX));
            self.send_nlmsg(nlh)
        }
    }

    /// Unbind from a specific protocol and queue number.
    pub fn unbind(&mut self, queue_num: u16) -> Result<()> {
        unsafe {
            let mut buf = [0; 8192];
            let nlh = nfq_hdr_put(&mut buf, NFQNL_MSG_CONFIG as u16, queue_num);
            let command = nfqnl_msg_config_cmd {
                command: NFQNL_CFG_CMD_UNBIND as u8,
                pf: 0,
                _pad: 0,
            };
            mnl_attr_put(
                nlh, NFQA_CFG_CMD as u16,
                std::mem::size_of::<nfqnl_msg_config_cmd>(),
                &command as *const nfqnl_msg_config_cmd as _
            );
            self.send_nlmsg(nlh)
        }
    }

    /// Receive a packet from the queue.
    pub fn recv(&mut self) -> Result<Message> {
        // We have processed all messages in previous recv batch, do next iteration
        while self.queue.is_empty() {
            let buf = Arc::make_mut(&mut self.buffer);
            let buf_size = buf.capacity();
            unsafe { buf.set_len(buf_size) }
            let size = unsafe { mnl_socket_recvfrom(self.nl, buf.as_mut_ptr() as _, buf_size) };
            if size == -1 {
                return Err(std::io::Error::last_os_error());
            }

            if unsafe { mnl_cb_run(buf.as_mut_ptr() as _, size as usize, 0, self.portid, Some(queue_cb), self as *mut Queue as _) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }

        let msg = self.queue.pop_front().unwrap();
        Ok(msg)
    }

    /// Verdict a message and give it a new nfmark.
    pub fn verdict_mark(&mut self, msg: Message, verdict: Verdict, mark: Option<u32>) -> Result<()> {
        unsafe {
            let nfg = mnl_nlmsg_get_payload(msg.nlh) as *mut nfgenmsg;
            let mut buf = [0; 8192];
            let nlh = nfq_hdr_put(&mut buf, NFQNL_MSG_VERDICT as u16, be16_to_cpu((*nfg).res_id));
            let vh = nfqnl_msg_verdict_hdr {
                verdict: be32_to_cpu(match verdict {
                    Verdict::Drop => 0,
                    Verdict::Accept => 1,
                    Verdict::Queue(num) => (num as u32) << 16 | 3,
                    Verdict::Repeat => 4,
                    Verdict::Stop => 5,
                }),
                id: (*msg.hdr).packet_id,
            };
            mnl_sys::mnl_attr_put(nlh, NFQA_VERDICT_HDR as u16, std::mem::size_of::<nfqnl_msg_verdict_hdr>(), &vh as *const nfqnl_msg_verdict_hdr as _);
            if let Some(mark) = mark {
                mnl_sys::mnl_attr_put_u32(nlh, NFQA_MARK as u16, be32_to_cpu(mark));
            }
            self.send_nlmsg(nlh)
        }
    }

    /// Verdict a message.
    pub fn verdict(&mut self, msg: Message, verdict: Verdict) -> Result<()> {
        self.verdict_mark(msg, verdict, None)
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        unsafe { mnl_sys::mnl_socket_close(self.nl) };
    }
}
