//! nfq - NetFilter queue for Rust
//!
//! `nfq` is Rust library for performing userspace handling of packets queued by the kernel packet
//! packet filter chains.
//!
//! # License
//! In contrast to `libnetfilter_queue` which is licensed under GPL 2.0, which will require all
//! binaries using that library to be bound by GPL, `nfq` is dual-licensed under MIT/Apache-2.0.
//! `nfq` achieves this by communicates with kernel via NETLINK sockets directly.
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
//!        let mut msg = queue.recv()?;
//!        msg.set_verdict(Verdict::Accept);
//!        queue.verdict(msg)?;
//!    }
//!    Ok(())
//! }
//! ```

mod binding;

use libc::*;
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
#[derive(Clone, Copy, PartialEq, Eq)]
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

// Messages are expected to be 32-bit aligned, so we take a [u32] as buffer instead [u8].
unsafe fn nfq_hdr_put(nlmsg: &mut Nlmsg, typ: u16, queue_num: u16) {
    let nlh = nlmsg.as_hdr();
    (*nlh).nlmsg_type = ((NFNL_SUBSYS_QUEUE as u16) << 8) | typ;
    (*nlh).nlmsg_flags = NLM_F_REQUEST as u16;
    let nfg: *mut nfgenmsg = nlmsg.extra_header();
    (*nfg).nfgen_family = AF_UNSPEC as u8;
    (*nfg).version = NFNETLINK_V0 as u8;
    (*nfg).res_id = be16_to_cpu(queue_num);
}

/// Helper functions for parsing `nlattr`. We do this ourselves instead of using libmnl to avoid
/// unnecessary function calls.
mod nla {
    #[inline]
    pub unsafe fn get_type(attr: *const libc::nlattr) -> u16 { (*attr).nla_type & (libc::NLA_TYPE_MASK as u16) }
    #[inline]
    pub unsafe fn get_payload_len(attr: *const libc::nlattr) -> usize {
        (*attr).nla_len as usize - std::mem::size_of::<libc::nlattr>()
    }
    /// Returned value is only 32-bit aligned.
    #[inline]
    pub unsafe fn get_payload<T>(attr: *const libc::nlattr) -> *const T {
        (attr as usize + std::mem::size_of::<libc::nlattr>()) as _
    }
    /// Get u32 from payload and convert it to native endian
    #[inline]
    pub unsafe fn get_u32(attr: *const libc::nlattr) -> u32 {
        super::be32_to_cpu(*get_payload(attr))
    }
}

struct AttrStream<'a> {
    buf: &'a [u32],
}

impl<'a> Iterator for AttrStream<'a> {
    type Item = *const nlattr;

    fn next(&mut self) -> Option<Self::Item> {
        let buf_left = self.buf.len() * 4;

        // Not enough space for an attribute header
        if buf_left < std::mem::size_of::<libc::nlattr>() { return None }

        let attr = self.buf.as_ptr() as *const nlattr;
        let nla_len = unsafe { (*attr).nla_len } as usize;

        // Make sure there are enough space for the entire attribute
        assert!(buf_left >= nla_len, "truncated attribute {} < {}", buf_left, nla_len);

        self.buf = &self.buf[(nla_len + 3) / 4 ..];
        Some(attr)
    }
}

struct Nlmsg<'a> {
    buf: &'a mut [u32],
    len: usize,
}

impl<'a> Nlmsg<'a> {
    unsafe fn new(buf: &'a mut [u32]) -> Self {
        // First clear all of the header
        let hdrlen = (std::mem::size_of::<nlmsghdr>() + 3) / 4;
        std::ptr::write_bytes(buf.as_mut_ptr(), 0, hdrlen);
        Self {
            buf,
            len: hdrlen,
        }
    }

    /// Allocate and zero for an extra header
    fn extra_header<T>(&mut self) -> *mut T {
        let len = (std::mem::size_of::<T>() + 3) / 4;
        let ptr = unsafe { self.buf.as_mut_ptr().offset(self.len as isize) };
        self.len += len;
        assert!(self.len <= self.buf.len());
        unsafe { std::ptr::write_bytes(ptr, 0, len) };
        ptr as _
    }

    /// Put an attribute
    fn put_raw(&mut self, typ: u16, len: usize) -> *mut u32 {
        let nla_len = len + std::mem::size_of::<nlattr>();
        let attr: *mut nlattr = unsafe { self.buf.as_mut_ptr().offset(self.len as isize) as _ };
        self.len += (nla_len + 3) / 4;
        assert!(self.len <= self.buf.len());
        unsafe {
            (*attr).nla_type = typ;
            (*attr).nla_len = nla_len as _;
            nla::get_payload::<u32>(attr) as *mut u32
        }
    }

    /// Put a slice of arbitary data. This is safe as it copies its memory representation only.
    fn put_slice<T>(&mut self, typ: u16, value: &[T]) {
        let ptr = self.put_raw(typ, value.len() * std::mem::size_of::<T>());
        unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), ptr as _, value.len()) };
    }

    /// Put an u32 attribute, convert to big endian
    fn put_u32(&mut self, typ: u16, data: u32) {
        let ptr = self.put_raw(typ, 4);
        unsafe { *ptr = be32_to_cpu(data) };
    }

    fn as_hdr(&mut self) -> *mut nlmsghdr {
        self.buf.as_mut_ptr() as _
    }

    unsafe fn adjust_len(&mut self) {
        let hdr = self.as_hdr();
        (*hdr).nlmsg_len = (self.len * 4) as _;
    }
}

enum PayloadState {
    Unmodified,
    Modified,
    Owned(Vec<u8>),
}

/// A network packet with associated metadata.
pub struct Message {
    // This is here for lifetime requirements, but we're not using it directly.
    #[allow(dead_code)]
    buffer: Arc<Vec<u32>>,
    id: u16,
    nfmark: u32,
    nfmark_dirty: bool,
    indev: u32,
    outdev: u32,
    physindev: u32,
    physoutdev: u32,
    orig_len: u32,
    skbinfo: u32,
    secctx: *const libc::c_char,
    uid: Option<u32>,
    gid: Option<u32>,
    timestamp: *const nfqnl_msg_packet_timestamp,
    hwaddr: *const nfqnl_msg_packet_hw,
    hdr: *const nfqnl_msg_packet_hdr,
    // conntrack data
    ct: Option<Conntrack>,
    // The actual lifetime is 'buffer
    payload: &'static mut [u8],
    payload_state: PayloadState,
    verdict: Verdict,
}

unsafe impl Send for Message {}

impl Message {
    /// Get the nfmark (fwmark) of the packet.
    #[inline]
    pub fn get_nfmark(&self) -> u32 { self.nfmark }

    /// Set the associated nfmark (fwmark) of the packet.
    #[inline]
    pub fn set_nfmark(&mut self, mark: u32) {
        self.nfmark = mark;
        self.nfmark_dirty = true;
    }

    /// Get the interface index of the interface the packet arrived on. If the packet is locally
    /// generated, or the input interface is no longer known (e.g. `POSTROUTING` chain), 0 is
    /// returned.
    #[inline]
    pub fn get_indev(&self) -> u32 { self.indev }

    /// Get the interface index of the bridge port the packet arrived on. If the packet is locally
    /// generated, or the input interface is no longer known (e.g. `POSTROUTING` chain), 0 is
    /// returned.
    #[inline]
    pub fn get_physindev(&self) -> u32 { self.physindev }

    /// Get the interface index of the interface the packet is to be transmitted from. If the
    /// packet is locally destinated, or the output interface is unknown (e.g. `PREROUTING` chain),
    /// 0 is returned.
    #[inline]
    pub fn get_outdev(&self) -> u32 { self.outdev }

    /// Get the interface index of the bridge port the packet is to be transmitted from. If the
    /// packet is locally destinated, or the output interface is unknown (e.g. `PREROUTING` chain),
    /// 0 is returned.
    #[inline]
    pub fn get_physoutdev(&self) -> u32 { self.physoutdev }

    /// Get the original length of the packet.
    #[inline]
    pub fn get_original_len(&self) -> usize {
        if self.orig_len == 0 { self.payload.len() } else { self.orig_len as usize }
    }

    /// Check if the packet is GSO-offloaded.
    #[inline]
    pub fn is_seg_offloaded(&self) -> bool {
        self.skbinfo & NFQA_SKB_GSO != 0
    }

    /// Check if the checksums are ready, e.g. due to offload.
    #[inline]
    pub fn is_checksum_ready(&self) -> bool {
        self.skbinfo & NFQA_SKB_CSUMNOTREADY == 0
    }

    /// Get the security context string of the local process sending the packet. If not applicable,
    /// `None` is returned.
    pub fn get_security_context(&self) -> Option<&str> {
        if self.secctx.is_null() { return None }
        unsafe { std::ffi::CStr::from_ptr(self.secctx).to_str().ok() }
    }

    /// Get the UID of the local process sending the packet. If not applicable, `None` is returned.
    #[inline]
    pub fn get_uid(&self) -> Option<u32> { self.uid }

    /// Get the GID of the local process sending the packet. If not applicable, `None` is returned.
    #[inline]
    pub fn get_gid(&self) -> Option<u32> { self.gid }

    /// Get the timestamp of the packet.
    pub fn get_timestamp(&self) -> Option<SystemTime> {
        if self.timestamp.is_null() { return None }
        unsafe {
            let duration = Duration::from_secs(be64_to_cpu((*self.timestamp).sec)) +
                Duration::from_micros(be64_to_cpu((*self.timestamp).usec));
            Some(SystemTime::UNIX_EPOCH + duration)
        }
    }

    /// Get the hardware address associated with the packet. For Ethernet packets, the hardware
    /// address returned will be the MAC address of the packet source host, if any.
    pub fn get_hw_addr(&self) -> Option<&[u8]> {
        if self.hwaddr.is_null() { return None }
        unsafe {
            let len = be16_to_cpu((*self.hwaddr).hw_addrlen) as usize;
            Some(&(*self.hwaddr).hw_addr[..len])
        }
    }

    /// Get the link layer protocol number, e.g. the EtherType field on Ethernet links.
    #[inline]
    pub fn get_hw_protocol(&self) -> u16 {
        be16_to_cpu(unsafe { (*self.hdr).hw_protocol })
    }

    /// Get the netfilter hook number that handles this packet.
    #[inline]
    pub fn get_hook(&self) -> u8 {
        unsafe { (*self.hdr).hook }
    }

    /// Get the content of the payload.
    #[inline]
    pub fn get_payload(&self) -> &[u8] {
        match self.payload_state {
            PayloadState::Unmodified |
            PayloadState::Modified => self.payload,
            PayloadState::Owned(ref vec) => &vec,
        }
    }

    /// Get the content of the payload in mutable state. If the final verdict is not
    /// `Verdict::Drop`, the change be committed to the kernel.
    ///
    /// *Note*: Once the method is called, the payload will be written back regardles whether
    /// the underlying storage is actually modified, therefore it is not optimal performance-wise.
    #[inline]
    pub fn get_payload_mut(&mut self) -> &mut [u8] {
        match self.payload_state {
            PayloadState::Unmodified => {
                self.payload_state = PayloadState::Modified;
                self.payload
            }
            PayloadState::Modified => self.payload,
            PayloadState::Owned(ref mut vec) => vec,
        }
    }

    /// Set the content of the payload. If the final verdict is not `Verdict::Drop`, the updated
    /// payload will be committed to the kernel.
    #[inline]
    pub fn set_payload(&mut self, payload: impl Into<Vec<u8>>) {
        self.payload_state = PayloadState::Owned(payload.into());
    }

    /// Get the current verdict.
    #[inline]
    pub fn get_verdict(&self) -> Verdict {
        self.verdict
    }

    /// Set the current verdict.
    #[inline]
    pub fn set_verdict(&mut self, verdict: Verdict) {
        self.verdict = verdict;
    }

    /// Get the associated conntrack information.
    #[inline]
    pub fn get_conntrack(&self) -> Option<&Conntrack> {
        self.ct.as_ref()
    }
}

/// Conntrack information associated with the message
pub struct Conntrack {
    state: u32,
    id: u32,
}

pub mod conntrack {
    #[derive(Debug)]
    pub enum State {
        Established,
        Related,
        New,
        EstablishedReply,
        RelatedReply,
        NewReply,
        #[doc(hidden)]
        Invalid,
    }
}

impl Conntrack {
    /// Get the conntrack ID.
    #[inline]
    pub fn get_id(&self) -> u32 {
        self.id
    }

    /// Get the connection state
    #[inline]
    pub fn get_state(&self) -> conntrack::State {
        use conntrack::State;
        match self.state {
            IP_CT_ESTABLISHED => State::Established,
            IP_CT_RELATED => State::Related,
            IP_CT_NEW => State::New,
            IP_CT_ESTABLISHED_REPLY => State::EstablishedReply,
            IP_CT_RELATED_REPLY => State::RelatedReply,
            IP_CT_NEW_REPLY => State::NewReply,
            _ => State::Invalid,
        }
    }
}

unsafe fn parse_ct_attr(attr: *const nlattr, ct: &mut Conntrack) {
    let typ = nla::get_type(attr) as c_uint;
    match typ {
        CTA_ID => ct.id = nla::get_u32(attr),
        _ => (),
    }
}

unsafe fn parse_attr(attr: *const nlattr, message: &mut Message) {
    let typ = nla::get_type(attr) as c_uint;
    match typ {
        NFQA_MARK => message.nfmark = nla::get_u32(attr),
        NFQA_IFINDEX_INDEV => message.indev = nla::get_u32(attr),
        NFQA_IFINDEX_OUTDEV => message.outdev = nla::get_u32(attr),
        NFQA_IFINDEX_PHYSINDEV => message.physindev = nla::get_u32(attr),
        NFQA_IFINDEX_PHYSOUTDEV => message.physoutdev = nla::get_u32(attr),
        NFQA_HWADDR => {
            assert!(nla::get_payload_len(attr) >= std::mem::size_of::<nfqnl_msg_packet_hw>());
            message.hwaddr = nla::get_payload(attr);
        }
        NFQA_CAP_LEN => message.orig_len = nla::get_u32(attr),
        NFQA_SKB_INFO => message.skbinfo = nla::get_u32(attr),
        NFQA_SECCTX => message.secctx = nla::get_payload(attr),
        NFQA_UID => message.uid = Some(nla::get_u32(attr)),
        NFQA_GID => message.gid = Some(nla::get_u32(attr)),
        NFQA_TIMESTAMP => {
            assert!(nla::get_payload_len(attr) >= std::mem::size_of::<nfqnl_msg_packet_timestamp>());
            message.timestamp = nla::get_payload(attr);
        }
        NFQA_PACKET_HDR => {
            assert!(nla::get_payload_len(attr) >= std::mem::size_of::<nfqnl_msg_packet_hdr>());
            message.hdr = nla::get_payload(attr);
        }
        NFQA_PAYLOAD => {
            let len = nla::get_payload_len(attr);
            // We actually own this message (even though the buffer is shared via a Arc, we know
            // that no other messages are overlapping, so it's safe to mutate it)
            let payload = nla::get_payload::<u8>(attr) as *mut u8;
            message.payload = std::slice::from_raw_parts_mut(payload as *const u8 as *mut u8, len as usize);
        }
        NFQA_CT => {
            // I'm too lazy to expand things out manually - as Conntrack are all integers, zero
            // init should be good enough.
            if message.ct.is_none() { message.ct = Some(std::mem::zeroed()) }
            let ct = message.ct.as_mut().unwrap();
            for attr in (AttrStream { buf: std::slice::from_raw_parts(nla::get_payload(attr), (nla::get_payload_len(attr) + 3) / 4) }) {
                parse_ct_attr(attr, ct);
            }
        }
        NFQA_CT_INFO => {
            if message.ct.is_none() { message.ct = Some(std::mem::zeroed()) }
            message.ct.as_mut().unwrap().state = nla::get_u32(attr);
        }
        _ => (),
    }
}

unsafe fn parse_msg(nlh: *const nlmsghdr, queue: &mut Queue) {
    const NLMSG_HDRLEN: usize = (std::mem::size_of::<nlmsghdr>() + 3) &! 3;
    const NFGEN_HDRLEN: usize = (std::mem::size_of::<nfgenmsg>() + 3) &! 3;
    let nfgenmsg = (nlh as usize + NLMSG_HDRLEN) as *const nfgenmsg;
    let attr_start = (nfgenmsg as usize + NFGEN_HDRLEN) as *const u32;
    let attr_len = (*nlh).nlmsg_len as usize - NLMSG_HDRLEN - NFGEN_HDRLEN;

    let mut message = Message {
        buffer: Arc::clone(&queue.buffer),
        id: (*nfgenmsg).res_id,
        hdr: std::ptr::null(),
        nfmark: 0,
        nfmark_dirty: false,
        indev: 0,
        outdev: 0,
        physindev: 0,
        physoutdev: 0,
        orig_len: 0,
        skbinfo: 0,
        uid: None,
        gid: None,
        secctx: std::ptr::null(),
        timestamp: std::ptr::null(),
        hwaddr: std::ptr::null(),
        ct: None,
        payload: &mut [],
        payload_state: PayloadState::Unmodified,
        verdict: Verdict::Accept,
    };

    for attr in (AttrStream { buf: std::slice::from_raw_parts(attr_start, (attr_len + 3) / 4) }) {
        parse_attr(attr, &mut message);
    }

    assert!(!message.hdr.is_null());

    queue.queue.push_back(message);
}

/// A NetFilter queue.
pub struct Queue {
    /// NetLink socket
    fd: libc::c_int,
    /// In order to support out-of-order verdict and batch recv, we need to carefully manage the
    /// lifetime of buffer, so that buffer is never freed before all messages are dropped.
    /// We use Arc for this case, and keep an extra copy here, so that if all messages are handled
    /// before call to `recv`, we can re-use the buffer.
    buffer: Arc<Vec<u32>>,
    /// We can receive multiple messages from kernel in a single recv, so we keep a queue
    /// internally before everything is consumed.
    queue: VecDeque<Message>,
}

unsafe impl Send for Queue {}

impl Queue {
    /// Open a NetFilter socket and queue connection.
    pub fn open() -> std::io::Result<Queue> {
        let fd = unsafe { socket(PF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) };
        if fd == -1 {
            return Err(std::io::Error::last_os_error());
        }

        let mut queue = Queue {
            fd,
            buffer: Arc::new(Vec::with_capacity((8192 + 0x10000) / 4)),
            queue: VecDeque::new(),
        };

        let mut addr: sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = AF_NETLINK as _;
        if unsafe { bind(fd, &addr as *const sockaddr_nl as _, std::mem::size_of_val(&addr) as _) } < 0 {
            return Err(std::io::Error::last_os_error());
        }

        queue.set_recv_enobufs(false)?;
        Ok(queue)
    }

    /// Change whether ENOBUFS should be received by the application if the kenrel queue is full.
    /// As user-space usually cannot do any special about this, `Queue::open()` will turn this off
    /// by default.
    pub fn set_recv_enobufs(&mut self, enable: bool) -> std::io::Result<()> {
        let val = (!enable) as c_int;
        if unsafe { setsockopt(
                self.fd, SOL_NETLINK, NETLINK_NO_ENOBUFS,
                &val as *const c_int as _, std::mem::size_of_val(&val) as _
        ) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    unsafe fn send_nlmsg(&self, mut nlh: Nlmsg) -> std::io::Result<()> {
        nlh.adjust_len();
        let nlh = nlh.as_hdr();
        let mut addr: sockaddr_nl = std::mem::zeroed();
        addr.nl_family = AF_NETLINK as _;
        if sendto(
            self.fd,
            nlh as _, (*nlh).nlmsg_len as _, 0,
            &addr as *const sockaddr_nl as _, std::mem::size_of_val(&addr) as _
        ) < 0 {
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
            let mut buf = [0u32; 8192 / 4];
            let mut nlmsg = Nlmsg::new(&mut buf);
            nfq_hdr_put(&mut nlmsg, NFQNL_MSG_CONFIG as u16, queue_num);
            let command = nfqnl_msg_config_cmd {
                command: NFQNL_CFG_CMD_BIND as u8,
                pf: 0,
                _pad: 0,
            };
            nlmsg.put_slice(NFQA_CFG_CMD as u16, std::slice::from_ref(&command));
            self.send_nlmsg(nlmsg)?;

            // Maybe we should make this configurable
            let mut nlmsg = Nlmsg::new(&mut buf);
            nfq_hdr_put(&mut nlmsg, NFQNL_MSG_CONFIG as u16, queue_num);
            let params = nfqnl_msg_config_params {
                copy_range: be32_to_cpu(0xffff),
                copy_mode: NFQNL_COPY_PACKET as u8,
            };
            nlmsg.put_slice(NFQA_CFG_PARAMS as u16, std::slice::from_ref(&params));
            self.send_nlmsg(nlmsg)
        }
    }

    /// Set whether the kernel should drop or accept a packet if the queue is full.
    pub fn set_fail_open(&mut self, queue_num: u16, enabled: bool) -> Result<()> {
        unsafe {
            let mut buf = [0u32; 8192 / 4];
            let mut nlmsg = Nlmsg::new(&mut buf);
            nfq_hdr_put(&mut nlmsg, NFQNL_MSG_CONFIG as u16, queue_num);
            nlmsg.put_u32(NFQA_CFG_FLAGS as u16, if enabled { NFQA_CFG_F_FAIL_OPEN } else { 0 });
            nlmsg.put_u32(NFQA_CFG_MASK as u16, NFQA_CFG_F_FAIL_OPEN);
            self.send_nlmsg(nlmsg)
        }
    }

    /// Set whether we should receive GSO-enabled and partial checksum packets.
    pub fn set_recv_gso(&mut self, queue_num: u16, enabled: bool) -> Result<()> {
        unsafe {
            let mut buf = [0u32; 8192 / 4];
            let mut nlmsg = Nlmsg::new(&mut buf);
            nfq_hdr_put(&mut nlmsg, NFQNL_MSG_CONFIG as u16, queue_num);
            nlmsg.put_u32(NFQA_CFG_FLAGS as u16, if enabled { NFQA_CFG_F_GSO } else { 0 });
            nlmsg.put_u32(NFQA_CFG_MASK as u16, NFQA_CFG_F_GSO);
            self.send_nlmsg(nlmsg)
        }
    }

    /// Set whether we should receive UID/GID along with packets.
    pub fn set_recv_uid_gid(&mut self, queue_num: u16, enabled: bool) -> Result<()> {
        unsafe {
            let mut buf = [0u32; 8192 / 4];
            let mut nlmsg = Nlmsg::new(&mut buf);
            nfq_hdr_put(&mut nlmsg, NFQNL_MSG_CONFIG as u16, queue_num);
            nlmsg.put_u32(NFQA_CFG_FLAGS as u16, if enabled { NFQA_CFG_F_UID_GID } else { 0 });
            nlmsg.put_u32(NFQA_CFG_MASK as u16, NFQA_CFG_F_UID_GID);
            self.send_nlmsg(nlmsg)
        }
    }

    /// Set whether we should receive security context strings along with packets.
    pub fn set_recv_security_context(&mut self, queue_num: u16, enabled: bool) -> Result<()> {
        unsafe {
            let mut buf = [0u32; 8192 / 4];
            let mut nlmsg = Nlmsg::new(&mut buf);
            nfq_hdr_put(&mut nlmsg, NFQNL_MSG_CONFIG as u16, queue_num);
            nlmsg.put_u32(NFQA_CFG_FLAGS as u16, if enabled { NFQA_CFG_F_SECCTX } else { 0 });
            nlmsg.put_u32(NFQA_CFG_MASK as u16, NFQA_CFG_F_SECCTX);
            self.send_nlmsg(nlmsg)
        }
    }

    /// Set whether we should receive connteack information along with packets.
    pub fn set_recv_conntrack(&mut self, queue_num: u16, enabled: bool) -> Result<()> {
        unsafe {
            let mut buf = [0u32; 8192 / 4];
            let mut nlmsg = Nlmsg::new(&mut buf);
            nfq_hdr_put(&mut nlmsg, NFQNL_MSG_CONFIG as u16, queue_num);
            nlmsg.put_u32(NFQA_CFG_FLAGS as u16, if enabled { NFQA_CFG_F_CONNTRACK } else { 0 });
            nlmsg.put_u32(NFQA_CFG_MASK as u16, NFQA_CFG_F_CONNTRACK);
            self.send_nlmsg(nlmsg)
        }
    }

    /// Unbind from a specific protocol and queue number.
    pub fn unbind(&mut self, queue_num: u16) -> Result<()> {
        unsafe {
            let mut buf = [0u32; 8192 / 4];
            let mut nlmsg = Nlmsg::new(&mut buf);
            nfq_hdr_put(&mut nlmsg, NFQNL_MSG_CONFIG as u16, queue_num);
            let command = nfqnl_msg_config_cmd {
                command: NFQNL_CFG_CMD_UNBIND as u8,
                pf: 0,
                _pad: 0,
            };
            nlmsg.put_slice(NFQA_CFG_CMD as u16, std::slice::from_ref(&command));
            self.send_nlmsg(nlmsg)
        }
    }

    /// Receive a packet from the queue.
    pub fn recv(&mut self) -> Result<Message> {
        // We have processed all messages in previous recv batch, do next iteration
        while self.queue.is_empty() {
            let buf = Arc::make_mut(&mut self.buffer);
            let buf_size = buf.capacity();
            unsafe { buf.set_len(buf_size) }

            let size = unsafe { recv(self.fd, buf.as_mut_ptr() as _, buf_size, MSG_TRUNC) };
            if size < 0 {
                return Err(std::io::Error::last_os_error());
            }

            // As we pass in MSG_TRUNC, if we receive a larger size it means the message is trucated
            let mut size = size as usize;
            if size > buf_size {
                return Err(std::io::Error::from_raw_os_error(ENOSPC));
            }

            const NLMSG_HDRLEN: usize = (std::mem::size_of::<nlmsghdr>() + 3) &! 3;
            let mut nlh = buf.as_ptr() as *const nlmsghdr;
            loop {
                if size < NLMSG_HDRLEN { break }
                let nlmsg_len = unsafe { (*nlh).nlmsg_len } as usize;
                if size < nlmsg_len { break }

                if unsafe { (*nlh).nlmsg_flags } & NLM_F_DUMP_INTR as u16 != 0 {
                    return Err(std::io::Error::from_raw_os_error(EINTR));
                }

                match unsafe { (*nlh).nlmsg_type } as c_int {
                    NLMSG_ERROR => {
                        assert!(nlmsg_len >= NLMSG_HDRLEN + std::mem::size_of::<nlmsgerr>());
                        let err = (nlh as usize + NLMSG_HDRLEN) as *const nlmsgerr;
                        let errno = unsafe { (*err).error }.abs();
                        if errno == 0 { break }
                        return Err(std::io::Error::from_raw_os_error(errno));
                    }
                    NLMSG_DONE => break,
                    v if v < NLMSG_MIN_TYPE => (),
                    _ => unsafe { parse_msg(nlh, self) },
                }

                let aligned_len = (nlmsg_len + 3) &! 3;
                nlh = (nlh as usize + aligned_len) as *const nlmsghdr;
                size = match size.checked_sub(aligned_len) {
                    Some(v) => v,
                    None => break,
                }
            }
        }

        let msg = self.queue.pop_front().unwrap();
        Ok(msg)
    }

    /// Verdict a message.
    pub fn verdict(&mut self, msg: Message) -> Result<()> {
        unsafe {
            // Performance is critical here: use uninitialized to avoid zeroing the memory.
            let mut buf: [u32; (8192 + 0x10000) / 4] = std::mem::uninitialized();
            let mut nlmsg = Nlmsg::new(&mut buf);
            nfq_hdr_put(&mut nlmsg, NFQNL_MSG_VERDICT as u16, be16_to_cpu(msg.id));
            let vh = nfqnl_msg_verdict_hdr {
                verdict: be32_to_cpu(match msg.verdict {
                    Verdict::Drop => 0,
                    Verdict::Accept => 1,
                    Verdict::Queue(num) => (num as u32) << 16 | 3,
                    Verdict::Repeat => 4,
                    Verdict::Stop => 5,
                }),
                id: (*msg.hdr).packet_id,
            };
            nlmsg.put_slice(NFQA_VERDICT_HDR as u16, std::slice::from_ref(&vh));
            if msg.nfmark_dirty {
                nlmsg.put_u32(NFQA_MARK as u16, msg.nfmark);
            }
            if let PayloadState::Unmodified = msg.payload_state {} else {
                if msg.verdict != Verdict::Drop {
                    let payload = msg.get_payload();
                    nlmsg.put_slice(NFQA_PAYLOAD as u16, payload);
                }
            }
            self.send_nlmsg(nlmsg)
        }
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}
