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
//! ```no_run
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

mod nlmsg;

use bytemuck::Zeroable;
use bytes::{Buf, Bytes, BytesMut};
use libc::{
    bind, c_int, recv, sendto, setsockopt, sockaddr_nl, socket, sysconf, AF_NETLINK, AF_UNSPEC,
    EINTR, ENOSPC, MSG_DONTWAIT, MSG_TRUNC, NETLINK_NETFILTER, NETLINK_NO_ENOBUFS, NFNETLINK_V0,
    NFNL_SUBSYS_QUEUE, NFQA_CAP_LEN, NFQA_CFG_CMD, NFQA_CFG_FLAGS, NFQA_CFG_F_CONNTRACK,
    NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_GSO, NFQA_CFG_F_SECCTX, NFQA_CFG_F_UID_GID, NFQA_CFG_MASK,
    NFQA_CFG_PARAMS, NFQA_CFG_QUEUE_MAXLEN, NFQA_CT, NFQA_CT_INFO, NFQA_GID, NFQA_HWADDR,
    NFQA_IFINDEX_INDEV, NFQA_IFINDEX_OUTDEV, NFQA_IFINDEX_PHYSINDEV, NFQA_IFINDEX_PHYSOUTDEV,
    NFQA_MARK, NFQA_PACKET_HDR, NFQA_PAYLOAD, NFQA_SECCTX, NFQA_SKB_CSUMNOTREADY, NFQA_SKB_GSO,
    NFQA_SKB_INFO, NFQA_TIMESTAMP, NFQA_UID, NFQA_VERDICT_HDR, NFQNL_CFG_CMD_BIND,
    NFQNL_CFG_CMD_UNBIND, NFQNL_COPY_META, NFQNL_COPY_PACKET, NFQNL_MSG_CONFIG, NFQNL_MSG_VERDICT,
    NLMSG_DONE, NLMSG_ERROR, NLMSG_MIN_TYPE, NLM_F_ACK, NLM_F_DUMP_INTR, NLM_F_REQUEST, PF_NETLINK,
    SOCK_RAW, SOL_NETLINK, _SC_PAGE_SIZE,
};
use std::collections::VecDeque;
use std::io::Result;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, SystemTime};

use nlmsg::{
    NfGenMsg, NfqNlMsgPacketHdr, NfqNlMsgPacketHw, NfqNlMsgPacketTimestamp, NlMsgErr, NlMsgHdr,
    NlmsgMut, CTA_ID, IP_CT_ESTABLISHED, IP_CT_ESTABLISHED_REPLY, IP_CT_NEW, IP_CT_NEW_REPLY,
    IP_CT_RELATED, IP_CT_RELATED_REPLY,
};

/// Decision made on a specific packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

fn nfq_hdr_put(nlmsg: &mut NlmsgMut, typ: u16, queue_num: u16, ack: bool) {
    let nlh = nlmsg.as_header_mut();
    nlh.ty = ((NFNL_SUBSYS_QUEUE as u16) << 8) | typ;
    nlh.flags = (NLM_F_REQUEST | if ack { NLM_F_ACK } else { 0 }) as u16;
    let nfg: &mut NfGenMsg = nlmsg.extra_header();
    nfg.family = AF_UNSPEC as u8;
    nfg.version = NFNETLINK_V0 as u8;
    nfg.res_id = queue_num.to_be();
}

#[derive(Debug)]
enum PayloadState {
    Unmodified,
    Modified,
    Owned(Vec<u8>),
}

/// A network packet with associated metadata.
pub struct Message {
    id: u16,
    nfmark: u32,
    nfmark_dirty: bool,
    indev: u32,
    outdev: u32,
    physindev: u32,
    physoutdev: u32,
    orig_len: u32,
    skbinfo: i32,
    secctx: Option<Bytes>,
    uid: Option<u32>,
    gid: Option<u32>,
    timestamp: Option<Bytes>,
    hwaddr: Option<Bytes>, //NfqNlMsgPacketHw,
    hdr: NfqNlMsgPacketHdr,
    // conntrack data
    ct: Option<Conntrack>,
    payload: BytesMut,
    payload_state: PayloadState,
    verdict: Verdict,
}

impl core::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Message")
            .field("queue_num", &self.get_queue_num())
            .field("nfmark", &self.get_nfmark())
            .field("indev", &self.get_indev())
            .field("outdev", &self.get_outdev())
            .field("physindev", &self.get_physindev())
            .field("physoutdev", &self.get_physoutdev())
            .field("original_len", &self.get_original_len())
            .field("skbinfo", &self.skbinfo)
            .field("secctx", &self.get_security_context())
            .field("uid", &self.get_uid())
            .field("gid", &self.get_gid())
            .field("timestamp", &self.get_timestamp())
            .field("hwaddr", &self.get_hw_addr())
            .field("packet_id", &self.get_packet_id())
            .field("hw_protocol", &self.get_hw_protocol())
            .field("hook", &self.get_hook())
            .field("ct", &self.ct)
            .field("payload", &self.get_payload())
            .field("verdict", &self.get_verdict())
            .finish()
    }
}

impl Message {
    /// Get the queue number.
    #[inline]
    pub fn get_queue_num(&self) -> u16 {
        self.id
    }

    /// Get the nfmark (fwmark) of the packet.
    #[inline]
    pub fn get_nfmark(&self) -> u32 {
        self.nfmark
    }

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
    pub fn get_indev(&self) -> u32 {
        self.indev
    }

    /// Get the interface index of the bridge port the packet arrived on. If the packet is locally
    /// generated, or the input interface is no longer known (e.g. `POSTROUTING` chain), 0 is
    /// returned.
    #[inline]
    pub fn get_physindev(&self) -> u32 {
        self.physindev
    }

    /// Get the interface index of the interface the packet is to be transmitted from. If the
    /// packet is locally destinated, or the output interface is unknown (e.g. `PREROUTING` chain),
    /// 0 is returned.
    #[inline]
    pub fn get_outdev(&self) -> u32 {
        self.outdev
    }

    /// Get the interface index of the bridge port the packet is to be transmitted from. If the
    /// packet is locally destinated, or the output interface is unknown (e.g. `PREROUTING` chain),
    /// 0 is returned.
    #[inline]
    pub fn get_physoutdev(&self) -> u32 {
        self.physoutdev
    }

    /// Get the original length of the packet.
    #[inline]
    pub fn get_original_len(&self) -> usize {
        if self.orig_len == 0 {
            self.payload.len()
        } else {
            self.orig_len as usize
        }
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
        match &self.secctx {
            None => None,
            Some(secctx) => std::ffi::CStr::from_bytes_until_nul(&secctx)
                .ok()?
                .to_str()
                .ok(),
        }
    }

    /// Get the UID of the local process sending the packet. If not applicable, `None` is returned.
    #[inline]
    pub fn get_uid(&self) -> Option<u32> {
        self.uid
    }

    /// Get the GID of the local process sending the packet. If not applicable, `None` is returned.
    #[inline]
    pub fn get_gid(&self) -> Option<u32> {
        self.gid
    }

    /// Get the timestamp of the packet.
    pub fn get_timestamp(&self) -> Option<SystemTime> {
        match &self.timestamp {
            None => None,
            Some(bytes) => {
                let timestamp: NfqNlMsgPacketTimestamp = bytemuck::pod_read_unaligned(&bytes);
                let duration = Duration::from_secs(u64::from_be(timestamp.sec))
                    + Duration::from_micros(u64::from_be(timestamp.usec));
                Some(SystemTime::UNIX_EPOCH + duration)
            }
        }
    }

    /// Get the hardware address associated with the packet. For Ethernet packets, the hardware
    /// address returned will be the MAC address of the packet source host, if any.
    pub fn get_hw_addr(&self) -> Option<&[u8]> {
        match &self.hwaddr {
            None => None,
            Some(bytes) => {
                let hwaddr: &NfqNlMsgPacketHw =
                    bytemuck::from_bytes(&bytes[..std::mem::size_of::<NfqNlMsgPacketHw>()]);
                Some(&hwaddr.hw_addr[..u16::from_be(hwaddr.hw_addrlen) as usize])
            }
        }
    }

    /// Get the packet ID that netfilter uses to track the packet.
    #[inline]
    pub fn get_packet_id(&self) -> u32 {
        u32::from_be(self.hdr.packet_id)
    }

    /// Get the link layer protocol number, e.g. the EtherType field on Ethernet links.
    #[inline]
    pub fn get_hw_protocol(&self) -> u16 {
        u16::from_be(self.hdr.hw_protocol)
    }

    /// Get the netfilter hook number that handles this packet.
    #[inline]
    pub fn get_hook(&self) -> u8 {
        self.hdr.hook
    }

    /// Get the content of the payload.
    #[inline]
    pub fn get_payload(&self) -> &[u8] {
        match self.payload_state {
            PayloadState::Unmodified | PayloadState::Modified => &self.payload,
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
                &mut self.payload
            }
            PayloadState::Modified => &mut self.payload,
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
    #[cfg_attr(not(feature = "ct"), doc(hidden))]
    pub fn get_conntrack(&self) -> Option<&Conntrack> {
        self.ct.as_ref()
    }
}

/// Conntrack information associated with the message
#[cfg_attr(not(feature = "ct"), doc(hidden))]
#[derive(Debug)]
pub struct Conntrack {
    state: u32,
    id: u32,
}

#[cfg_attr(not(feature = "ct"), doc(hidden))]
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

fn parse_ct_attr(ty: u16, mut buf: BytesMut, ct: &mut Conntrack) {
    let typ = (ty & libc::NLA_TYPE_MASK as u16) as u32;
    // There are many more types, they just aren't handled yet.
    #[allow(clippy::single_match)]
    match typ {
        CTA_ID => ct.id = buf.get_u32(),
        _ => (),
    }
}

fn parse_attr(ty: u16, mut buf: BytesMut, message: &mut Message) {
    let typ = (ty & libc::NLA_TYPE_MASK as u16) as c_int;
    match typ {
        NFQA_MARK => message.nfmark = buf.get_u32(),
        NFQA_IFINDEX_INDEV => message.indev = buf.get_u32(),
        NFQA_IFINDEX_OUTDEV => message.outdev = buf.get_u32(),
        NFQA_IFINDEX_PHYSINDEV => message.physindev = buf.get_u32(),
        NFQA_IFINDEX_PHYSOUTDEV => message.physoutdev = buf.get_u32(),
        NFQA_HWADDR => message.hwaddr = Some(buf.freeze()),
        NFQA_CAP_LEN => message.orig_len = buf.get_u32(),
        NFQA_SKB_INFO => message.skbinfo = buf.get_u32() as i32,
        NFQA_SECCTX => message.secctx = Some(buf.freeze()),
        NFQA_UID => message.uid = Some(buf.get_u32()),
        NFQA_GID => message.gid = Some(buf.get_u32()),
        NFQA_TIMESTAMP => message.timestamp = Some(buf.freeze()),
        NFQA_PACKET_HDR => {
            message.hdr = *bytemuck::from_bytes(&buf[..core::mem::size_of::<NfqNlMsgPacketHdr>()])
        }
        NFQA_PAYLOAD => message.payload = buf,
        NFQA_CT => {
            // I'm too lazy to expand things out manually - as Conntrack are all integers, zero
            // init should be good enough.
            if message.ct.is_none() {
                message.ct = Some(unsafe { std::mem::zeroed() })
            }
            let ct = message.ct.as_mut().unwrap();
            for (ty, buf) in nlmsg::AttrStream::new(buf) {
                parse_ct_attr(ty, buf, ct);
            }
        }
        NFQA_CT_INFO => {
            if message.ct.is_none() {
                message.ct = Some(unsafe { std::mem::zeroed() })
            }
            message.ct.as_mut().unwrap().state = buf.get_u32();
        }
        _ => (),
    }
}

fn parse_msg(mut bytes: BytesMut, queue: &mut Queue) {
    bytes.advance(core::mem::size_of::<NlMsgHdr>());

    let nfgenmsg: NfGenMsg = *bytemuck::from_bytes(&bytes[..core::mem::size_of::<NfGenMsg>()]);
    bytes.advance(core::mem::size_of::<NfGenMsg>());

    let mut message = Message {
        id: u16::from_be(nfgenmsg.res_id),
        hdr: Zeroable::zeroed(),
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
        secctx: None,
        timestamp: None,
        hwaddr: None,
        ct: None,
        payload: BytesMut::new(),
        payload_state: PayloadState::Unmodified,
        verdict: Verdict::Accept,
    };

    for (ty, buf) in nlmsg::AttrStream::new(bytes) {
        parse_attr(ty, buf, &mut message);
    }

    queue.queue.push_back(message);
}

/// A NetFilter queue.
pub struct Queue {
    /// NetLink socket
    fd: OwnedFd,

    /// Flag to send for recv operation. Decides whether or not the operation blocks until there is
    /// message from the kernel.
    recv_flag: libc::c_int,
    bufsize: usize,

    /// We can receive multiple messages from kernel in a single recv, so we keep a queue
    /// internally before everything is consumed.
    queue: VecDeque<Message>,

    /// Message buffer reused across verdict calls
    verdict_buffer: BytesMut,
}

#[inline]
fn metadata_size() -> usize {
    // This value corresponds to kernel's NLMSG_GOODSIZE or libmnl's MNL_SOCKET_BUFFER_SIZE
    core::cmp::min(unsafe { sysconf(_SC_PAGE_SIZE) as _ }, 8192)
}

impl Queue {
    /// Open a NetFilter socket and queue connection.
    pub fn open() -> std::io::Result<Queue> {
        let fd = unsafe { socket(PF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) };
        if fd == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        let metadata_size = metadata_size();
        let mut queue = Queue {
            fd,
            recv_flag: 0,
            bufsize: metadata_size,
            queue: VecDeque::new(),
            verdict_buffer: BytesMut::with_capacity(metadata_size + 65536),
        };

        let mut addr: sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = AF_NETLINK as _;
        if unsafe {
            bind(
                queue.fd.as_raw_fd(),
                &addr as *const sockaddr_nl as _,
                std::mem::size_of_val(&addr) as _,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }

        queue.set_recv_enobufs(false)?;
        Ok(queue)
    }

    /// Change whether ENOBUFS should be received by the application if the kernel queue is full.
    /// As user-space usually cannot do any special about this, [`open`](#method.open) will turn
    /// this off by default.
    pub fn set_recv_enobufs(&mut self, enable: bool) -> std::io::Result<()> {
        let val = (!enable) as c_int;
        if unsafe {
            setsockopt(
                self.fd.as_raw_fd(),
                SOL_NETLINK,
                NETLINK_NO_ENOBUFS,
                &val as *const c_int as _,
                std::mem::size_of_val(&val) as _,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn send_nlmsg(&self, nlmsg: &[u8]) -> std::io::Result<()> {
        unsafe {
            let mut addr: sockaddr_nl = std::mem::zeroed();
            addr.nl_family = AF_NETLINK as _;
            if sendto(
                self.fd.as_raw_fd(),
                nlmsg.as_ptr() as _,
                nlmsg.len() as _,
                0,
                &addr as *const sockaddr_nl as _,
                std::mem::size_of_val(&addr) as _,
            ) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Bind to a specific queue number.
    ///
    /// This method will set the copy range to 65535 by default. It can be changed by using
    /// [`set_copy_range`](#method.set_copy_range).
    pub fn bind(&mut self, queue_num: u16) -> Result<()> {
        let mut nlmsg = nlmsg::NlmsgMut::with_capacity(metadata_size());
        nfq_hdr_put(&mut nlmsg, NFQNL_MSG_CONFIG as u16, queue_num, true);
        nlmsg.put(
            NFQA_CFG_CMD as u16,
            &nlmsg::NfqNlMsgConfigCmd {
                command: NFQNL_CFG_CMD_BIND as u8,
                padding: 0,
                pf: 0,
            },
        );

        self.send_nlmsg(&nlmsg.finish())?;
        self.recv_error()?;
        self.set_copy_range(queue_num, 65535)
    }

    /// Set whether the kernel should drop or accept a packet if the queue is full.
    pub fn set_fail_open(&mut self, queue_num: u16, enabled: bool) -> Result<()> {
        let mut nlmsg = nlmsg::NlmsgMut::with_capacity(metadata_size());
        nfq_hdr_put(&mut nlmsg, NFQNL_MSG_CONFIG as u16, queue_num, true);
        nlmsg.put_be32(
            NFQA_CFG_FLAGS as u16,
            if enabled {
                NFQA_CFG_F_FAIL_OPEN as u32
            } else {
                0
            },
        );
        nlmsg.put_be32(NFQA_CFG_MASK as u16, NFQA_CFG_F_FAIL_OPEN as u32);
        self.send_nlmsg(&nlmsg.finish())?;
        self.recv_error()
    }

    /// Set whether we should receive GSO-enabled and partial checksum packets.
    pub fn set_recv_gso(&mut self, queue_num: u16, enabled: bool) -> Result<()> {
        let mut nlmsg = nlmsg::NlmsgMut::with_capacity(metadata_size());
        nfq_hdr_put(&mut nlmsg, NFQNL_MSG_CONFIG as u16, queue_num, true);
        nlmsg.put_be32(
            NFQA_CFG_FLAGS as u16,
            if enabled { NFQA_CFG_F_GSO as u32 } else { 0 },
        );
        nlmsg.put_be32(NFQA_CFG_MASK as u16, NFQA_CFG_F_GSO as u32);
        self.send_nlmsg(&nlmsg.finish())?;
        self.recv_error()
    }

    /// Set whether we should receive UID/GID along with packets.
    pub fn set_recv_uid_gid(&mut self, queue_num: u16, enabled: bool) -> Result<()> {
        let mut nlmsg = nlmsg::NlmsgMut::with_capacity(metadata_size());
        nfq_hdr_put(&mut nlmsg, NFQNL_MSG_CONFIG as u16, queue_num, true);
        nlmsg.put_be32(
            NFQA_CFG_FLAGS as u16,
            if enabled {
                NFQA_CFG_F_UID_GID as u32
            } else {
                0
            },
        );
        nlmsg.put_be32(NFQA_CFG_MASK as u16, NFQA_CFG_F_UID_GID as u32);
        self.send_nlmsg(&nlmsg.finish())?;
        self.recv_error()
    }

    /// Set whether we should receive security context strings along with packets.
    pub fn set_recv_security_context(&mut self, queue_num: u16, enabled: bool) -> Result<()> {
        let mut nlmsg = nlmsg::NlmsgMut::with_capacity(metadata_size());
        nfq_hdr_put(&mut nlmsg, NFQNL_MSG_CONFIG as u16, queue_num, true);
        nlmsg.put_be32(
            NFQA_CFG_FLAGS as u16,
            if enabled { NFQA_CFG_F_SECCTX as u32 } else { 0 },
        );
        nlmsg.put_be32(NFQA_CFG_MASK as u16, NFQA_CFG_F_SECCTX as u32);
        self.send_nlmsg(&nlmsg.finish())?;
        self.recv_error()
    }

    /// Set whether we should receive connteack information along with packets.
    #[cfg_attr(not(feature = "ct"), doc(hidden))]
    pub fn set_recv_conntrack(&mut self, queue_num: u16, enabled: bool) -> Result<()> {
        let mut nlmsg = nlmsg::NlmsgMut::with_capacity(metadata_size());
        nfq_hdr_put(&mut nlmsg, NFQNL_MSG_CONFIG as u16, queue_num, true);
        nlmsg.put_be32(
            NFQA_CFG_FLAGS as u16,
            if enabled {
                NFQA_CFG_F_CONNTRACK as u32
            } else {
                0
            },
        );
        nlmsg.put_be32(NFQA_CFG_MASK as u16, NFQA_CFG_F_CONNTRACK as u32);
        self.send_nlmsg(&nlmsg.finish())?;
        self.recv_error()
    }

    /// Set copy range. Packet larger than the specified range will be truncated. If the range
    /// given is 0, only metadata will be copied.
    ///
    /// To get the original length of truncated packet, use
    /// [`Message::get_original_len`](struct.Message.html#method.get_original_len).
    pub fn set_copy_range(&mut self, queue_num: u16, range: u16) -> Result<()> {
        let mut nlmsg = nlmsg::NlmsgMut::with_capacity(metadata_size());
        nfq_hdr_put(&mut nlmsg, NFQNL_MSG_CONFIG as u16, queue_num, true);
        nlmsg.put(
            NFQA_CFG_PARAMS as u16,
            &nlmsg::NfqNlMsgConfigParams {
                copy_range: (range as u32).to_be(),
                copy_mode: if range == 0 {
                    NFQNL_COPY_META
                } else {
                    NFQNL_COPY_PACKET
                } as u8,
            },
        );
        self.send_nlmsg(&nlmsg.finish())?;
        self.recv_error()?;

        self.bufsize = metadata_size() + range as usize;
        Ok(())
    }

    /// Set the maximum kernel queue length. If the application cannot [`recv`](#method.recv) fast
    /// enough, newly queued packet will be dropped (or accepted if fail open is enabled).
    pub fn set_queue_max_len(&mut self, queue_num: u16, len: u32) -> Result<()> {
        let mut nlmsg = nlmsg::NlmsgMut::with_capacity(metadata_size());
        nfq_hdr_put(&mut nlmsg, NFQNL_MSG_CONFIG as u16, queue_num, true);
        nlmsg.put_be32(NFQA_CFG_QUEUE_MAXLEN as u16, len);
        self.send_nlmsg(&nlmsg.finish())?;
        self.recv_error()
    }

    /// Set whether the recv function blocks or not
    pub fn set_nonblocking(&mut self, nonblocking: bool) {
        self.recv_flag = if nonblocking { MSG_DONTWAIT } else { 0 };
    }

    /// Unbind from a specific queue number.
    pub fn unbind(&mut self, queue_num: u16) -> Result<()> {
        let mut nlmsg = nlmsg::NlmsgMut::with_capacity(metadata_size());
        nfq_hdr_put(&mut nlmsg, NFQNL_MSG_CONFIG as u16, queue_num, true);
        nlmsg.put(
            NFQA_CFG_CMD as u16,
            &nlmsg::NfqNlMsgConfigCmd {
                command: NFQNL_CFG_CMD_UNBIND as u8,
                padding: 0,
                pf: 0,
            },
        );
        self.send_nlmsg(&nlmsg.finish())?;
        self.recv_error()
    }

    // Receive an nlmsg, using callback to process them. If Ok(true) is returned it means we got an
    // ACK.
    fn recv_nlmsg(&mut self, mut callback: impl FnMut(&mut Self, BytesMut)) -> Result<bool> {
        let mut buf = BytesMut::with_capacity(self.bufsize + 3);
        let align_offset = (buf.as_ptr() as usize).wrapping_neg() % 4;
        if align_offset != 0 {
            buf = buf.split_off(align_offset);
        }

        let size = unsafe {
            recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as _,
                buf.capacity(),
                self.recv_flag | MSG_TRUNC,
            )
        };
        if size < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // As we pass in MSG_TRUNC, if we receive a larger size it means the message is trucated
        let size = size as usize;
        if size > buf.capacity() {
            return Err(std::io::Error::from_raw_os_error(ENOSPC));
        }

        unsafe { buf.set_len(size) };

        while buf.len() > core::mem::size_of::<NlMsgHdr>() {
            let nlh: NlMsgHdr = *bytemuck::from_bytes(&buf[..core::mem::size_of::<NlMsgHdr>()]);

            // Sanity check
            let len = nlh.len as usize;
            if size < len {
                break;
            }

            let aligned_len = len.next_multiple_of(4);
            let mut msg_buf = buf.split_to(core::cmp::min(aligned_len, buf.len()));
            msg_buf.truncate(len);

            if nlh.flags & NLM_F_DUMP_INTR as u16 != 0 {
                return Err(std::io::Error::from_raw_os_error(EINTR));
            }

            let nlmsg_type = nlh.ty as c_int;
            match nlmsg_type {
                NLMSG_ERROR => {
                    let err: &NlMsgErr = bytemuck::from_bytes(
                        &msg_buf[core::mem::size_of::<NlMsgHdr>()..]
                            [..core::mem::size_of::<NlMsgErr>()],
                    );
                    let errno = err.error.abs();
                    if errno == 0 {
                        return Ok(true);
                    }
                    return Err(std::io::Error::from_raw_os_error(errno));
                }
                NLMSG_DONE => return Ok(true),
                v if v < NLMSG_MIN_TYPE => (),
                _ => callback(self, msg_buf),
            }
        }

        Ok(false)
    }

    // Receive the next error message. Returns Ok only if errno is 0 (which is a response to a
    // message with F_ACK set).
    fn recv_error(&mut self) -> Result<()> {
        while !self.recv_nlmsg(|_, _| ())? {}
        Ok(())
    }

    /// Receive a packet from the queue.
    pub fn recv(&mut self) -> Result<Message> {
        // We have processed all messages in previous recv batch, do next iteration
        while self.queue.is_empty() {
            self.recv_nlmsg(|this, buf| {
                parse_msg(buf, this);
            })?;
        }

        let msg = self.queue.pop_front().unwrap();
        Ok(msg)
    }

    /// Verdict a message.
    pub fn verdict(&mut self, msg: Message) -> Result<()> {
        self.try_verdict(&msg)
    }

    /// Verdict a message (without consuming it).
    pub fn try_verdict(&mut self, msg: &Message) -> Result<()> {
        let buffer = core::mem::take(&mut self.verdict_buffer);
        let mut nlmsg = NlmsgMut::new(buffer);
        nfq_hdr_put(&mut nlmsg, NFQNL_MSG_VERDICT as u16, msg.id, false);
        let vh = nlmsg::NfqNlMsgVerdictHdr {
            verdict: (match msg.verdict {
                Verdict::Drop => 0,
                Verdict::Accept => 1,
                Verdict::Queue(num) => (num as u32) << 16 | 3,
                Verdict::Repeat => 4,
                Verdict::Stop => 5,
            })
            .to_be(),
            id: msg.hdr.packet_id,
        };
        nlmsg.put(NFQA_VERDICT_HDR as u16, &vh);
        if msg.nfmark_dirty {
            nlmsg.put_be32(NFQA_MARK as u16, msg.nfmark);
        }
        if let PayloadState::Unmodified = msg.payload_state {
        } else {
            if msg.verdict != Verdict::Drop {
                let payload = msg.get_payload();
                nlmsg.put_bytes(NFQA_PAYLOAD as u16, payload);
            }
        }
        let buffer = nlmsg.finish();
        let ret = self.send_nlmsg(&buffer);
        self.verdict_buffer = buffer;
        ret
    }
}

impl AsRawFd for Queue {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for Queue {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

fn _assert_send_and_sync() {
    fn check<T: Send + Sync>() {}

    check::<Message>();
    check::<Queue>();
}
