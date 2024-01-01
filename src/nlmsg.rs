#![allow(dead_code)]

use bytemuck::{AnyBitPattern, NoUninit, Pod, Zeroable};
use bytes::{Buf, BufMut, BytesMut};

#[allow(non_camel_case_types)]
type be16 = u16;
#[allow(non_camel_case_types)]
type be32 = u32;
#[allow(non_camel_case_types)]
type be64 = u64;

pub const IP_CT_ESTABLISHED: u32 = 0;
pub const IP_CT_RELATED: u32 = 1;
pub const IP_CT_NEW: u32 = 2;
pub const IP_CT_IS_REPLY: u32 = 3;
pub const IP_CT_ESTABLISHED_REPLY: u32 = 3;
pub const IP_CT_RELATED_REPLY: u32 = 4;
pub const IP_CT_NUMBER: u32 = 5;
pub const IP_CT_NEW_REPLY: u32 = 5;

pub const CTA_UNSPEC: u32 = 0;
pub const CTA_TUPLE_ORIG: u32 = 1;
pub const CTA_TUPLE_REPLY: u32 = 2;
pub const CTA_STATUS: u32 = 3;
pub const CTA_PROTOINFO: u32 = 4;
pub const CTA_HELP: u32 = 5;
pub const CTA_NAT_SRC: u32 = 6;
pub const CTA_TIMEOUT: u32 = 7;
pub const CTA_MARK: u32 = 8;
pub const CTA_COUNTERS_ORIG: u32 = 9;
pub const CTA_COUNTERS_REPLY: u32 = 10;
pub const CTA_USE: u32 = 11;
pub const CTA_ID: u32 = 12;
pub const CTA_NAT_DST: u32 = 13;
pub const CTA_TUPLE_MASTER: u32 = 14;
pub const CTA_SEQ_ADJ_ORIG: u32 = 15;
pub const CTA_NAT_SEQ_ADJ_ORIG: u32 = CTA_SEQ_ADJ_ORIG;
pub const CTA_SEQ_ADJ_REPLY: u32 = 17;
pub const CTA_NAT_SEQ_ADJ_REPLY: u32 = CTA_SEQ_ADJ_REPLY;
pub const CTA_SECMARK: u32 = 19; // obsolete
pub const CTA_ZONE: u32 = 20;
pub const CTA_SECCTX: u32 = 21;
pub const CTA_TIMESTAMP: u32 = 22;
pub const CTA_MARK_MASK: u32 = 23;
pub const CTA_LABELS: u32 = 24;
pub const CTA_LABELS_MASK: u32 = 25;
pub const CTA_SYNPROXY: u32 = 26;
pub const CTA_FILTER: u32 = 27;
pub const CTA_STATUS_MASK: u32 = 28;

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct NlMsgHdr {
    pub len: u32,
    pub ty: u16,
    pub flags: u16,
    pub seq: u32,
    pub pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct NlMsgErr {
    pub error: core::ffi::c_int,
    pub msg: NlMsgHdr,
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct NlAttr {
    pub len: u16,
    pub ty: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct NfGenMsg {
    pub family: u8,
    pub version: u8,
    pub res_id: be16,
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct NfqNlMsgConfigCmd {
    pub command: u8,
    pub padding: u8,
    pub pf: be16,
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct NfqNlMsgVerdictHdr {
    pub verdict: be32,
    pub id: be32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct NfqNlMsgConfigParams {
    pub copy_range: be32,
    pub copy_mode: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct NfqNlMsgPacketHdr {
    pub packet_id: be32,
    pub hw_protocol: be16,
    pub hook: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct NfqNlMsgPacketHw {
    pub hw_addrlen: be16,
    pub padding: [u8; 2],
    pub hw_addr: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct NfqNlMsgPacketTimestamp {
    pub sec: be64,
    pub usec: be64,
}

pub struct NlmsgMut(BytesMut);

impl NlmsgMut {
    pub fn new(mut buf: BytesMut) -> Self {
        assert!(buf.as_ptr() as usize % 4 == 0);
        buf.clear();

        // Add an empty header.
        buf.put_bytes(0, core::mem::size_of::<NlMsgHdr>());
        Self(buf)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let mut buf = BytesMut::with_capacity(capacity + 3);
        let align_offset = (buf.as_ptr() as usize).wrapping_neg() % 4;
        if align_offset != 0 {
            buf = buf.split_off(align_offset);
        }

        Self::new(buf)
    }

    pub fn nested(&mut self, ty: u16) -> Self {
        let mut nested_buffer = self.0.split_off(self.0.len());

        // len of NlAttr will be updated by finish_nested
        nested_buffer.put_slice(bytemuck::bytes_of(&NlAttr {
            len: 0,
            ty: ty | libc::NLA_F_NESTED as u16,
        }));

        Self(nested_buffer)
    }

    pub fn finish_nested(&mut self, mut nested: NlmsgMut) {
        let len = nested.0.len();
        let header: &mut NlAttr =
            bytemuck::from_bytes_mut(&mut nested.0[..core::mem::size_of::<NlAttr>()]);
        header.len = len as u16;
        self.0.unsplit(nested.0.split());
    }

    /// Allocate and zero for an extra header
    pub fn extra_header<T: NoUninit + AnyBitPattern>(&mut self) -> &mut T {
        assert!(core::mem::size_of::<T>() % 4 == 0);

        let offset = self.0.len();
        let len = core::mem::size_of::<T>();
        self.0.put_bytes(0, len);
        bytemuck::from_bytes_mut(&mut self.0[offset..])
    }

    /// Put a slice of arbitary data.
    pub fn put_bytes(&mut self, ty: u16, data: &[u8]) {
        let data_len = data.len().next_multiple_of(4);
        let total_len: u16 = (data_len + core::mem::size_of::<NlAttr>())
            .try_into()
            .unwrap();

        self.0
            .put_slice(bytemuck::bytes_of(&NlAttr { len: total_len, ty }));
        self.0.put_slice(data);
        // Insert padding
        self.0.put_bytes(0, data_len - data.len());
    }

    /// Put an arbitrary data.
    pub fn put<T: NoUninit>(&mut self, ty: u16, data: &T) {
        self.put_bytes(ty, bytemuck::bytes_of(data))
    }

    /// Put an u32 attribute, convert to big endian
    pub fn put_be32(&mut self, ty: u16, data: u32) {
        self.put_bytes(ty, &data.to_be_bytes())
    }

    pub fn as_header_mut(&mut self) -> &mut NlMsgHdr {
        bytemuck::from_bytes_mut(&mut self.0[..core::mem::size_of::<NlMsgHdr>()])
    }

    pub fn finish(mut self) -> BytesMut {
        let len = self.0.len();
        self.as_header_mut().len = len as u32;
        self.0
    }
}

pub struct AttrStream<T>(T);

impl<T> AttrStream<T> {
    pub fn new(buf: T) -> Self {
        Self(buf)
    }
}

impl Iterator for AttrStream<BytesMut> {
    type Item = (u16, BytesMut);

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.remaining() < core::mem::size_of::<NlAttr>() {
            return None;
        }

        let mut attr = NlAttr::zeroed();
        self.0.copy_to_slice(bytemuck::bytes_of_mut(&mut attr));

        let bytes = self
            .0
            .split_to(attr.len as usize - core::mem::size_of::<NlAttr>());

        // Skip padding for the next attribute
        let padding = (attr.len as usize).wrapping_neg() % 4;
        if self.0.remaining() >= padding {
            self.0.advance(padding);
        }

        Some((attr.ty, bytes))
    }
}
