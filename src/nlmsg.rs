use bytemuck::{AnyBitPattern, NoUninit, Pod, Zeroable};
use bytes::{BufMut, BytesMut};

#[allow(non_camel_case_types)]
type be16 = u16;
#[allow(non_camel_case_types)]
type be32 = u32;

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

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct NfqNlMsgConfigParams {
    pub copy_range: be32,
    pub copy_mode: u8,
    pub padding: [u8; 3],
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
