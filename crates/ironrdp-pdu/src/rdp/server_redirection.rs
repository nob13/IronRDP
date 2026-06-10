//! Server Redirection PDU.
//!
//! Defined in [\[MS-RDPBCGR\] 2.2.13.1] (Enhanced Security Server Redirection
//! Packet) wrapping [\[MS-RDPBCGR\] 2.2.13.1.1] (TS_SERVER_REDIRECTION_PACKET).
//!
//! Sent by a server to instruct the client to disconnect and reconnect to a
//! different (or the same) endpoint, optionally with a routing token, fresh
//! credentials, and a target certificate. gnome-remote-desktop's `--system`
//! daemon uses this to hand off authenticated sessions to the per-user
//! daemon listening on the same address.
//!
//! This client decodes the packet only; it never originates one.
//!
//! [\[MS-RDPBCGR\] 2.2.13.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/efacbc1c-a3a4-4de2-832b-aacefac6b9b8
//! [\[MS-RDPBCGR\] 2.2.13.1.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3970fa05-89cf-4f97-9842-0f3e26a7afd4

use bitflags::bitflags;
use ironrdp_core::{Decode, DecodeResult, ReadCursor, ensure_fixed_part_size, ensure_size, invalid_field_err};

bitflags! {
    /// `RedirFlags` bits, [MS-RDPBCGR] 2.2.13.1.1.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct RedirFlags: u32 {
        const TARGET_NET_ADDRESS       = 0x0000_0001;
        const LOAD_BALANCE_INFO        = 0x0000_0002;
        const USERNAME                 = 0x0000_0004;
        const DOMAIN                   = 0x0000_0008;
        const PASSWORD                 = 0x0000_0010;
        const DONT_STORE_USERNAME      = 0x0000_0020;
        const SMARTCARD_LOGON          = 0x0000_0040;
        const NOREDIRECT               = 0x0000_0080;
        const TARGET_FQDN              = 0x0000_0100;
        const TARGET_NETBIOS_NAME      = 0x0000_0200;
        const TARGET_NET_ADDRESSES     = 0x0000_0800;
        const CLIENT_TSV_URL           = 0x0000_1000;
        const SERVER_TSV_CAPABLE       = 0x0000_2000;
        const PASSWORD_IS_PK_ENCRYPTED = 0x0000_4000;
        const REDIRECTION_GUID         = 0x0000_8000;
        const TARGET_CERTIFICATE       = 0x0001_0000;
        // Spec leaves higher bits reserved; tolerate them.
        const _ = !0;
    }
}

/// Decoded `TS_SERVER_REDIRECTION_PACKET`.
///
/// All optional fields are present iff the corresponding `RedirFlags` bit is set.
/// String-typed fields are stored as raw little-endian UTF-16 byte sequences as
/// they appear on the wire — callers that need decoded strings should run them
/// through a UTF-16 decoder. Binary fields (LoadBalanceInfo, Password,
/// RedirectionGuid, TargetCertificate, TsvUrl) are kept as-is.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ServerRedirectionPacket {
    pub session_id: u32,
    pub flags: RedirFlags,
    pub target_net_address: Option<Vec<u8>>,
    pub load_balance_info: Option<Vec<u8>>,
    pub username: Option<Vec<u8>>,
    pub domain: Option<Vec<u8>>,
    pub password: Option<Vec<u8>>,
    pub target_fqdn: Option<Vec<u8>>,
    pub target_netbios_name: Option<Vec<u8>>,
    pub tsv_url: Option<Vec<u8>>,
    pub redirection_guid: Option<Vec<u8>>,
    pub target_certificate: Option<Vec<u8>>,
    pub target_net_addresses: Option<Vec<u8>>,
}

impl ServerRedirectionPacket {
    /// 2-byte `pad2Octets` (per the Enhanced Security Server Redirection Packet wrapper),
    /// then the inner packet header.
    const FIXED_PART_SIZE: usize =
        2 /* pad2Octets */ + 2 /* flags */ + 2 /* length */ + 4 /* sessionID */ + 4 /* redirFlags */;

    /// Inner `flags` field value: must equal `SEC_REDIRECTION_PKT` per [MS-RDPBCGR].
    const SEC_REDIRECTION_PKT: u16 = 0x0400;
}

fn read_length_prefixed(src: &mut ReadCursor<'_>) -> DecodeResult<Vec<u8>> {
    ensure_size!(in: src, size: 4);
    let len = src.read_u32() as usize;
    ensure_size!(in: src, size: len);
    Ok(src.read_slice(len).to_vec())
}

impl<'de> Decode<'de> for ServerRedirectionPacket {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        // 2 pad octets between the Share Control Header and the inner packet body.
        let _pad = src.read_u16();
        let raw_flags = src.read_u16();
        if raw_flags != Self::SEC_REDIRECTION_PKT {
            return Err(invalid_field_err!(
                "flags",
                "expected SEC_REDIRECTION_PKT (0x0400) at start of redirection packet"
            ));
        }
        let _length = src.read_u16();
        let session_id = src.read_u32();
        let flags = RedirFlags::from_bits_retain(src.read_u32());

        let mut pkt = ServerRedirectionPacket {
            session_id,
            flags,
            ..Default::default()
        };

        // Field order matches MS-RDPBCGR 2.2.13.1.1 / FreeRDP rdp_recv_server_redirection_pdu.
        // TARGET_NET_ADDRESSES is the LAST field on the wire.
        if flags.contains(RedirFlags::TARGET_NET_ADDRESS) {
            pkt.target_net_address = Some(read_length_prefixed(src)?);
        }
        if flags.contains(RedirFlags::LOAD_BALANCE_INFO) {
            pkt.load_balance_info = Some(read_length_prefixed(src)?);
        }
        if flags.contains(RedirFlags::USERNAME) {
            pkt.username = Some(read_length_prefixed(src)?);
        }
        if flags.contains(RedirFlags::DOMAIN) {
            pkt.domain = Some(read_length_prefixed(src)?);
        }
        if flags.contains(RedirFlags::PASSWORD) {
            pkt.password = Some(read_length_prefixed(src)?);
        }
        if flags.contains(RedirFlags::TARGET_FQDN) {
            pkt.target_fqdn = Some(read_length_prefixed(src)?);
        }
        if flags.contains(RedirFlags::TARGET_NETBIOS_NAME) {
            pkt.target_netbios_name = Some(read_length_prefixed(src)?);
        }
        if flags.contains(RedirFlags::CLIENT_TSV_URL) {
            pkt.tsv_url = Some(read_length_prefixed(src)?);
        }
        if flags.contains(RedirFlags::REDIRECTION_GUID) {
            pkt.redirection_guid = Some(read_length_prefixed(src)?);
        }
        if flags.contains(RedirFlags::TARGET_CERTIFICATE) {
            pkt.target_certificate = Some(read_length_prefixed(src)?);
        }
        if flags.contains(RedirFlags::TARGET_NET_ADDRESSES) {
            pkt.target_net_addresses = Some(read_length_prefixed(src)?);
        }

        // A trailing 1-byte pad is optional in the Enhanced Security wrapper; ignored.
        Ok(pkt)
    }
}
