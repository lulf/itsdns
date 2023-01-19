//! DNS client built on embedded-nal-async UDP traits.
#![no_std]
#![feature(impl_trait_projections)]
#![feature(async_fn_in_trait)]

use embedded_nal_async::{AddrType, Dns, IpAddr, UdpStack};
use heapless::String;

struct Error;

/// DNS client
pub struct ItsDns<S: UdpStack> {
    stack: S,
}

struct DnsQuery<'a> {
    id: u16,
    opcode: Opcode,
    host: &'a str,
}

enum Opcode {
    Query,
    IQuery,
    Status,
}

#[repr(u8)]
enum QType {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    ALL = 255,
}

#[repr(u8)]
enum QClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
}

struct DnsResponse {
    authoritative: bool,
}

impl<'a> DnsQuery<'a> {
    fn encode(&self, buf: &mut [u8]) -> Result<usize, Error> {
        assert!(buf.len() >= 8);
        let id = self.id.to_le_bytes();
        buf[0] = id[0];
        buf[1] = id[1];

        // bit 0 - query
        // bit 1-4 - opcode
        // bit 5 - authorative (for responses, not set)
        // bit 6 - truncation (not set)
        // bit 7 - recursion (not set)
        buf[2] = match self.opcode {
            Opcode::Query => 0,
            Opcode::IQuery => 1,
            Opcode::Status => 2,
        } << 3;

        buf[3] = 0;

        buf[4] = 1; // QDCOUNT
        buf[5] = 0; // ANCOUNT
        buf[6] = 0; // NSCOUNT
        buf[7] = 0; // ARCOUNT

        let mut pos = 8;
        let mut labels = self.host.split('.');
        while let Some(label) = labels.next() {
            let label = label.as_bytes();
            let l = label.len().min(255);
            buf[pos] = l as u8;
            pos += 1;

            buf[pos..pos + l].copy_from_slice(&label[..l]);
            pos += l;
        }
        buf[pos] = 0;
        pos += 1;

        let qtype = (QType::A as u16).to_be_bytes();
        buf[pos] = qtype[0];
        buf[pos + 1] = qtype[1];

        let qclass = (QClass:IN as u16).to_be_bytes();
        buf[pos + 2] = qclass[0];
        buf[pos + 3] = qclass[1];

        Ok(pos)
    }
}

impl<S: UdpStack> Dns for ItsDns<S> {
    type Error = ();

    async fn get_host_by_name(
        &self,
        host: &str,
        addr_type: AddrType,
    ) -> Result<IpAddr, Self::Error> {
        Err(())
    }

    async fn get_host_by_address(&self, addr: IpAddr) -> Result<String<256>, Self::Error> {
        Err(())
    }
}
