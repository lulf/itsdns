#![no_std]
#![feature(impl_trait_projections)]
#![allow(incomplete_features)]
#![feature(async_fn_in_trait)]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use core::sync::atomic::{AtomicU16, Ordering};
use embedded_nal_async::{AddrType, ConnectedUdp, Dns, IpAddr, Ipv4Addr, SocketAddr, UdpStack};
use heapless::String;

mod message;
use message::*;

/// Errors returned by the client.
#[derive(Debug)]
pub enum Error<N> {
    /// Error in the underlying network
    Network(N),
    /// Error specific to DNS
    Dns(DnsError),
    /// DNS entry not found
    NotFound,
}

/// An error related to the DNS message itself.
#[derive(Debug)]
pub enum DnsError {
    /// Error encoding the message.
    Encode,
    /// Error decoding the message.
    Decode,
    /// Message format error.
    FormatError,
    /// Failure occured on server.
    ServerFailure,
    /// Error in name.
    NameError,
    /// Functionality not supported.
    NotImplemented,
    /// Request refused.
    Refused,
}

/// DNS client
pub struct ItsDns<S: UdpStack> {
    id: AtomicU16,
    stack: S,
    server: SocketAddr,
}

impl<S: UdpStack> ItsDns<S> {
    /// Create a new DNS client using the UDP stack and a DNS server.
    pub fn new(stack: S, server: SocketAddr) -> Self {
        Self {
            id: AtomicU16::new(0),
            stack,
            server,
        }
    }

    /// Lookup a host by the name and return the IP address of the host.
    pub async fn get_host_by_name(
        &self,
        host: &str,
        _addr_type: AddrType,
    ) -> Result<IpAddr, Error<S::Error>> {
        let mut packet = [0; 512];

        let id = self.id.fetch_add(1, Ordering::Relaxed);
        let len = DnsMessage {
            id,
            opcode: Opcode::Query,
            questions: Questions::Slice(&[Question {
                qname: Domain::String(host),
                qtype: QType::A,
                qclass: QClass::IN,
            }]),
            answers: Answers::Slice(&[]),
        }
        .encode(&mut packet[..])
        .map_err(Error::Dns)?;

        match self.stack.connect(self.server).await {
            Ok((_, mut server)) => {
                server.send(&packet[..len]).await.map_err(Error::Network)?;

                let len = server
                    .receive_into(&mut packet[..])
                    .await
                    .map_err(Error::Network)?;

                let m = DnsMessage::decode(&packet[..len]).map_err(Error::Dns)?;

                for answer in 0..m.answers.count() {
                    if let Some(answer) = m.answers.get(answer).map_err(Error::Dns)? {
                        if answer.domain == Domain::String(host)
                            && answer.r#type == QType::A
                            && answer.rdata.len() >= 4
                        {
                            let ip = answer.rdata;
                            return Ok(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])));
                        }
                    }
                }
                Err(Error::NotFound)
            }
            Err(e) => Err(Error::Network(e)),
        }
    }
}

impl<S: UdpStack> Dns for ItsDns<S> {
    type Error = Error<S::Error>;

    async fn get_host_by_name(
        &self,
        host: &str,
        addr_type: AddrType,
    ) -> Result<IpAddr, Self::Error> {
        ItsDns::get_host_by_name(self, host, addr_type).await
    }

    async fn get_host_by_address(&self, _addr: IpAddr) -> Result<String<256>, Self::Error> {
        todo!()
    }
}
