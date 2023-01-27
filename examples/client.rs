#![feature(async_fn_in_trait)]
#![allow(incomplete_features)]

use embedded_nal_async::SocketAddr;
use std::str::FromStr;

use itsdns::*;

#[tokio::main]
async fn main() {
    let nameserver: SocketAddr = SocketAddr::from_str("8.8.8.8:53").unwrap();
    let stack = std_embedded_nal_async::Stack::default();
    let client = ItsDns::new(stack, nameserver);

    let host = "example.com";
    println!("Resolving {}...", host);
    let ip = client
        .get_host_by_name(host, embedded_nal_async::AddrType::IPv4)
        .await
        .unwrap();

    println!("Resolved {} to {}", host, ip);
}
