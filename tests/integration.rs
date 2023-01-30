#![feature(async_fn_in_trait)]
#![allow(incomplete_features)]

use embedded_nal_async::{IpAddr, SocketAddr};
use std::str::FromStr;

use itsdns::*;

#[tokio::test]
async fn test_query() {
    let nameserver: SocketAddr = SocketAddr::from_str("8.8.8.8:53").unwrap();
    let stack = std_embedded_nal_async::Stack::default();
    let client = ItsDns::new(stack, nameserver);

    let ip = client
        .get_host_by_name("example.com", embedded_nal_async::AddrType::IPv4)
        .await
        .unwrap();
    assert_eq!(IpAddr::from_str("93.184.216.34").unwrap(), ip);
}
