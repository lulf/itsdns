# itsdns

[![CI](https://github.com/lulf/itsdns/actions/workflows/ci.yaml/badge.svg)](https://github.com/lulf/itsdns/actions/workflows/ci.yaml)
[![crates.io](https://img.shields.io/crates/v/itsdns.svg)](https://crates.io/crates/itsdns)
[![docs.rs](https://docs.rs/itsdns/badge.svg)](https://docs.rs/itsdns)

It's always DNS.

A light weight (no_std and no_alloc) lightweight DNS client that you can use with any UDP stack implemented by `embedded-nal-async`. It also implements the DNS traits from `embedded-nal-async`.

# example

```rust
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
```
