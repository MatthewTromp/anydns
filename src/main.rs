type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;
use std::net::UdpSocket;

use anydns::handle_query;

const PORT: u16 = 5301;

fn main() -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", PORT))?;

    loop {
        match handle_query(&socket) {
            Ok(_) => {}
            Err(e) => eprintln!("An error occurred: {}", e),
        }
    }
}
