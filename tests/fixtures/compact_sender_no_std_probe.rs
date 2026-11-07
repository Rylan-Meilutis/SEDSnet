//! External no_std compile probe; consume the actual compiled SDK rlib.
#![no_std]
#![crate_type = "rlib"]

pub fn compact_source_for_sender(sender: &str) -> u32 {
    sedsnet::packet::sender_address_u32(sender)
}
