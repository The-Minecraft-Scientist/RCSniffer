extern crate pnet;
extern crate json;
extern crate base64;
extern crate chrono;
#[macro_use] extern crate hex_literal;

use chrono::prelude::*;
use json::*;
use base64::encode;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::env;
use std::io::{self, Write};
use std::process;

//convert two bytes to a u16
fn to_u16(a: u8, b: u8,) -> u16{
    ( ( a as u16 ) << 8 ) | b as u16
}
//bot structure to hold  our data once we parse it
struct Bot {
    capture_time: String,
    cube_data: Vec<u8>,
}
//export to .bot string
impl Bot {
    pub fn to_json(&self) ->  String {
    object!(
        "addedDate": self.capture_time.clone(),
        "cubeData": encode(&self.cube_data)
    ).dump()
    }
}
//grab "pure" cube and color data from "raw" packets sniffed on the wire
fn from_packet(cube_data_packet: Vec<u8>) -> Bot{
    let time: DateTime<Local> = Local::now();
    let cube_data_offset: usize = (to_u16(cube_data_packet[14],cube_data_packet[15])+28) as usize;
    let mut p = cube_data_offset;
    while p <cube_data_packet.len() {
        if cube_data_packet[ p .. p + 4] == hex!("21 78 00 00 // this is the octet that cubeData stops in") {
            break
        }
        p += 4;
    }
    Bot {cube_data: cube_data_packet[cube_data_offset .. p].to_vec(),capture_time: time.to_rfc3339()}
}
fn main() {
    use pnet::datalink::Channel::Ethernet;
    let iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            writeln!(io::stderr(), "RCSniff [network interface] (di)").unwrap();
            process::exit(1);
        }
    };
    let (debug,listints) = match env::args().nth(2) {
        Some(n) => {
            match n.as_str() {
                "d" => {(true, false)}
                "di" => {(true,true)}
                "i" => {(false, true)}
                _ => {(false,false)}
            }
        }
        _ => {(false,false)}
    };
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    if listints {
        let mut o: String = "Interfaces: \n".to_owned();
        for interface in interfaces.clone() {
            if interface.is_up() && !interface.is_loopback() && ! interface.is_point_to_point() {
                o = o + &*interface.name + &*"\n"
            }
        }
        println!("{}",o)
    }
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };
    let mut waitfor = 0;
    let mut cube_buffer: Vec<u8>=vec!();
    loop {
        match rx.next() {
            Ok(packet) => {
                let epack = &EthernetPacket::new(packet).unwrap();
                //we only care about ipv4 packets
                let head = Ipv4Packet::new(epack.payload());
                if let Some(head) = head {
                    let pcall = head.get_next_level_protocol();
                    let pcallpack = head.payload();
                    //we only care about TCP packets
                    if pcall == IpNextHeaderProtocols::Tcp {
                        let tcp = TcpPacket::new(pcallpack);
                        if let Some(tcp) = tcp {
                            let pl = tcp.payload().clone();
                            let len = pl.len();
                            // now we filter the TCP packets by dest port and get rid of the cruft (shorter than 58 length payload) and anything the server is sending
                            if tcp.get_destination() == 4533  && len>58 {
                                println!("rc packet detected: len {}",&len);
                                if debug { println!("{:02X?}",pl) };
                                let total_len = to_u16(pl[3],pl[4]) as usize;
                                // use a specific 5-byte slice of the payload to determine its identifier and match it with ones that interest us
                                match pl[8 .. 13] {
                                    hex!("02 29 00 06 36") => {
                                        let pcount = ( total_len as f32 / 1390.0 ).ceil() as u16;
                                        waitfor = total_len;
                                        println!("CubeData identifier detected (total length: {}, packets needed: {}",&total_len,&pcount)
                                    }
                                    _=>{}
                                }
                                println!("{},  {}", waitfor,len);
                                if waitfor > 0 {
                                    waitfor = waitfor - len;
                                    cube_buffer.append(pl.to_vec().as_mut());
                                    if waitfor == 0 {
                                        println!("barebones .bot JSON for this bot: {}", from_packet(cube_buffer.clone()).to_json()
                                        );
                                        cube_buffer.clear();
                                    }

                                }
                            }
                        }
                    }
                }
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }
}