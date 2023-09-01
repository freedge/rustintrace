use pcap::{Device, Capture};
use clap::Parser;
use etherparse::{SlicedPacket, TransportSlice, InternetSlice};
use std::collections::HashMap;
use chrono::Local;
use std::thread;
use std::sync::mpsc; 
use std::time::SystemTime;

mod traceroute;

#[derive(Parser)]
struct Cli {
    /// The interface to capture
    #[arg(short, long)]
    interface: String,
    
    /// We will resend the packets using ttl ranging from 1 to this
    #[arg(short, long = "maxttl", default_value_t = 15)]
    ttl: u8,

    /// We will only send after the packets has been seen this many times
    #[arg(short, long = "retransmit", default_value_t = 5)]
    re: u8,

    /// Maximum number of packets we will capture
    #[arg(short, long, default_value_t = 100000)]
    max: u32,

    /// Quiescing time: we will wait that many milli seconds before sending more
    #[arg(short, long, default_value_t = 2000)]
    quiescing: u128,

    #[arg(short, long)]
    verbose: bool,

    /// Filter (tcpdump format)
    filter: String,
}

#[derive(Hash, Eq, PartialEq, Debug)]
struct V4Key {
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
}

#[derive(Debug)]
struct Val {
    sequence_number: u32,
    acknowledgment_number:  u32,
    count: u8
}

struct Block {
    packet: Vec<u8>,
    header_size: usize,
}

fn main() {
    let args = Cli::parse();
    let mut total_captured = 0;


    let main_device = Device::from(&args.interface[..]);
    let mut cap = Capture::from_device(main_device).unwrap()
                  .immediate_mode(true)
                  .open().unwrap();

    cap.filter(&args.filter[..], false).unwrap();

    // we track all connections here. This grows and is never cleaned
    let mut packets : HashMap<V4Key, Val> = HashMap::new();

    // starting a different thread for traceroute stuff
    let (tx, rx) = mpsc::channel::<Block>();    
    let handler = thread::Builder::new().name("traceroute".into()).spawn(move || {        
        let mut last = std::time::UNIX_EPOCH;
        loop {
            match rx.recv() {
                Ok(receive) => {
                    if let Ok(dur) = SystemTime::now().duration_since(last) {
                        if dur.as_millis() > args.quiescing {
                            println!("📣"); 
                            traceroute::traceroute(receive.packet, args.ttl, &args.interface[..], receive.header_size);
                            if args.verbose {
                                println!("🙊");
                            }
                            last = SystemTime::now();
                        } else if args.verbose {
                            println!("💤");
                        }
                    }
                }
                _ => { break;}
            }
        }
    }).unwrap();

    while let Ok(packet) = cap.next_packet() {
        if let Ok(value) = SlicedPacket::from_ethernet(&packet) {
            total_captured += 1;            
            if args.max == total_captured {
                drop(tx);
                handler.join().unwrap();
                break;
            }
            if let Some(InternetSlice::Ipv4(ip_header, _)) = value.ip {
                match value.transport {
                    Some(TransportSlice::Icmpv4(_)) => {
                        println!("[{total_captured}] ICMP from {} ({})", ip_header.source_addr(), Local::now());
                    }
                    Some(TransportSlice::Tcp(tcp_header)) =>  {
                        let key = V4Key {
                            source: ip_header.source(),
                            destination: ip_header.destination(),
                            source_port: tcp_header.source_port(),
                            destination_port: tcp_header.destination_port(),
                        };                        
                        let count = match packets.get_mut(&key) {
                            Some(v) if v.sequence_number == tcp_header.sequence_number() && v.acknowledgment_number == tcp_header.acknowledgment_number() => {
                                v.count += 1;
                                v.count
                            } 
                            Some(v) => {    
                                v.sequence_number = tcp_header.sequence_number();
                                v.acknowledgment_number = tcp_header.acknowledgment_number();
                                v.count = 1;
                                1
                            }
                            None => {
                                packets.insert(key, Val{sequence_number: tcp_header.sequence_number(), acknowledgment_number: tcp_header.acknowledgment_number(), count: 1});
                                1
                            }
                        };
                        let df = ip_header.dont_fragment();
                        if count == args.re || args.verbose {
                            let df_string = if df { "DF " } else { "" };
                            println!("[{total_captured}] {}:{}->{}:{} iplen={} seq={} ttl={} [x{count}] {} ({})", ip_header.source_addr(), tcp_header.source_port(), ip_header.destination_addr(), tcp_header.destination_port(), ip_header.total_len(), tcp_header.sequence_number(), ip_header.ttl(), df_string, Local::now());
                        }
                        if count == args.re && df && ip_header.ttl() > args.ttl {
                            let header_size : usize = 4 * ip_header.ihl() as usize;
                            tx.send(Block {packet: packet.to_vec(), header_size: header_size}).unwrap();                            
                        }
                    }
                    None | _=> todo!(),
                }
            }
        }               
    }
    println!("Hello, world!");
}
