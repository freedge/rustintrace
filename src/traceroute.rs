use pnet::datalink::Channel;
use pnet::util::checksum;
use std::{thread, time};


// send the same packet with varying ttls
pub fn traceroute(packet: Vec<u8>, ttl: u8, iface_name: &str, header_len: usize) {
    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == iface_name)
        .unwrap();

    let (mut sender, _) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    
    for i in 1..=ttl {
        let mut data = packet.clone();
        data[22] = i;
        let  c = checksum(&data[14..14+header_len], 5);
        data[14 + 10 ] = ((c & 0xFF00) >> 8) as u8;
        data[14 + 11 ] = (c & 0xFF) as u8;

        sender
            .send_to(&data, None)
            .unwrap()
            .unwrap();
        thread::sleep(time::Duration::from_millis(40));
    }
}