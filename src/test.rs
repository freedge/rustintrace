#[cfg(test)]
mod tests {
    use crate::*;

    fn read_hexstream(hexstream: &str) -> Vec<u8> {
        let mut packet : Vec<u8> = vec![];
        let mut it = hexstream.chars();
        let mut n = it.next();
        while let Some(high) = n {
            let low = it.next().unwrap();
            let s = String::new() + &high.to_string() + &low.to_string();
            let c = i64::from_str_radix(&s, 16).unwrap() as u8;
            packet.push(c);
            n = it.next();
        };
        packet
    }

    fn format_packet_from_hexstream(packet1: &str) -> String {
        let v = read_hexstream(packet1);
        let Ok(eth) = SlicedPacket::from_ethernet(&v[..]) else { panic!("could not parse") };
        let Some(TransportSlice::Icmpv4(icmp)) = eth.transport else { panic!("could not parse transport") };
        format_inner_packet(&icmp)
    }

    #[test]
    fn test_format_truncated_packet() {
        let packet1 = "002248a10000000d3ab2e12d08004500003800000000fd01692c0a3900040a3c00000b00addb00000000450000baa52b4000010645700a3c0000ac1e9828c3be0029ff7e67bd";
        assert_eq!("10.60.0.0:50110->172.30.152.40:41 len=186 seq=4286474173 ? ", format_packet_from_hexstream(packet1));
    }

    #[test]
    fn test_normal_packet() {
        let packet1 = "002248a10000000d3ab2e847080045c000509c7600003e0121c5ac1cc7390a3c00000b0083c9000000004500003449f740000106a12a0a3c0000ac1e9828dd6e002985477c86afc9facf801010d0a2ac00000101080a23137e71862466f5";
        assert_eq!("10.60.0.0:56686->172.30.152.40:41 len=52 seq=2236054662 ack=2949249743 ", format_packet_from_hexstream(packet1));
    }

    #[test]
    fn test_ping_expired() {
        let packet1 = "00155d34310100155ded98130800450000607ca20000fd014a18c295ae6a0ae07b020b007257001100004500005490a04000010153170ae07b02080808080800e42f0002000138e2f664000000001bcc060000000000101112131415161718191a1b1c1d1e1f2021222324252627";
        assert_eq!("8|0 10.224.123.2->8.8.8.8 len=84 seq=1 ", format_packet_from_hexstream(packet1));
    }
}
