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

    #[test]
    fn test_format_truncated_packet() {
        let packet1 = "002248a10000000d3ab2e12d08004500003800000000fd01692c0a3900040a3c00000b00addb00000000450000baa52b4000010645700a3c0000ac1e9828c3be0029ff7e67bd";
        let v = read_hexstream(packet1);
        let Ok(eth) = SlicedPacket::from_ethernet(&v[..]) else { panic!("could not parse") };
        let Some(TransportSlice::Icmpv4(icmp)) = eth.transport else { panic!("could not parse transport") };
        let st = format_inner_packet(&icmp);
        assert_eq!("10.60.0.0:50110->172.30.152.40:41 len=186 seq=4286474173 ? ", st);
    }

    #[test]
    fn test_normal_packet() {
        let packet1 = "002248a10000000d3ab2e847080045c000509c7600003e0121c5ac1cc7390a3c00000b0083c9000000004500003449f740000106a12a0a3c0000ac1e9828dd6e002985477c86afc9facf801010d0a2ac00000101080a23137e71862466f5";
        let v = read_hexstream(packet1);
        let Ok(eth) = SlicedPacket::from_ethernet(&v[..]) else { panic!("could not parse") };
        let Some(TransportSlice::Icmpv4(icmp)) = eth.transport else { panic!("could not parse transport") };
        let st = format_inner_packet(&icmp);
        assert_eq!("10.60.0.0:56686->172.30.152.40:41 len=52 seq=2236054662 ack=2949249743 ", st);
    }
}
