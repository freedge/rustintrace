[![Docker Repository on Quay](https://quay.io/repository/frigault/rustintrace/status "Docker Repository on Quay")](https://quay.io/repository/frigault/rustintrace)
[![Rust](https://github.com/freedge/rustintrace/actions/workflows/rust.yml/badge.svg)](https://github.com/freedge/rustintrace/actions/workflows/rust.yml)

An adhoc tool to investigate intermittent packet drop

```
$ sudo podman run -ti --rm --network=host --name=rit --cap-add net_admin,net_raw quay.io/frigault/rustintrace:latest --help
Usage: rustintrace [OPTIONS] --interface <INTERFACE> <FILTER>

Arguments:
  <FILTER>  Filter (tcpdump format)

Options:
  -i, --interface <INTERFACE>  The interface to capture
  -t, --maxttl <TTL>           We will resend the packets using ttl ranging from 1 to this [default: 15]
  -r, --retransmit <RE>        We will only send after the packets has been seen this many times [default: 5]
  -m, --max <MAX>              Maximum number of packets we will capture [default: 100000]
  -q, --quiescing <QUIESCING>  Quiescing time: we will wait that many milli seconds before sending more [default: 2000]
  -s, --snaplen <SNAPLEN>      Snaplen, we will only resend packets smaller than this size [default: 1500]
  -v, --verbose
  -h, --help                   Print help
```

```
sudo podman run -ti --rm --network=host --name=rit --cap-add net_admin,net_raw quay.io/frigault/rustintrace:latest -i eth0 "(host 10.224.123.3 and port 80) or icmp"

[7] 192.168.42.2:58082->10.224.123.3:80 iplen=128 seq=3782784997 ttl=64 [x5] DF  (2023-09-02 13:51:41.929750723 +00:00)
📣
```

- detect packet retransmission
- following the 5th transmission, resend the last packet with increasing ttl from 1 to 15




https://github.com/robertswiecki/intrace

https://linux.die.net/man/8/tcpkill

https://github.com/iovisor/bpftrace/blob/master/tools/tcpretrans.bt
