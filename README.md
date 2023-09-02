[![Docker Repository on Quay](https://quay.io/repository/frigault/rustintrace/status "Docker Repository on Quay")](https://quay.io/repository/frigault/rustintrace)
[![Rust](https://github.com/freedge/rustintrace/actions/workflows/rust.yml/badge.svg)](https://github.com/freedge/rustintrace/actions/workflows/rust.yml)

An adhoc tool to investigate intermittent packet drop

```
cargo build && sudo ip netns exec n1 target/debug/rustintrace  -i vm1 "host 10.224.123.3 or icmp"
```

- detect packet retransmission
- following the 5th transmission, resend the last packet with increasing ttl from 1 to 15




https://github.com/robertswiecki/intrace

https://linux.die.net/man/8/tcpkill

https://github.com/iovisor/bpftrace/blob/master/tools/tcpretrans.bt
