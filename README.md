# TCP In Rust


### Test
```bash
ping 192.168.0.1
nc 192.168.0.2 443
curl 192.168.0.2:443
```
#### Run Wireshark
```bash
tshark -i utun7

Capturing on 'utun7'
    1   0.000000   192.168.0.1 → 192.168.0.2   TCP 68 52828 → 443 [SYN, ECE, CWR] Seq=0 Win=65535 Len=0 MSS=1460 WS=64 TSval=3932160025 TSecr=0 SACK_PERM
    2   0.000182   192.168.0.2 → 192.168.0.1   TCP 44 443 → 52828 [SYN, ACK] Seq=0 Ack=1 Win=1500 Len=0
    3   0.000305   192.168.0.1 → 192.168.0.2   TCP 44 52828 → 443 [ACK] Seq=1 Ack=1 Win=65535 Len=0
    4   2.534487   192.168.0.1 → 192.168.0.2   SSL 46
    5   2.534662   192.168.0.2 → 192.168.0.1   TCP 44 443 → 52828 [FIN, ACK] Seq=1 Ack=3 Win=1500 Len=0
    6   2.534814   192.168.0.1 → 192.168.0.2   TCP 44 52828 → 443 [ACK] Seq=3 Ack=2 Win=65535 Len=0
    7   2.534942   192.168.0.1 → 192.168.0.2   TCP 44 52828 → 443 [FIN, ACK] Seq=3 Ack=2 Win=65535 Len=0
    8   2.535047   192.168.0.2 → 192.168.0.1   TCP 44 443 → 52828 [ACK] Seq=2 Ack=4 Win=1500 Len=0
```