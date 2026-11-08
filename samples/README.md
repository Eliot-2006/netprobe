# Sample captures

Small, synthetic, committed captures used by `scripts/demo.sh`. None contain real traffic.

| File | What it shows | How it was made |
|---|---|---|
| `http_session.pcap` | One clean HTTP-style TCP session over IPv4: handshake, request, 6 KB response, FIN both ways | Copy of `tests/fixtures/tcp_clean_v4.pcap` (Scapy, `tests/fixtures/gen_fixtures.py`) |
| `lossy_bulk_transfer.pcap` | 6 bulk TCP transfers with ~1.8% capture loss and ~3% reordering: ACKed gaps, out-of-order segments | `synth_pcap -o samples/lossy_bulk_transfer.pcap --profile d2 --size 600K --flows 6 --loss 1 --reorder 3 --seed 11` |
| `mixed_traffic.pcap` | 40 mixed flows: TCP and UDP, IPv4 and IPv6, VLAN tags, reordering, loss, retransmissions, a malformed frame | `synth_pcap -o samples/mixed_traffic.pcap --profile d3 --size 700K --flows 40 --seed 7` |

`synth_pcap` is built by the `bench` preset (`cmake --preset bench && cmake --build --preset bench`).
Output is deterministic for the same arguments.

The published copies in `docs/demo/` (served by GitHub Pages) are regenerated with:

```bash
for f in http_session lossy_bulk_transfer mixed_traffic; do
    build/release/netprobe analyze samples/$f.pcap -q --deterministic --html docs/demo/$f.html
done
```
