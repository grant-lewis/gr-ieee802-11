# gr-ieee802-11 (SNR + CSI Fork)

This is a fork of [bastibl/gr-ieee802-11](https://github.com/bastibl/gr-ieee802-11) that exposes SNR and CSI as raw bytes appended to the pcap packet output.

## Payload Format

After the packet bytes, the following fields are appended:

| Field | Length | Format |
|---|---|---|
| Packet bytes | Variable | Standard 802.11 payload |
| Marker | 4 bytes | `0x00 0x01 0x02 0x03` |
| Signal* | 8 bytes | Little-endian double |
| Noise* | 8 bytes | Little-endian double |
| CSI | 416 bytes | 52 × 8 bytes, one `float32` complex per subcarrier |

*In the radiotap header, the SNR computed by the LS equalizer is given by `10 * log10(signal / noise / 2)`.

---

## Installation

With GNU Radio 3.10 installed:

### 1. Clone this repository

```bash
git clone https://github.com/grant-lewis/gr-ieee802-11
```

### 2. Clone gr-foo

```bash
git clone https://github.com/bastibl/gr-foo
```

Replace `gr-foo/lib/wireshark_connector_impl.cc` with the version from this repository:

```bash
cp gr-ieee802-11/wireshark_connector_impl.cc gr-foo/lib/wireshark_connector_impl.cc
```

### 3. Build and install gr-foo

```bash
cd gr-foo
mkdir build && cd build
cmake ..
make
sudo make install
sudo ldconfig
```

### 4. Build and install this repository

```bash
cd gr-ieee802-11
mkdir build && cd build
cmake ..
make
sudo make install
sudo ldconfig
```

---

## References

- [bastibl/gr-ieee802-11](https://github.com/bastibl/gr-ieee802-11) - Original repository
- [WIME Project](https://www.wime-project.net)
