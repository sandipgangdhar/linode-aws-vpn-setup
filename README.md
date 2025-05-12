# VPN Setup IPsec between AWS and Linode

This repository contains all the necessary scripts and configurations to set up a fully automated IPsec VPN tunnel between AWS and Linode.

## Files:
- `vpn-updown.sh`: Manages the tunnel interface, IP rules, and routes.
- `vpn-failover.sh`: Handles failover logic between primary and secondary tunnels.
- `ipsec.conf`: IPsec configuration for strongSwan.
- `ipsec.secrets`: Secret keys for IPsec authentication.

## Documentation
The full setup guide is available in the `docs` folder: [VPN Setup Guide](./docs/VPN_Setup_Guide.docx)

---
