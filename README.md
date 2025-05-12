## VPN Failover and IPsec Tunnel Automation

This repository contains the configuration and scripts required to automate VPN failover and IPsec tunnel management between AWS and Linode using StrongSwan. It includes:
- Automated IPsec tunnel bring-up and teardown
- Real-time failover monitoring with `vpn-failover.sh`
- Dynamic routing and IP rules management
- Seamless integration with IPsec service lifecycle

---

## Prerequisites
1. **Ubuntu 20.04+**
2. **StrongSwan** (`sudo apt-get install strongswan`)
3. **iptables-persistent** (`sudo apt-get install iptables-persistent`)
4. **IPsec Configuration Files** (`ipsec.conf` and `ipsec.secrets`)

---

## Configuration
### 1. `ipsec.conf`
Contains the IPsec connection definitions for AWS and Linode. It sets up the VPN tunnels and applies necessary security policies.

### 2. `ipsec.secrets`
Stores the shared secrets for IPsec authentication.

### 3. `vpn-updown.sh`
Triggered by IPsec during tunnel up/down events:
- Configures the VTI interfaces
- Applies IP routes and firewall rules
- Logs the state of the tunnel
- Updates `/var/run/vpn_last_switch` with the tunnel state

### 4. `vpn-failover.sh`
Runs as a systemd service to:
- Monitor the tunnel state
- Perform failover between primary and secondary tunnels
- Update IP routes, firewall rules, and IP rules dynamically
- Detects IPsec service status to handle graceful fallback

---

## Setup Instructions
1. **Clone the Repository**
    ```bash
    git clone <repository-url>
    cd <repository-folder>
    ```

2. **Copy Scripts**
    ```bash
    sudo cp vpn-updown.sh /usr/local/bin/vpn-updown.sh
    sudo cp vpn-failover.sh /usr/local/bin/vpn-failover.sh
    sudo chmod +x /usr/local/bin/vpn-updown.sh
    sudo chmod +x /usr/local/bin/vpn-failover.sh
    ```

3. **Configure IPsec**
    - Place `ipsec.conf` in `/etc/ipsec.conf`
    - Place `ipsec.secrets` in `/etc/ipsec.secrets`

4. **Enable IPsec Service**
    ```bash
    sudo systemctl enable ipsec
    sudo systemctl start ipsec
    ```

5. **Enable VPN Failover Service**
    Place the following content in `/etc/systemd/system/vpn-failover.service`:
    ```
    [Unit]
    Description=VPN Tunnel Failover Service
    After=network-online.target ipsec.service
    Wants=network-online.target

    [Service]
    Type=simple
    User=root
    Group=root
    WorkingDirectory=/usr/local/bin
    ExecStart=/bin/bash /usr/local/bin/vpn-failover.sh
    Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    Restart=always
    RestartSec=10
    LimitNOFILE=65536
    StandardOutput=syslog
    StandardError=syslog
    SyslogIdentifier=vpn-failover

    [Install]
    WantedBy=multi-user.target
    ```

    Enable and start the service:
    ```bash
    sudo systemctl enable vpn-failover
    sudo systemctl start vpn-failover
    ```

---

## Monitoring and Failover Logic
`vpn-failover.sh` continuously:
- Checks the health of the primary tunnel
- Fails over to the secondary tunnel upon detection of failure
- Maintains proper IP rules and routing tables
- Prevents race conditions using file locks and state tracking

---

## Advanced Troubleshooting
1. **Check IPsec Status**
    ```bash
    sudo ipsec statusall
    ```

2. **Check Routes**
    ```bash
    ip route show table customvpn
    ```

3. **Check Firewall Rules**
    ```bash
    sudo iptables -t filter -L
    sudo iptables -t nat -L
    sudo iptables -t mangle -L
    ```

4. **Logs**
    - VPN Failover logs: `/var/log/vpn-failover.log`
    - IPsec logs: `/var/log/syslog`

---

## Known Issues
1. IPsec service restart may take up to 2 minutes to fully sync routes.
2. If the `/var/run/vpn_last_switch` is deleted, failover logic may be impacted.

---

## Contributing
Contributions are welcome. Please submit a PR with detailed information and testing notes.

---


## Documentation
The full setup guide is available in the `docs` folder: [VPN Setup Guide](./docs/VPN_Setup_Guide.docx)

---
