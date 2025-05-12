""# Troubleshooting

---

## 🔹 **1️⃣ Check Tunnel Interfaces:**  
```bash
ip link show Tunnel1
ip link show Tunnel2
```

- Are they both in state `UP`?  
- Do you see proper IP addresses (169.254.x.x) assigned?  
  - **Local IP**: 169.254.195.78 for Tunnel1 and 169.254.125.126 for Tunnel2.  
  - **Remote IP**: 169.254.195.77 for Tunnel1 and 169.254.125.125 for Tunnel2.  

> If you don’t see this, the tunnel interface is not properly configured.  

---

## 🔹 **2️⃣ Check Routing Table (customvpn):**  
```bash
ip route show table customvpn
```

- You should see entries like:  
```plaintext
10.0.0.0/16 via 169.254.195.77 dev Tunnel1 metric 100
10.0.0.0/16 via 169.254.125.125 dev Tunnel2 metric 200
```

- If not, add them manually:  
```bash
sudo ip route add 10.0.0.0/16 via 169.254.195.77 dev Tunnel1 table customvpn metric 100
sudo ip route add 10.0.0.0/16 via 169.254.125.125 dev Tunnel2 table customvpn metric 200
```

---

## 🔹 **3️⃣ Check IP Rules:**  
```bash
ip rule show
```

- You should see:  
```plaintext
100:    from 172.16.0.0/12 fwmark 0x64 lookup customvpn
100:    from 172.16.0.0/12 fwmark 0xc8 lookup customvpn
```

- If not, add them:  
```bash
sudo ip rule add from 172.16.0.0/12 fwmark 0x64 lookup customvpn priority 100
sudo ip rule add from 172.16.0.0/12 fwmark 0xC8 lookup customvpn priority 100
```

---

## 🔹 **4️⃣ Check NAT Rules (POSTROUTING):**  
```bash
sudo iptables -t nat -L -v -n
```

- You should see:  
```plaintext
RETURN     all  --  172.16.0.0/12        10.0.0.0/16
MASQUERADE all  --  172.16.0.0/12        0.0.0.0/0
```

- If not, re-add them:  
```bash
sudo iptables -t nat -A POSTROUTING -s 172.16.0.0/12 -d 10.0.0.0/16 -j RETURN
sudo iptables -t nat -A POSTROUTING -s 172.16.0.0/12 -o eth0 -j MASQUERADE
```

---

## 🔹 **5️⃣ Check Mangle Rules:**  
```bash
sudo iptables -t mangle -L -v -n
```

- Ensure the four rules are present:  
  - FORWARD -s 172.16.0.0/12 -d 10.0.0.0/16 -o Tunnel1 ...
  - FORWARD -s 172.16.0.0/12 -d 10.0.0.0/16 -o Tunnel2 ...
  - OUTPUT  -s 172.16.0.0/12 -d 10.0.0.0/16 -o Tunnel1 MARK set 0x64
  - OUTPUT  -s 172.16.0.0/12 -d 10.0.0.0/16 -o Tunnel2 MARK set 0xC8  

---

## 🔹 **6️⃣ Check XFRM Policy:**  
```bash
ip xfrm policy
```

- You should see policies for:  
  - `src 172.16.0.0/12 to 10.0.0.0/16`
  - `dst 10.0.0.0/16 to 172.16.0.0/12`  

> If these policies are missing, IPsec traffic will not be encapsulated correctly.  

---

## 🔹 **7️⃣ Attempt a Ping (Verbose Output):**  
```bash
ping -I 172.16.0.1 10.0.4.85
ping -I 172.16.0.2 10.0.4.85
```

If it still fails, run:  
```bash
sudo tcpdump -i Tunnel1 icmp or esp
sudo tcpdump -i Tunnel2 icmp or esp
sudo tcpdump -i eth0 icmp or esp
```

---

## 🔹 **8️⃣ Ping the Tunnel Endpoint:**  
```bash
ping -I 169.254.195.78 169.254.195.77   # For Tunnel1
ping -I 169.254.125.126 169.254.125.125 # For Tunnel2
```

- If you receive a response, the tunnel is up.  
- If there is no response, the tunnel is down.  

---

## 🔹 **9️⃣ Check IPsec Logs:**  
```bash
sudo tail -f /var/log/syslog | grep charon
```

Look for:  
  - `NO_PROPOSAL_CHOSEN`
  - `AUTHENTICATION_FAILED`
  - `CHILD_SA not established`
  - `IKE_SA deleted`  

---

## 🔹 **🔟 Verify IP Forwarding:**  
```bash
sysctl net.ipv4.ip_forward
```

- If it returns `0`, enable it:  
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

---

## 🔹 **1️⃣1️⃣ Verify Security Association (SA):**  
```bash
ip xfrm state
```

Look for:  
  - SPI (Security Parameter Index) entries  
  - Both inbound and outbound are listed  

---
""
