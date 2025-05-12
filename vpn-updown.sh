#!/bin/bash
# ================================
# AWS-Updown.sh Script
# Author: Sandip Gangdhar <sgangdha@akamai.com>
# Description: This script manages IPsec VPN tunnels in AWS, handling the creation, 
# cleanup, and routing of traffic through Tunnel1 and Tunnel2.
# ================================

# ================================
# Global Variables
# ================================
LOG_FILE="/var/log/vpn-updown.log"            # Log file location for script output
DEBUG_MODE=0                                  # Set to 1 to enable debug logs, 0 to disable
INTERFACE="eth0"                              # Interface to bind the VPN traffic (public-facing)
ROUTE_TABLE_NAME="customvpn"                  # Name of the custom route table for VPN routes
LAST_SWITCH_FILE="/var/run/vpn_last_switch"   # File to store the last switch information
LOCK_FILE="/var/run/vpn_switch.lock"          # Lock file to prevent race conditions

# ================================
# Logging Functions
# ================================

# Function to log and execute commands
# This function executes a command and logs its output to the specified log file.
log_and_run() {
    if [[ $DEBUG_MODE -eq 1 ]]; then
	# If debug mode is enabled, log the command and its output to the log file    
        echo "=== Running Command: $* at $(date) ===" | tee -a "$LOG_FILE"
        eval "$@" 2>&1 | tee -a "$LOG_FILE"
    else
	# If debug mode is disabled, log the output silently to the log file    
        eval "$@" >> "$LOG_FILE" 2>&1
    fi
}

# Function for debug logs
# This function logs debug messages if DEBUG_MODE is enabled.
debug_log() {
    if [[ $DEBUG_MODE -eq 1 ]]; then
	# Log the debug message only if DEBUG_MODE is enabled    
        echo "[DEBUG] $1" | tee -a "$LOG_FILE"
    fi
}

# ================================
# Initialization Log
# ================================
# Log the start of the script execution with a timestamp and the IPsec action (PLUTO_VERB)
echo "=== Running aws-updown.sh at $(date) for $PLUTO_VERB ===" | tee -a "$LOG_FILE"

# ================================
# Route Table Verification and Creation
# ================================
# This section checks if the custom route table exists.
# If not, it creates it and logs the action.
if ip route show table "$ROUTE_TABLE_NAME" &>/dev/null; then
    debug_log "[DEBUG] Custom route table '$ROUTE_TABLE_NAME' already exists."	
else
    debug_log "[DEBUG] Custom route table '$ROUTE_TABLE_NAME' does not exist. Creating it..."	

    # Appending the route table entry to the Linux route tables
    echo "100 $ROUTE_TABLE_NAME" >> /etc/iproute2/rt_tables
    debug_log "[INFO] Custom route table '$ROUTE_TABLE_NAME' successfully created."
fi

# ================================
# Argument Parsing
# ================================
# This block is responsible for parsing command-line arguments passed to the script.
# Each parameter corresponds to a specific value required to configure the VPN tunnel.

# Loop through all command-line arguments until none are left
while [[ $# -gt 1 ]]; do
    # Log the current argument being processed	
    debug_log "==== Parsing argument: $1 ===="
    case ${1} in
        -ln|--link-name) 
            # Tunnel name (e.g., Tunnel1, Tunnel2)		
            TUNNEL_NAME="${2}"; 
	    debug_log "[INFO] Tunnel Name set to: $TUNNEL_NAME"
            shift ;; # Shift to the next argument

        -ll|--link-local) 
	    # Local tunnel address (usually the VTI interface IP)	
            TUNNEL_LOCAL_ADDRESS="${2}"; 
	    debug_log "[INFO] Tunnel Local Address set to: $TUNNEL_LOCAL_ADDRESS"
            shift ;; # Shift to the next argument

        -lr|--link-remote) 
 	    # Remote tunnel address (the IP address of the remote VPN gateway)	
            TUNNEL_REMOTE_ADDRESS="${2}"; 
	    debug_log "[INFO] Tunnel Remote Address set to: $TUNNEL_REMOTE_ADDRESS"
            shift ;; # Shift to the next argument

        -m|--mark) 
	    # Tunnel mark (fwmark for routing policy)	
            TUNNEL_MARK="${2}"; 
	    debug_log "[INFO] Tunnel Mark set to: $TUNNEL_MARK"
            shift ;; # Shift to the next argument

        -l|--local-route) 
	    # Local subnet route (source subnet for VPN traffic)	
            TUNNEL_LOCAL_ROUTE="${2}"; 
	    debug_log "[INFO] Tunnel Local Route set to: $TUNNEL_LOCAL_ROUTE"
            shift ;; # Shift to the next argument

        -r|--static-route) 
	    # Static route (destination subnet for VPN traffic)	
            TUNNEL_STATIC_ROUTE="${2}"; 
	    debug_log "[INFO] Static Route set to: $TUNNEL_STATIC_ROUTE"
            shift ;;
        *) 
	    # If an unknown argument is found, log it as an error and move forward	
            echo "${0}: Unknown argument \"${1}\"" | tee -a "$LOG_FILE" >&2 ;;
    esac
    shift # Shift to the next pair of arguments
done

# ============================================
# Step 1: Create VTI Interface
# ============================================
# Description:
# - This step creates a VTI (Virtual Tunnel Interface) for the VPN tunnel.
# - It uses the provided local and remote IP addresses.
# - The interface is brought up with an MTU of 1419.

debug_log "[DEBUG] ==== Argument parsing complete ===="

create_interface() {
    # ================================
    # Function: create_interface
    # Description: 
    #   - This function sets up the VTI interface for the VPN tunnel.
    #   - It configures routing, IP rules, and iptables for the specified tunnel.
    # Arguments:
    #   - TUNNEL_NAME: The name of the tunnel (e.g., Tunnel1, Tunnel2).
    #   - TUNNEL_LOCAL_ADDRESS: Local IP address of the VTI interface.
    #   - TUNNEL_REMOTE_ADDRESS: Remote IP address of the VTI interface.
    #   - TUNNEL_MARK: The fwmark for policy-based routing.
    #   - TUNNEL_STATIC_ROUTE: The static route for remote subnets.
    #   - TUNNEL_LOCAL_ROUTE: The local subnet to route.
    # ================================

    # ============================================
    # Step 1: Create VTI Interface
    # ============================================
    # Description:
    # - This step creates a VTI (Virtual Tunnel Interface) for the VPN tunnel.
    # - It uses the provided local and remote IP addresses.
    # - The interface is brought up with an MTU of 1419.

    debug_log "[INFO] Creating VTI interface for $TUNNEL_NAME"
    
    # Adding the virtual tunnel interface (VTI)
    log_and_run ip link add "$TUNNEL_NAME" type vti local "$PLUTO_ME" remote "$PLUTO_PEER" key "$TUNNEL_MARK"

    # Assigning the local and remote IP addresses to the VTI interface    
    log_and_run ip addr add "$TUNNEL_LOCAL_ADDRESS" remote "$TUNNEL_REMOTE_ADDRESS" dev "$TUNNEL_NAME"

    # Setting the interface up and configuring MTU for proper packet fragmentation    
    log_and_run ip link set "$TUNNEL_NAME" up mtu 1419
    debug_log "[INFO] VTI interface $TUNNEL_NAME created and configured successfully."

    # ============================================
    # Step 2: Add Routing for the Tunnel
    # ============================================
    # Description:
    # - Adds routing for the specified tunnel to the custom VPN routing table.
    # - Defines a routing weight based on the tunnel name for priority routing.

    debug_log "[INFO] Configuring routes for $TUNNEL_NAME"    
   
    # Set the routing weight based on the tunnel name    
    if [ $TUNNEL_NAME = Tunnel1 ]; then
	    weight=100
    else
      	    weight=200
    fi 	    

    #add the route
    log_and_run ip route add $TUNNEL_STATIC_ROUTE via `echo $TUNNEL_LOCAL_ADDRESS | awk -F'/' {'print $1'}` dev "$TUNNEL_NAME" table "$ROUTE_TABLE_NAME" metric $weight
    debug_log "[INFO] Routes for $TUNNEL_NAME added successfully."
    
    # ============================================
    # Step 3: Add IP Rule for Marking
    # ============================================
    # Description:
    # - Adds an IP rule that marks packets originating from the specified subnet.
    # - This allows for custom routing decisions in the custom VPN routing table.

    debug_log "[INFO] Adding IP rule for $TUNNEL_MARK"
    
    # Add the IP rule to the routing table
    log_and_run ip rule add from $TUNNEL_LOCAL_ROUTE fwmark $TUNNEL_MARK lookup $ROUTE_TABLE_NAME priority 100
    debug_log "[INFO] IP Rule for $TUNNEL_MARK added successfully."

    # ============================================
    # Step 4: Apply Filter Table FORWARD Rules
    # ============================================
    # Description:
    # - This step adds FORWARD chain rules to allow traffic through the tunnel.
    # - It ensures that traffic can be forwarded to the specified tunnel interface.

    debug_log "[INFO] Adding iptables filter rules for $TUNNEL_NAME"

    # Check if the FORWARD rule already exists
    EXISTING=$(iptables -t filter -S FORWARD | grep -- "-o $TUNNEL_NAME -j ACCEPT")
    debug_log "[INFO] FORWARD chain check: $EXISTING for $TUNNEL_NAME"

    # If not found, add it
    if [ -z "$EXISTING" ]; then
	    debug_log "[INFO] FORWARD rule not found for $TUNNEL_NAME. Adding it."
	    log_and_run iptables -v -t filter -A FORWARD -o $TUNNEL_NAME -j ACCEPT
    else
	    debug_log "[INFO] FORWARD rule for $TUNNEL_NAME already exists. Skipping."
    fi

    # ============================================
    # Step 5: Apply NAT Table POSTROUTING Rules (RETURN)
    # ============================================
    # Description:
    # - Adds a RETURN rule to the NAT POSTROUTING chain to bypass NAT for internal traffic.
    # - Ensures local traffic to the tunnel is not masqueraded.

    debug_log "[INFO] Adding iptables NAT POSTROUTING RETURN rules for $TUNNEL_NAME"

    # Rule to prevent double NAT for internal routing
    EXISTING=$(iptables -t nat -S POSTROUTING | grep -- "-s $TUNNEL_LOCAL_ROUTE -d $TUNNEL_STATIC_ROUTE -j RETURN")
    debug_log "[INFO] NAT POSTROUTING RETURN check: $EXISTING for $TUNNEL_NAME"

    # If not found, add it
    if [ -z "$EXISTING" ]; then
	    debug_log "[INFO] NAT POSTROUTING RETURN  rule not found for $TUNNEL_NAME. Adding it."
	    log_and_run iptables -v -t nat -I POSTROUTING 1 -s $TUNNEL_LOCAL_ROUTE -d $TUNNEL_STATIC_ROUTE -j RETURN
    else
	    debug_log "[INFO] NAT POSTROUTING RETURN  rule for $TUNNEL_NAME already exists. Skipping."
    fi

    # ============================================
    # Step 6: Apply NAT Table POSTROUTING Rules (MASQUERADE)
    # ============================================
    # Description:
    # - Adds a MASQUERADE rule to the NAT POSTROUTING chain for outgoing traffic.
    # - Ensures that traffic exiting the specified interface is masqueraded.
    
    debug_log "[INFO] Adding iptables NAT POSTROUTING MASQUERADE rule for $TUNNEL_NAME"

    # Check if the MASQUERADE rule already exists
    EXISTING=$(iptables -t nat -S POSTROUTING | grep -- "-s $TUNNEL_LOCAL_ROUTE -o $INTERFACE -j MASQUERADE")
    debug_log "[INFO] NAT POSTROUTING MASQUERADE check: $EXISTING for $TUNNEL_NAME"

    # If not found, add it
    if [ -z "$EXISTING" ]; then
	    debug_log "[INFO] NAT POSTROUTING MASQUERADE rule not found for $TUNNEL_NAME. Adding it."
	    log_and_run iptables -v -t nat -A POSTROUTING -s $TUNNEL_LOCAL_ROUTE -o $INTERFACE -j MASQUERADE
    else
	    debug_log "[INFO] NAT POSTROUTING MASQUERADE rule for $TUNNEL_NAME already exists. Skipping."
    fi

    # ============================================
    # Step 7: Apply NAT Table POSTROUTING SNAT Rule for Tunnel
    # ============================================
    # Description:
    # - Adds an SNAT rule for traffic going out through the tunnel interface.
    # - Ensures traffic is source NATed with the VPN server IP for proper return routing.

    # Add the SNAT rule if not present
    debug_log "[INFO] Attempting to add NAT POSTROUTING SNAT rule for ping test for $TUNNEL_NAME"

    # Get VPN Server IP and construct Tunnel Local Address
    VPN_SERVER_IP=$(ip addr list eth1 | grep -w inet | awk {'print $2'} | awk -F'/' {'print $1'})
    VPN_TUNNEL_LOCAL_ADDRESS=$(echo -e "$TUNNEL_LOCAL_ADDRESS" | awk -F'/' {'print $1'})

    # Check if the SNAT rule already exists
    EXISTING=$(iptables -t nat -S POSTROUTING | grep -- "-s $VPN_TUNNEL_LOCAL_ADDRESS -o $TUNNEL_NAME -j SNAT --to-source $VPN_SERVER_IP")
    debug_log "[INFO] NAT POSTROUTING SNAT check: $EXISTING for $TUNNEL_NAME"
    
    # If not found, add it
    if [ -z "$EXISTING" ]; then
	    debug_log "[INFO] SNAT rule not found for $TUNNEL_NAME. Adding it."
	    log_and_run iptables -v -t nat -A POSTROUTING -s $VPN_TUNNEL_LOCAL_ADDRESS -o $TUNNEL_NAME -j SNAT --to-source $VPN_SERVER_IP
    else
	    debug_log "[INFO] SNAT rule for $TUNNEL_NAME already exists. Skipping."
    fi

    # ============================================
    # Step 8: Apply TCP MSS Clamping in Mangle Table
    # ============================================
    # Description:
    # - Ensures proper Maximum Segment Size (MSS) for TCP packets.
    # - Prevents packet fragmentation by adjusting the MSS value.
    # - Clamps the MSS to the Path MTU to optimize performance and avoid issues.

    debug_log "[INFO] Attempting to add TCP MSS Clamping for $TUNNEL_NAME"

    # Check if the MSS Clamping rule already exists in the mangle table FORWARD chain
    EXISTING=$(iptables -t mangle -S FORWARD | grep -- "-s $TUNNEL_LOCAL_ROUTE -o $TUNNEL_NAME -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
    debug_log "[INFO] MSS Clamping rule check for $TUNNEL_NAME: $EXISTING"

    # If the rule is not found, add it
    if [ -z "$EXISTING" ]; then
	    debug_log "[INFO] MSS Clamping rule not found for $TUNNEL_NAME. Adding it."
	    log_and_run iptables -v -t mangle -A FORWARD -s $TUNNEL_LOCAL_ROUTE -o "$TUNNEL_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    else
	    debug_log "[INFO] MSS Clamping rule for $TUNNEL_NAME already exists. Skipping."
    fi

     # ============================================
     # Step 9: Apply Mangle Table PREROUTING Rules
     # ============================================
     # Description:
     # - Adds a mangle table PREROUTING rule for traffic coming into the system.
     # - Marks packets with the specified tunnel mark for routing decision.
     debug_log "[INFO] Attempting to add mangle Table PREROUTING chain rules for $TUNNEL_NAME at $(date)"
     EXISTING=$(iptables -t mangle -S PREROUTING | grep -- "-s $TUNNEL_LOCAL_ROUTE -d $TUNNEL_STATIC_ROUTE -j MARK --set-mark $TUNNEL_MARK")
     if [ -z "$EXISTING" ]; then
	debug_log "[INFO] PREROUTING rule for $TUNNEL_MARK not found. Adding it."     
        log_and_run iptables -v -t mangle -A PREROUTING -s $TUNNEL_LOCAL_ROUTE -d $TUNNEL_STATIC_ROUTE -j MARK --set-mark $TUNNEL_MARK
	debug_log "[INFO] PREROUTING rule for $TUNNEL_MARK added successfully."
    else
	debug_log "[INFO] PREROUTING rule for $TUNNEL_MARK already exists. Skipping."
    fi

    # ============================================
    # Step 10: Apply Mangle Table OUTPUT Rules
    # ============================================
    # Description:
    # - Adds a mangle table OUTPUT rule for traffic originating from the server.
    # - Marks packets with the specified tunnel mark for proper routing.
    debug_log "[INFO] Attempting to add mangle Table OUTPUT chain rules for $TUNNEL_NAME at $(date)"
    EXISTING=$(iptables -t mangle -S OUTPUT | grep -- "-s $TUNNEL_LOCAL_ROUTE -d $TUNNEL_STATIC_ROUTE -j MARK --set-mark $TUNNEL_MARK")
    if [ -z "$EXISTING" ]; then
	    debug_log "[INFO] OUTPUT rule for $TUNNEL_MARK not found. Adding it."
	    log_and_run iptables -v -t mangle -A OUTPUT -s $TUNNEL_LOCAL_ROUTE -d $TUNNEL_STATIC_ROUTE -j MARK --set-mark $TUNNEL_MARK
    else
	    debug_log "[INFO] OUTPUT rule for $TUNNEL_MARK already exists. Skipping."
    fi

}    

# ============================================
# Configure sysctl Parameters
# ============================================
# Description:
# - This step configures the necessary sysctl parameters for the tunnel.
# - Enables IP forwarding, adjusts route filtering, and disables policies.
# - Ensures that traffic flows correctly through the VPN tunnel.

configure_sysctl() {
    debug_log "[DEBUG] Attempting to configure sysctl rules for $TUNNEL_NAME"

    # ---------------------------------------------------------
    # Enable IP Forwarding:
    # - Allows the Linux kernel to forward packets between interfaces.
    # - This is essential for traffic to traverse through the tunnel.
    # ---------------------------------------------------------    
    log_and_run sysctl -w net.ipv4.ip_forward=1
    debug_log "[INFO] IP Forwarding enabled for $TUNNEL_NAME"

    # ---------------------------------------------------------
    # Configure Reverse Path Filtering:
    # - Sets reverse path filtering to '2' (loose mode).
    # - This mode allows asymmetric routing, which is common with VPNs.
    # - Ensures that packets are not dropped if they come from unexpected interfaces.
    # ---------------------------------------------------------    
    log_and_run sysctl -w net.ipv4.conf."$TUNNEL_NAME".rp_filter=2
    debug_log "[INFO] Reverse Path Filtering configured for $TUNNEL_NAME"

    # ---------------------------------------------------------
    # Disable Policy Enforcement on the Tunnel Interface:
    # - This prevents the kernel from applying its own routing policies.
    # - Necessary to ensure tunnel traffic follows custom rules.
    # ---------------------------------------------------------
    log_and_run sysctl -w net.ipv4.conf."$TUNNEL_NAME".disable_policy=1
    debug_log "[INFO] Policy enforcement disabled for $TUNNEL_NAME"

    # ---------------------------------------------------------
    # Disable XFRM (IPsec Transformations) and Policy for Pluto Interface:
    # - These settings prevent the Pluto interface from attempting to perform IPsec transformations.
    # - Ensures the tunnel interface is fully responsible for traffic handling.
    # ---------------------------------------------------------
    log_and_run sysctl -w net.ipv4.conf."$PLUTO_INTERFACE".disable_xfrm=1
    log_and_run sysctl -w net.ipv4.conf."$PLUTO_INTERFACE".disable_policy=1
    debug_log "[INFO] XFRM and policy disabled for $PLUTO_INTERFACE"
    
    # ---------------------------------------------------------
    # Completion Log:
    # - Logs that sysctl configurations have been successfully applied.
    # ---------------------------------------------------------
    debug_log "[INFO] sysctl configuration completed for $TUNNEL_NAME at $(date)"
}

# ============================================
# Cleanup Function
# ============================================
# Description:
# - This function is responsible for cleaning up all configurations
#   related to the specified tunnel.
# - It removes routes, IP rules, interface links, and iptables rules.
# - Ensures that when a tunnel goes down, its configurations are
#   completely removed to prevent conflicts and memory leaks.

cleanup() {
    debug_log "[INFO] Starting cleanup for $TUNNEL_NAME"	 

    # ---------------------------------------------------------
    # Step 1: Remove Routes and Interface Links
    # ---------------------------------------------------------
    debug_log "[INFO] Removing routes and interface links for $TUNNEL_NAME"
    log_and_run ip route del "$TUNNEL_STATIC_ROUTE" dev "$TUNNEL_NAME" metric 100 || true
    log_and_run ip link set "$TUNNEL_NAME" down || true
    log_and_run ip link del "$TUNNEL_NAME" || true
    debug_log "[INFO] Routes and interface links removed for $TUNNEL_NAME"

    # ---------------------------------------------------------
    # Step 2: Remove IP Rules
    # ---------------------------------------------------------
    debug_log "[INFO] Removing IP Rule for $TUNNEL_MARK"
    log_and_run ip rule delete from $TUNNEL_LOCAL_ROUTE fwmark $TUNNEL_MARK lookup $ROUTE_TABLE_NAME priority 100
    debug_log "[INFO] IP Rule removed for $TUNNEL_MARK"

    # ---------------------------------------------------------
    # Step 3: Remove FORWARD Chain Rules from Filter Table
    # ---------------------------------------------------------
    debug_log "[INFO] Removing FORWARD Chain rule from Filter Table for $TUNNEL_NAME"
    EXISTING=$(iptables -t filter -S FORWARD | grep -- "-o $TUNNEL_NAME -j ACCEPT")
    if [[ -n "$EXISTING" ]]; then
	    debug_log "[INFO] Found FORWARD Chain rule. Deleting it."
	    log_and_run iptables -v -t filter -D FORWARD -o $TUNNEL_NAME -j ACCEPT
    else
	    debug_log "[INFO] FORWARD Chain rule not found. Skipping."
    fi

    # ---------------------------------------------------------
    # Step 4: Remove NAT Table POSTROUTING RETURN Rules
    # ---------------------------------------------------------
    debug_log "[INFO] Removing POSTROUTING RETURN rule from NAT Table for $TUNNEL_NAME"
    EXISTING=$(iptables -t nat -S POSTROUTING | grep -- "-s $TUNNEL_LOCAL_ROUTE -d $TUNNEL_STATIC_ROUTE -j RETURN")
    if [[ -n "$EXISTING" ]]; then
	    debug_log "[INFO] Found POSTROUTING RETURN rule. Deleting it."
	    log_and_run iptables -v -t nat -D POSTROUTING -s $TUNNEL_LOCAL_ROUTE -d $TUNNEL_STATIC_ROUTE -j RETURN
    else
	    debug_log "[INFO] POSTROUTING RETURN rule not found. Skipping."
    fi

    # ---------------------------------------------------------
    # Step 5: Remove NAT Table POSTROUTING RMASQUERADEules
    # ---------------------------------------------------------
    debug_log "[INFO] Removing POSTROUTING MASQUERADE rule for $TUNNEL_NAME"
    EXISTING=$(iptables -t nat -S POSTROUTING | grep -- "-s $TUNNEL_LOCAL_ROUTE -o $INTERFACE -j MASQUERADE")
    if [[ -n "$EXISTING" ]]; then
	    debug_log "[INFO] Found MASQUERADE rule. Deleting it."
	    log_and_run iptables -v -t nat -D POSTROUTING -s $TUNNEL_LOCAL_ROUTE -o $INTERFACE -j MASQUERADE
    else
	    debug_log "[INFO] MASQUERADE rule not found. Skipping."
    fi

    # ---------------------------------------------------------
    # Step 6: Remove SNAT Rules from NAT Table
    # ---------------------------------------------------------    
    debug_log "[INFO] Removing SNAT rules from NAT Table for $TUNNEL_NAME"
    VPN_SERVER_IP=$(ip addr list eth1 | grep -w inet | awk {'print $2'} | awk -F'/' {'print $1'})
    VPN_TUNNEL_LOCAL_ADDRESS=$(echo -e "$TUNNEL_LOCAL_ADDRESS" | awk -F'/' {'print $1'})
    EXISTING=$(iptables -t nat -S POSTROUTING | grep -- "-s $VPN_TUNNEL_LOCAL_ADDRESS/32 -o $TUNNEL_NAME -j SNAT --to-source $VPN_SERVER_IP")
    if [[ -n "$EXISTING" ]]; then
	    debug_log "[INFO] Found SNAT rule. Deleting it."
	    log_and_run iptables -v -t nat -D POSTROUTING -s $VPN_TUNNEL_LOCAL_ADDRESS/32 -o $TUNNEL_NAME -j SNAT --to-source $VPN_SERVER_IP
    else
	    debug_log "[INFO] SNAT rule not found. Skipping."
    fi

    # ---------------------------------------------------------
    # Step 7: Remove TCP MSS Clamping Rules
    # ---------------------------------------------------------
    debug_log "[INFO] Removing TCP MSS Clamping from Mangle Table for $TUNNEL_NAME"
    EXISTING=$(iptables -t mangle -S FORWARD| grep -- " -s $TUNNEL_LOCAL_ROUTE -o "$TUNNEL_NAME" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
    if [[ -n "$EXISTING" ]]; then
	    debug_log "[INFO] Found MSS Clamping rule. Deleting it."
	    log_and_run iptables -v -t mangle -D FORWARD -s $TUNNEL_LOCAL_ROUTE -o "$TUNNEL_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    else
	    debug_log "[INFO] MSS Clamping rule not found. Skipping."
    fi

    # ---------------------------------------------------------
    # Step 8: Remove Mangle Table OUTPUT Chain Rules
    # ---------------------------------------------------------    
    debug_log "[INFO] Removing OUTPUT Chain rules from Mangle Table for $TUNNEL_NAME"
    TUNNEL_MARK_LOWER=$(echo "$TUNNEL_MARK" | tr '[:upper:]' '[:lower:]')
    EXISTING=$(iptables -t mangle -S OUTPUT | grep -- "-s $TUNNEL_LOCAL_ROUTE -d $TUNNEL_STATIC_ROUTE -j MARK --set-xmark $TUNNEL_MARK_LOWER")
    if [[ -n "$EXISTING" ]]; then
	    debug_log "[INFO] Found OUTPUT chain rule. Deleting it."
	    log_and_run iptables -v -t mangle -D OUTPUT -s $TUNNEL_LOCAL_ROUTE -d $TUNNEL_STATIC_ROUTE -j MARK --set-xmark $TUNNEL_MARK_LOWER
    else
	    debug_log "[INFO] OUTPUT chain rule not found. Skipping."
    fi

    # ---------------------------------------------------------
    # Step 9: Remove Mangle Table PREROUTING Chain Rules
    # ---------------------------------------------------------
    debug_log "[INFO] Removing PREROUTING Chain rules from Mangle Table for $TUNNEL_NAME"
    TUNNEL_MARK_LOWER=$(echo "$TUNNEL_MARK" | tr '[:upper:]' '[:lower:]')
    EXISTING=$(iptables -t mangle -S PREROUTING | grep -- "-s $TUNNEL_LOCAL_ROUTE -d $TUNNEL_STATIC_ROUTE -j MARK --set-xmark $TUNNEL_MARK_LOWER")
     if [[ -n "$EXISTING" ]]; then
	debug_log "[INFO] Found PREROUTING chain rule. Deleting it."     
        log_and_run iptables -v -t mangle -D PREROUTING -s $TUNNEL_LOCAL_ROUTE -d $TUNNEL_STATIC_ROUTE -j MARK --set-xmark $TUNNEL_MARK_LOWER
    else
	debug_log "[INFO] PREROUTING chain rule not found. Skipping."    
    fi

    # ---------------------------------------------------------
    # Step 10: Completion Log
    # ---------------------------------------------------------
    debug_log "[INFO] Cleanup for $TUNNEL_NAME completed at $(date)"
    echo "[INFO] Cleanup for $TUNNEL_NAME finished successfully." | tee -a "$LOG_FILE"    
}

# ============================================
# VPN Tunnel State Handler
# ============================================
# Description:
# - This final step handles the state changes of the VPN tunnel.
# - It listens for `up-client` and `down-client` events from `PLUTO_VERB`.
# - Depending on the event, it triggers the creation or cleanup of the VPN tunnel.
# - This is the entry point that ties the whole script together.

# ---------------------------------------------------------
# Listen for IPsec Events via PLUTO_VERB
# ---------------------------------------------------------
case "$PLUTO_VERB" in
    # -----------------------------------------------------
    # If the VPN tunnel is coming up (up-client)
    # -----------------------------------------------------	
    up-client)
        debug_log "[INFO] Tunnel $TUNNEL_NAME is coming up. Creating interface and configuring sysctl."
        create_interface
        configure_sysctl
        # ============================================
        # Step 11: Update VPN Last Switch Timestamp
        # ============================================
        # Description:
        # - This step records the last time the VPN tunnel switched.
        # - It updates a timestamp to help track failover events.
        # - Uses a locking mechanism to prevent race conditions during file write.
	
        # ---------------------------------------------------------
        # Ensure the directory `/var/run` exists. This directory
        # is used for storing runtime files, including lock files.
        # ---------------------------------------------------------
        if [ ! -d "/var/run" ]; then
            debug_log "[INFO] /var/run directory not found. Creating it."
            mkdir -p /var/run
        else
            debug_log "[INFO] /var/run directory already exists. Skipping creation."
        fi

        # ---------------------------------------------------------
        # Locking Mechanism:
        # - Uses a file-based lock to prevent concurrent writes.
        # - Ensures atomic operation during timestamp update.
        # ---------------------------------------------------------
        exec 200>"$LOCK_FILE"
        flock -n 200 || exit 1

        # ---------------------------------------------------------
        # Write the Tunnel Name and Timestamp:
        # - Writes the active tunnel name and the current Unix timestamp
        #   to the last switch file.
        # ---------------------------------------------------------
        echo "$TUNNEL_NAME $(date +%s)" > "$LAST_SWITCH_FILE"
        debug_log "[INFO] Last switch updated to $TUNNEL_NAME UP at $(date)"

        # ---------------------------------------------------------
        # Release the Lock:
        # - Ensures other processes can access the file if needed.
        # ---------------------------------------------------------
        flock -u 200
        exec 200>&-

	debug_log "[INFO] Tunnel $TUNNEL_NAME setup is complete."
        ;;

    # -----------------------------------------------------
    # If the VPN tunnel is going down (down-client)
    # -----------------------------------------------------
    down-client)
        debug_log "[INFO] Tunnel $TUNNEL_NAME is going down. Starting cleanup process."
        cleanup
        # Lock the file to prevent race conditions
        exec 200>"$LOCK_FILE"
        flock -n 200 || exit 1

        # Log the tunnel as DOWN due to service stop
        echo "SERVICE_DOWN $(date +%s)" > "$LAST_SWITCH_FILE"
        debug_log "[INFO] Tunnel service stopped. Marked SERVICE_DOWN in $LAST_SWITCH_FILE at $(date)"

        # Release the lock
        flock -u 200
        exec 200>&-	
	debug_log "[INFO] Tunnel $TUNNEL_NAME cleanup is complete."
        ;;
    *)
        debug_log "[WARN] Unknown PLUTO_VERB: $PLUTO_VERB. No action taken."
        ;;
esac

    if [ ! -d "/var/run" ]; then
	    debug_log "[INFO] /var/run directory not found. Creating it."
	    mkdir -p /var/run
    else
	    debug_log "[INFO] /var/run directory already exists. Skipping creation."
    fi
