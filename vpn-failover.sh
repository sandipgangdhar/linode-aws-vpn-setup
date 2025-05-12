#!/bin/bash

# ================================
# VPN Failover Monitoring Script
# Author: Sandip Gangdhar <sgangdha@akamai.com>
# Description: This script monitors two VPN tunnels (Tunnel1 and Tunnel2) 
# and switches the active tunnel in case of failure, while ensuring proper 
# routing and IP rules are maintained.
# ================================

# Global Variables
LOG_FILE="/var/log/vpn-failover.log"
DEBUG_MODE=1  # Set to 1 to enable debug logs, 0 to disable
LAST_SWITCH_FILE="/var/run/vpn_last_switch"

# Tunnel Configuration
PRIMARY_TUNNEL="Tunnel2"
SECONDARY_TUNNEL="Tunnel1"
PRIMARY_IP="169.254.91.58"
SECONDARY_IP="169.254.211.190"
ROUTE_TABLE_NAME="customvpn"
MARK_PRIMARY="0xc8"
MARK_SECONDARY="0x64"

# Network Configuration
PING_IP="10.0.4.85"
SUBNET_LOCAL="172.16.0.0/12"
SUBNET_REMOTE="10.0.0.0/16"
VPN_SERVER_IP="172.16.0.2"
SLEEP_TIME=5
POLL_INTERVAL=60  # 60 seconds for monitoring

# ================================
# Logging Functions
# ================================

log_and_run() {
    if [[ $DEBUG_MODE -eq 1 ]]; then
        echo "=== Running Command: $* at $(date) ===" | tee -a "$LOG_FILE"
        eval "$@" 2>&1 | tee -a "$LOG_FILE"
    else
        eval "$@" >> "$LOG_FILE" 2>&1
    fi
}

debug_log() {
    if [[ $DEBUG_MODE -eq 1 ]]; then
        echo "[DEBUG] $1" | tee -a "$LOG_FILE" >&2
    fi
}

log_and_run "echo Starting VPN failover monitoring script..."

# Function to Check Tunnel Status from $LAST_SWITCH_FILE
check_tunnel_status() {
    if [ -f "$LAST_SWITCH_FILE" ]; then
        local status
        local tunnel_state
        local last_switch_time
        local current_time

        # Grace period to allow full initialization (e.g., 120 seconds)
        local grace_period=120

        while true; do
            status=$(cat "$LAST_SWITCH_FILE")
            current_time=$(date +%s)

            # Extract status and timestamp
            tunnel_state=$(echo "$status" | awk '{print $1}')
            last_switch_time=$(echo "$status" | awk '{print $2}')

            # Case 1: If the service is down, log it and skip further checks
            if [[ "$tunnel_state" == "SERVICE_DOWN" ]]; then
                debug_log "[INFO] IPsec service is stopped. Skipping failover checks."
                return 1
            fi

            # Case 2: If the grace period has not passed yet, wait
            if (( current_time - last_switch_time < grace_period )); then
                local remaining=$((grace_period - (current_time - last_switch_time)))
                debug_log "[INFO] Tunnel $tunnel_state is still initializing. Waiting $remaining seconds."
                sleep 5  # Check every 5 seconds
            else
                # Case 3: Tunnel is marked active and the grace period has passed
                debug_log "[INFO] Tunnel $tunnel_state is marked as active. Proceeding with checks."
                return 0
            fi
        done
    else
        debug_log "[ERROR] $LAST_SWITCH_FILE not found. Skipping checks."
        return 1
    fi
}

# ================================
# Route and Rule Management Functions
# ================================

route_exists() {
    local subnet="$1"
    local dev="$2"
    local gw="$3"
    debug_log "Checking if route exists for $subnet via $gw on $dev"
    ip route show table $ROUTE_TABLE_NAME | grep -q "$subnet via $gw dev $dev"
}

add_route() {
    local subnet="$1"
    local dev="$2"
    local gw="$3"
    local metric="$4"

    debug_log "Attempting to add route: $subnet via $gw dev $dev"
    if ! route_exists "$subnet" "$dev" "$gw"; then
        debug_log "Route not found. Adding: $subnet via $gw dev $dev"
        log_and_run ip route add $subnet via $gw dev $dev table $ROUTE_TABLE_NAME metric $metric
    else
        debug_log "Route already exists: $subnet via $gw dev $dev. Skipping."
    fi
}

delete_route() {
    local subnet="$1"
    local dev="$2"
    local gw="$3"

    debug_log "Attempting to delete route: $subnet via $gw dev $dev"
    if route_exists "$subnet" "$dev" "$gw"; then
        debug_log "Route found. Deleting: $subnet via $gw dev $dev"
        log_and_run ip route del $subnet via $gw dev $dev table $ROUTE_TABLE_NAME
    else
        debug_log "Route not found: $subnet via $gw dev $dev. Skipping deletion."
    fi
}

rule_exists() {
    local mark="$1"
    debug_log "Checking if IP rule exists for mark $mark"
    ip rule show | grep -q "fwmark $mark lookup $ROUTE_TABLE_NAME"
}

add_rule() {
    local subnet="$1"
    local mark="$2"
    debug_log "Attempting to add IP rule: from $subnet fwmark $mark"
    if ! rule_exists "$mark"; then
        debug_log "IP rule not found. Adding: from $subnet fwmark $mark"
        log_and_run ip rule add from $subnet fwmark $mark lookup $ROUTE_TABLE_NAME priority 100
    else
        debug_log "IP rule already exists: from $subnet fwmark $mark. Skipping."
    fi
}

delete_rule() {
    local subnet="$1"
    local mark="$2"
    debug_log "Attempting to delete IP rule: from $subnet fwmark $mark"
    if rule_exists "$mark"; then
        debug_log "IP rule found. Deleting: from $subnet fwmark $mark"
        log_and_run ip rule del from $subnet fwmark $mark lookup $ROUTE_TABLE_NAME
    else
        debug_log "IP rule not found: from $subnet fwmark $mark. Skipping deletion."
    fi
}

# ================================
# IPTables Management Functions
# ================================

# Function to add static rules if not present
static_iptables_rules() {
    debug_log "[INFO] Ensuring static iptables rules are present"

    # Filter Table
    EXISTING=$(iptables -t filter -S FORWARD | grep -- "-o Tunnel1 -j ACCEPT")
    if [ -z "$EXISTING" ]; then
        debug_log "[INFO] Adding static rule for Tunnel1 in filter table FORWARD chain"
        log_and_run iptables -t filter -A FORWARD -o Tunnel1 -j ACCEPT
    else
        debug_log "[INFO] Static rule for Tunnel1 in filter table FORWARD chain already exists."
    fi

    EXISTING=$(iptables -t filter -S FORWARD | grep -- "-o Tunnel2 -j ACCEPT")
    if [ -z "$EXISTING" ]; then
        debug_log "[INFO] Adding static rule for Tunnel2 in filter table FORWARD chain"
        log_and_run iptables -t filter -A FORWARD -o Tunnel2 -j ACCEPT
    else
        debug_log "[INFO] Static rule for Tunnel2 in filter table FORWARD chain already exists."
    fi

    # NAT Table
    EXISTING=$(iptables -t nat -S POSTROUTING | grep -- "-s $SUBNET_LOCAL -d $SUBNET_REMOTE -j RETURN")
    if [ -z "$EXISTING" ]; then
        debug_log "[INFO] Adding NAT RETURN rule for subnet $SUBNET_LOCAL"
        log_and_run iptables -t nat -I POSTROUTING 1 -s $SUBNET_LOCAL -d $SUBNET_REMOTE -j RETURN
    else
        debug_log "[INFO] NAT RETURN rule already exists for $SUBNET_LOCAL"
    fi

    EXISTING=$(iptables -t nat -S POSTROUTING | grep -- "-s $SUBNET_LOCAL -o eth0 -j MASQUERADE")
    if [ -z "$EXISTING" ]; then
        debug_log "[INFO] Adding NAT MASQUERADE rule for eth0"
        log_and_run iptables -t nat -A POSTROUTING -s $SUBNET_LOCAL -o eth0 -j MASQUERADE
    else
        debug_log "[INFO] NAT MASQUERADE rule for eth0 already exists."
    fi

    # SNAT Rules
    EXISTING=$(iptables -t nat -S POSTROUTING | grep -- "-s ${PRIMARY_IP}/32 -o Tunnel2 -j SNAT --to-source $VPN_SERVER_IP")
    if [ -z "$EXISTING" ]; then
        debug_log "[INFO] Adding SNAT rule for Tunnel2"
        log_and_run iptables -t nat -A POSTROUTING -s $PRIMARY_IP -o Tunnel2 -j SNAT --to-source $VPN_SERVER_IP
    else
        debug_log "[INFO] SNAT rule for Tunnel2 already exists."
    fi
    ]
    EXISTING=$(iptables -t nat -S POSTROUTING | grep -- "-s ${SECONDARY_IP}/32 -o Tunnel1 -j SNAT --to-source $VPN_SERVER_IP")
    if [ -z "$EXISTING" ]; then
        debug_log "[INFO] Adding SNAT rule for Tunnel1"
        log_and_run iptables -t nat -A POSTROUTING -s $SECONDARY_IP -o Tunnel1 -j SNAT --to-source $VPN_SERVER_IP
    else
        debug_log "[INFO] SNAT rule for Tunnel1 already exists."
    fi
    
    # Mangle Table - MSS Clamping Rules
    debug_log "[INFO] Setting up Mangle Table Rules for MSS Clamping"
    
    # Tunnel1 MSS Clamping Rule
    EXISTING=$(iptables -t mangle -S FORWARD | grep -- "-s $SUBNET_LOCAL -o Tunnel1 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
    debug_log "[DEBUG] the EXISTING variable output from Mangle Table FORWARD Chain for Tunnel1 MSS Clamping: $EXISTING at $(date)" | tee -a "$LOG_FILE"
    if [ -z "$EXISTING" ]; then
        debug_log "[INFO] MSS Clamping Rule for Tunnel1 not found. Adding it." | tee -a "$LOG_FILE"
        log_and_run iptables -v -t mangle -A FORWARD -s $SUBNET_LOCAL -o Tunnel1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    else
        debug_log "[INFO] MSS Clamping Rule for Tunnel1 already exists. Skipping." | tee -a "$LOG_FILE"
    fi
    
    # Tunnel2 MSS Clamping Rule
    EXISTING=$(iptables -t mangle -S FORWARD | grep -- "-s $SUBNET_LOCAL -o Tunnel2 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
    debug_log "[DEBUG] the EXISTING variable output from Mangle Table FORWARD Chain for Tunnel2 MSS Clamping: $EXISTING at $(date)" | tee -a "$LOG_FILE"
    if [ -z "$EXISTING" ]; then
        debug_log "[INFO] MSS Clamping Rule for Tunnel2 not found. Adding it." | tee -a "$LOG_FILE"
        log_and_run iptables -v -t mangle -A FORWARD -s $SUBNET_LOCAL -o Tunnel2 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    else
        debug_log "[INFO] MSS Clamping Rule for Tunnel2 already exists. Skipping." | tee -a "$LOG_FILE"
    fi
}

# Apply Mangle Rules Based on Active Tunnel
apply_dynamic_iptables() {
    local active_tunnel="$1"

    debug_log "[INFO] Applying Dynamic Mangle Rules for Active Tunnel: $active_tunnel"

    # Define MARK values based on the active tunnel
    if [[ "$active_tunnel" == "$PRIMARY_TUNNEL" ]]; then
        MARK_ACTIVE="$MARK_PRIMARY"
        MARK_INACTIVE="$MARK_SECONDARY"
    else
        MARK_ACTIVE="$MARK_SECONDARY"
        MARK_INACTIVE="$MARK_PRIMARY"
    fi

    # PREROUTING Chain from Mangle table
    # Remove unwanted rule for inactive tunnel if present
    EXISTING=$(iptables -t mangle -S PREROUTING | grep -- "-s $SUBNET_LOCAL -d $SUBNET_REMOTE -j MARK --set-xmark $MARK_INACTIVE")
    debug_log "[DEBUG] Existing PREROUTING rule for inactive tunnel: $EXISTING"
    if [[ -n "$EXISTING" ]]; then
        debug_log "[INFO] Removing PREROUTING rule for inactive tunnel mark $MARK_INACTIVE"
        log_and_run iptables -t mangle -D PREROUTING -s $SUBNET_LOCAL -d $SUBNET_REMOTE -j MARK --set-mark $MARK_INACTIVE
    else
        debug_log "[INFO] No PREROUTING rule found for inactive tunnel. Skipping removal."
    fi

    # Add the rule for the active tunnel if it doesn't exist
    EXISTING=$(iptables -t mangle -S PREROUTING | grep -- "-s $SUBNET_LOCAL -d $SUBNET_REMOTE -j MARK --set-xmark $MARK_ACTIVE")
    debug_log "[DEBUG] Existing PREROUTING rule for active tunnel: $EXISTING"
    if [[ -z "$EXISTING" ]]; then
        debug_log "[INFO] Adding PREROUTING rule for active tunnel mark $MARK_ACTIVE"
        log_and_run iptables -v -t mangle -A PREROUTING -s $SUBNET_LOCAL -d $SUBNET_REMOTE -j MARK --set-mark $MARK_ACTIVE
    else
        debug_log "[INFO] PREROUTING rule for active tunnel already exists. Skipping."
    fi

    # OUTPUT Chain from Mangle table
    # Remove unwanted rule for inactive tunnel if present
    EXISTING=$(iptables -t mangle -S OUTPUT | grep -- "-s $SUBNET_LOCAL -d $SUBNET_REMOTE -j MARK --set-xmark $MARK_INACTIVE")
    debug_log "[DEBUG] Existing OUTPUT rule for inactive tunnel: $EXISTING"
    if [[ -n "$EXISTING" ]]; then
        debug_log "[INFO] Removing OUTPUT rule for inactive tunnel mark $MARK_INACTIVE"
        log_and_run iptables -t mangle -D OUTPUT -s $SUBNET_LOCAL -d $SUBNET_REMOTE -j MARK --set-mark $MARK_INACTIVE
    else
        debug_log "[INFO] No OUTPUT rule found for inactive tunnel. Skipping removal."
    fi

    # Add the rule for the active tunnel if it doesn't exist
    EXISTING=$(iptables -t mangle -S OUTPUT | grep -- "-s $SUBNET_LOCAL -d $SUBNET_REMOTE -j MARK --set-xmark $MARK_ACTIVE")
    debug_log "[DEBUG] Existing OUTPUT rule for active tunnel: $EXISTING"
    if [[ -z "$EXISTING" ]]; then
        debug_log "[INFO] Adding OUTPUT rule for active tunnel mark $MARK_ACTIVE"
        log_and_run iptables -v -t mangle -A OUTPUT -s $SUBNET_LOCAL -d $SUBNET_REMOTE -j MARK --set-mark $MARK_ACTIVE
    else
        debug_log "[INFO] OUTPUT rule for active tunnel already exists. Skipping."
    fi
}

# ================================
# Tunnel Monitoring Logic
# ================================

get_active_tunnel() {
    # Ensuring Tunnel is fully initialized before starting the ping test
    debug_log "[INFO] Checking tunnel status from $LAST_SWITCH_FILE"
    if ! check_tunnel_status; then
	    debug_log "[INFO] Tunnel is either down or still initializing. Skipping ping checks."

	    # Wait for the specified poll interval before re-checking
	    sleep $POLL_INTERVAL

	    # Skip the rest of the current loop and start the next iteration
	    #continue
	    return 1
    fi

    debug_log "Pinging $PING_IP via $PRIMARY_TUNNEL"
    if ping -I $PRIMARY_TUNNEL -c 3 $PING_IP &>/dev/null; then
        debug_log "$PRIMARY_TUNNEL is ACTIVE."
        echo -n "$PRIMARY_TUNNEL"
    else
        debug_log "$PRIMARY_TUNNEL is DOWN. Pinging $SECONDARY_TUNNEL..."

        delete_route "$SUBNET_REMOTE" "$PRIMARY_TUNNEL" "$PRIMARY_IP" 
        delete_rule "$SUBNET_LOCAL" "$MARK_PRIMARY"

        add_route "$SUBNET_REMOTE" "$SECONDARY_TUNNEL" "$SECONDARY_IP" 100
        add_rule "$SUBNET_LOCAL" "$MARK_SECONDARY"

        # Ensure static rules are always present
        static_iptables_rules

	debug_log "[DEBUG] $SECONDARY_TUNNEL Tunnel is active. Ensuring proper mangle rules."
	apply_dynamic_iptables "$SECONDARY_TUNNEL"

        debug_log "Waiting for $SLEEP_TIME seconds for the tunnel to come up..."
        sleep $SLEEP_TIME

        if ping -I $SECONDARY_TUNNEL -c 3 $PING_IP &>/dev/null; then
            debug_log "$SECONDARY_TUNNEL is ACTIVE."
            echo -n "$SECONDARY_TUNNEL" 
	    # SWAP TUNNEL VARIABLES
	    debug_log "[INFO] Swapping tunnel roles. $SECONDARY_TUNNEL becomes primary."
	    TEMP_TUNNEL=$PRIMARY_TUNNEL
	    TEMP_IP=$PRIMARY_IP
	    TEMP_MARK=$MARK_PRIMARY
	    
	    PRIMARY_TUNNEL=$SECONDARY_TUNNEL
	    PRIMARY_IP=$SECONDARY_IP
	    MARK_PRIMARY=$MARK_SECONDARY
	    
	    SECONDARY_TUNNEL=$TEMP_TUNNEL
	    SECONDARY_IP=$TEMP_IP
	    MARK_SECONDARY=$TEMP_MARK   
	    echo "$PRIMARY_TUNNEL"	    
        else
            debug_log "Both tunnels are DOWN. Exiting failover script."
            exit 1
        fi
    fi
}

# ================================
# Monitoring Logic
# ================================
while true; do
    debug_log "Starting VPN failover and monitoring loop..."
    active_tunnel_tmp=$(get_active_tunnel)
    # If no tunnel is detected, skip processing
    if [[ -z "$active_tunnel_tmp" ]]; then
        debug_log "[ERROR] No active tunnel detected. Skipping iptables processing."
        sleep $POLL_INTERVAL
        continue
    fi
    active_tunnel=$(echo "$active_tunnel_tmp" | xargs)
    debug_log "[INFO] Active Tunnel Detected: $active_tunnel"

    # Ensure static rules are always present
    static_iptables_rules

    # Only one block is enough since PRIMARY_TUNNEL is always up-to-date
    if [[ "$active_tunnel" == "$PRIMARY_TUNNEL" ]]; then
        debug_log "[DEBUG] $PRIMARY_TUNNEL is active. Ensuring proper routes and rules."
        add_route "$SUBNET_REMOTE" "$PRIMARY_TUNNEL" "$PRIMARY_IP" 100
        add_rule "$SUBNET_LOCAL" "$MARK_PRIMARY"
        delete_route "$SUBNET_REMOTE" "$SECONDARY_TUNNEL" "$SECONDARY_IP"
        delete_rule "$SUBNET_LOCAL" "$MARK_SECONDARY"
	debug_log "[DEBUG] $PRIMARY_TUNNEL Tunnel is active. Ensuring proper mangle rules."
	apply_dynamic_iptables "$PRIMARY_TUNNEL"
    fi

    debug_log "Sleeping for $POLL_INTERVAL seconds before next check..."
    sleep $POLL_INTERVAL
done
