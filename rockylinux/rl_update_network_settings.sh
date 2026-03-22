#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; [[ -z "$RL_LIB_LOADED" ]] && source "$SCRIPT_DIR/rl_lib.sh"

function list_network_interfaces() {
    echo ""
    echo -e "${Bold}Available Network Interfaces${Reset}"
    echo -e "${Dim}$(printf '─%.0s' $(seq 1 70))${Reset}"
    printf "  ${Cyan}%-12s${Reset} %-18s %-6s %-8s %s\n" "INTERFACE" "MAC ADDRESS" "MTU" "STATE" "IP ADDRESS"
    echo -e "${Dim}$(printf '─%.0s' $(seq 1 70))${Reset}"

    local interfaces=($(get_interfaces_array))

    for iface in "${interfaces[@]}"; do
        # Skip bond slaves
        [[ -d "/sys/class/net/$iface/master" ]] && continue

        local mac=$(cat /sys/class/net/$iface/address 2>/dev/null || echo "N/A")
        local mtu=$(cat /sys/class/net/$iface/mtu 2>/dev/null || echo "N/A")
        local state=$(cat /sys/class/net/$iface/operstate 2>/dev/null || echo "N/A")
        local ipv4=$(ip -4 addr show $iface 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | head -1)
        [[ -z "$ipv4" ]] && ipv4="-"

        # Color state
        local state_color="$Red"
        [[ "$state" == "up" ]] && state_color="$Green"

        printf "  %-12s %-18s %-6s ${state_color}%-8s${Reset} %s\n" "$iface" "$mac" "$mtu" "$state" "$ipv4"
    done
    echo ""
}

function get_interfaces_array() {
    ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | grep -v '^docker' | grep -v '^br-' | sed 's/@.*//'
}

# Calculate default gateway (last usable IP in subnet)
function calculate_default_gateway() {
    local ip="$1"
    local cidr="$2"

    IFS=. read -r i1 i2 i3 i4 <<< "$ip"
    local ip_dec=$((i1 * 256**3 + i2 * 256**2 + i3 * 256 + i4))
    local mask_dec=$(( (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF ))
    local broadcast_dec=$(( (ip_dec & mask_dec) | (~mask_dec & 0xFFFFFFFF) ))
    local gateway_dec=$((broadcast_dec - 1))
    echo "$((gateway_dec >> 24 & 0xFF)).$((gateway_dec >> 16 & 0xFF)).$((gateway_dec >> 8 & 0xFF)).$((gateway_dec & 0xFF))"
}

# Prompt user for IP configuration (DHCP or Static)
function select_ip_config() {
    local iface="$1"
    local current_ip=""
    local current_cidr=""

    # Get current IP address if interface is provided
    if [[ -n "$iface" ]]; then
        local cfg_file="/etc/sysconfig/network-scripts/ifcfg-$iface"

        # First check saved configuration file
        if [[ -f "$cfg_file" ]]; then
            local saved_ip=$(grep -E '^IPADDR=' "$cfg_file" | cut -d'=' -f2 | tr -d '"')
            local saved_prefix=$(grep -E '^PREFIX=' "$cfg_file" | cut -d'=' -f2 | tr -d '"')

            if [[ -n "$saved_ip" ]]; then
                if [[ -n "$saved_prefix" ]]; then
                    current_ip="${saved_ip}/${saved_prefix}"
                else
                    current_ip="$saved_ip"
                fi
                current_cidr="$current_ip"
            fi
        fi

        # Fallback to runtime configuration if not in config file
        if [[ -z "$current_ip" ]]; then
            current_cidr=$(ip -4 addr show $iface 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | head -1)
            current_ip="$current_cidr"
        fi
    fi

    local ip_options=("DHCP" "Static IP")
    show_menu "IPv4 Configuration" 1 "${ip_options[@]}"

    bootproto="dhcp"
    ipaddr=""
    netmask=""
    gateway=""
    dns1=""
    dns2=""
    defroute="yes"

    if [[ "$menu_index" == "1" ]]; then
        bootproto="none"

        while true; do
            local ip_prompt="  IP address (e.g., 192.168.1.100/24)"
            [[ -n "$current_ip" ]] && ip_prompt+=" [$current_ip]"
            ip_prompt+=": "
            read -p "$ip_prompt" ip_input

            [[ -z "$ip_input" && -n "$current_ip" ]] && ip_input="$current_ip"

            if [[ "$ip_input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]{1,2})$ ]]; then
                ipaddr="${ip_input%/*}"
                local cidr="${ip_input#*/}"
                case $cidr in
                    8)  netmask="255.0.0.0";;
                    16) netmask="255.255.0.0";;
                    17) netmask="255.255.128.0";;
                    18) netmask="255.255.192.0";;
                    19) netmask="255.255.224.0";;
                    20) netmask="255.255.240.0";;
                    21) netmask="255.255.248.0";;
                    22) netmask="255.255.252.0";;
                    23) netmask="255.255.254.0";;
                    24) netmask="255.255.255.0";;
                    25) netmask="255.255.255.128";;
                    26) netmask="255.255.255.192";;
                    27) netmask="255.255.255.224";;
                    28) netmask="255.255.255.240";;
                    29) netmask="255.255.255.248";;
                    30) netmask="255.255.255.252";;
                    31) netmask="255.255.255.254";;
                    32) netmask="255.255.255.255";;
                    *)  print_warn "Unsupported CIDR: /$cidr"; continue;;
                esac
                print_ok "Netmask: $netmask (CIDR /$cidr)"
                break
            elif [[ "$ip_input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                ipaddr="$ip_input"
                break
            else
                print_warn "Invalid IP address format"
            fi
        done

        if [[ -z "$netmask" ]]; then
            while true; do
                read -p "  Netmask [255.255.255.0]: " netmask
                [[ -z "$netmask" ]] && netmask="255.255.255.0"
                [[ "$netmask" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && break
                print_warn "Invalid netmask format"
            done
        fi

        # Calculate default gateway (last usable IP in subnet)
        local default_gateway=""
        if [[ -n "$cidr" ]] && [[ "$cidr" =~ ^[0-9]+$ ]]; then
            default_gateway=$(calculate_default_gateway "$ipaddr" "$cidr")
        fi

        local gateway_prompt="  Gateway"
        if [[ -n "$default_gateway" ]]; then
            gateway_prompt+=" [$default_gateway] (- for none): "
        else
            gateway_prompt+=" (blank for none): "
        fi
        read -p "$gateway_prompt" gateway

        # Handle explicit "no gateway" with "-"
        if [[ "$gateway" == "-" ]]; then
            gateway=""
        # Use calculated default if user pressed enter
        elif [[ -z "$gateway" && -n "$default_gateway" ]]; then
            gateway="$default_gateway"
        fi

        if [[ -n "$gateway" ]]; then
            local dns_prompt="  Primary DNS [$gateway] (- for none): "
            read -p "$dns_prompt" dns1

            # Handle explicit "no DNS" with "-"
            if [[ "$dns1" == "-" ]]; then
                dns1=""
            elif [[ -z "$dns1" ]]; then
                dns1="$gateway"
            fi

            read -p "  Secondary DNS (blank for none): " dns2
        else
            dns1=""
            dns2=""
            defroute="no"
            print_info "No gateway - DNS skipped, default route disabled"
        fi
    fi

    if [[ -n "$gateway" ]]; then
        read -p "  Use as default route? [Y/n]: " use_defroute
        [[ "$use_defroute" =~ ^[Nn]$ ]] && defroute="no"
    fi
}

# Configure a single network interface using NetworkManager
function configure_interface() {
    echo ""
    echo -e "${Bold}Configure Network Interface${Reset}"

    local all_interfaces=($(get_interfaces_array))
    local interfaces=()

    for iface in "${all_interfaces[@]}"; do
        [[ ! -d "/sys/class/net/$iface/master" ]] && interfaces+=("$iface")
    done

    if [[ ${#interfaces[@]} -eq 0 ]]; then
        print_warn "No network interfaces found"
        return
    fi

    interfaces+=("Return to network menu")
    show_menu "Select interface" ${#interfaces[@]} "${interfaces[@]}"

    if [[ $menu_index -eq $((${#interfaces[@]} - 1)) ]]; then
        return
    fi

    local selected_iface="${interfaces[$menu_index]}"
    local current_mtu=$(cat /sys/class/net/$selected_iface/mtu 2>/dev/null || echo "1500")
    local mac_addr=$(cat /sys/class/net/$selected_iface/address 2>/dev/null)
    local conn_name="$selected_iface"
    local new_iface_name="$selected_iface"
    local rename_required=false

    local existing_conn=$(nmcli -t -f NAME,DEVICE connection show | grep ":$selected_iface$" | cut -d: -f1 | head -1)
    [[ -n "$existing_conn" ]] && conn_name="$existing_conn"

    while true; do
        echo ""
        print_info "Configuring: $selected_iface (MAC: $mac_addr)"

        # Ask for new interface name (optional)
        if [[ ! "$selected_iface" =~ \. ]] && [[ ! "$selected_iface" =~ ^bond ]] && [[ ! -d "/sys/class/net/$selected_iface/master" ]]; then
            echo ""
            read -p "  New interface name (leave blank to keep '$selected_iface'): " new_iface_name

            if [[ -n "$new_iface_name" ]] && [[ "$new_iface_name" != "$selected_iface" ]]; then
                # Validate new interface name
                if [[ ! "$new_iface_name" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
                    print_warn "Invalid interface name (must start with letter, contain only alphanumeric, _, -)"
                    continue
                fi

                if ip link show "$new_iface_name" &>/dev/null; then
                    print_warn "Interface $new_iface_name already exists"
                    continue
                fi

                rename_required=true
                print_ok "Will rename interface: $selected_iface → $new_iface_name"
            else
                new_iface_name="$selected_iface"
                rename_required=false
            fi
        fi

        read -p "  MTU [$current_mtu]: " new_mtu
        [[ -z "$new_mtu" ]] && new_mtu="$current_mtu"

        if ! [[ "$new_mtu" =~ ^[0-9]+$ ]] || (( new_mtu < 576 || new_mtu > 9000 )); then
            print_warn "Invalid MTU (576-9000)"
            continue
        fi

        select_ip_config "$selected_iface"

        # Show summary
        local summary_items=()
        if [[ "$rename_required" == true ]]; then
            summary_items+=("Interface:     $selected_iface → $new_iface_name")
        else
            summary_items+=("Interface:     $selected_iface")
        fi
        summary_items+=(
            "MTU:           $new_mtu"
            "Boot Protocol: $bootproto"
        )
        [[ "$bootproto" == "none" ]] && summary_items+=(
            "IP Address:    $ipaddr"
            "Netmask:       $netmask"
        )
        [[ -n "$gateway" ]] && summary_items+=("Gateway:       $gateway")
        [[ -n "$dns1" ]] && summary_items+=("DNS1:          $dns1")
        [[ -n "$dns2" ]] && summary_items+=("DNS2:          $dns2")
        summary_items+=("Default Route: $defroute")
        summary_items+=("IPv6:          disabled")

        print_summary "Interface Configuration" "${summary_items[@]}"

        echo ""
        read -p "  Apply configuration? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            break
        else
            read -p "  Return to network menu? [y/N]: " return_menu
            [[ "$return_menu" =~ ^[Yy]$ ]] && return
        fi
    done

    local default_iface=$(ip route show default 2>/dev/null | awk '{print $5}' | head -1)
    local is_default_route="N"
    [[ "$selected_iface" == "$default_iface" ]] && is_default_route="Y"

    if [[ "$rename_required" == true ]]; then
        # Create udev rule for persistent naming
        local udev_rule="/etc/udev/rules.d/75-persistent-net-${new_iface_name}.rules"
        cat > "$udev_rule" <<EOF
# Generated by rocky-setup.sh on $(date)
# Rename $selected_iface to $new_iface_name based on MAC address
SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="$mac_addr", NAME="$new_iface_name"
EOF
        chmod 644 "$udev_rule"
        print_ok "Udev rule created for interface rename"
    fi

    local prefix=""
    local ipv4_addr=""
    local dns_servers=""
    if [[ "$bootproto" != "dhcp" ]]; then
        prefix=$(netmask_to_cidr "$netmask")
        ipv4_addr="${ipaddr}/${prefix}"
        dns_servers="$dns1"
        [[ -n "$dns2" ]] && dns_servers="$dns1 $dns2"
    fi

    local final_conn_name="$selected_iface"
    local final_iface_name="$selected_iface"
    if [[ "$rename_required" == true ]]; then
        final_conn_name="$new_iface_name"
        final_iface_name="$new_iface_name"
    fi

    local nm_cmd_base="ipv6.method disabled 802-3-ethernet.mtu $new_mtu connection.autoconnect yes"
    local nm_cmd_ip=""

    if [[ "$bootproto" == "dhcp" ]]; then
        nm_cmd_ip="ipv4.method auto ipv4.addresses \"\" ipv4.gateway \"\" ipv4.dns \"\" ipv4.never-default \"\""
    else
        nm_cmd_ip="ipv4.method manual ipv4.addresses $ipv4_addr ipv4.gateway \"$gateway\" ipv4.dns \"$dns_servers\""
        [[ -z "$gateway" ]] && nm_cmd_ip+=" ipv4.never-default yes" || nm_cmd_ip+=" ipv4.never-default \"\""
    fi

    if [[ -n "$existing_conn" ]]; then
        if [[ "$rename_required" == true ]]; then
            eval nmcli connection modify \"$existing_conn\" connection.id \"$final_conn_name\" connection.interface-name \"\" 802-3-ethernet.mac-address \"$mac_addr\" $nm_cmd_ip $nm_cmd_base &>/dev/null
        else
            eval nmcli connection modify \"$existing_conn\" $nm_cmd_ip $nm_cmd_base &>/dev/null
        fi
        print_ok "Connection modified: $existing_conn → $final_conn_name"
    else
        if [[ "$rename_required" == true ]]; then
            eval nmcli connection add type ethernet con-name \"$final_conn_name\" 802-3-ethernet.mac-address \"$mac_addr\" $nm_cmd_ip $nm_cmd_base &>/dev/null
        else
            eval nmcli connection add type ethernet con-name \"$final_conn_name\" ifname \"$final_iface_name\" $nm_cmd_ip $nm_cmd_base &>/dev/null
        fi
        print_ok "Connection created: $final_conn_name"
    fi

    if [[ "$is_default_route" == "Y" ]] || [[ "$rename_required" == true ]]; then
        echo ""
        if [[ "$rename_required" == true ]]; then
            print_warn "Interface rename requires reboot"
        fi
        if [[ "$is_default_route" == "Y" ]]; then
            print_warn "This is the default route interface (SSH connection)"
        fi
        print_warn "Reboot required to apply changes safely"
        echo ""
        if [[ "$bootproto" == "dhcp" ]]; then
            print_info "New configuration: DHCP (IP will be assigned on boot)"
        else
            print_info "New IP address: $ipaddr"
        fi
        if [[ "$rename_required" == true ]]; then
            print_info "Interface will be renamed to: $new_iface_name"
        fi
        echo ""
        read -p "  Reboot now to apply changes? [y/N]: " reboot_confirm
        if [[ "$reboot_confirm" =~ ^[Yy]$ ]]; then
            print_info "Rebooting in 5 seconds..."
            sleep 5
            reboot
        else
            print_info "Please reboot manually to apply network changes"
        fi
    else
        # Not default route - safe to down/up immediately
        local conn_to_activate="${existing_conn:-$selected_iface}"
        nmcli connection down "$conn_to_activate" &>/dev/null
        nmcli connection up "$conn_to_activate" &>/dev/null
        print_ok "Connection activated: $conn_to_activate"
    fi
}

# Convert netmask to CIDR prefix
function netmask_to_cidr() {
    local netmask="$1"
    local cidr=0
    IFS=. read -r i1 i2 i3 i4 <<< "$netmask"
    local mask_dec=$((i1 * 256**3 + i2 * 256**2 + i3 * 256 + i4))

    while [[ $mask_dec -gt 0 ]]; do
        ((cidr++))
        mask_dec=$((mask_dec << 1 & 0xFFFFFFFF))
    done

    echo "$cidr"
}

# Rename network interface
function rename_interface() {
    echo ""
    echo -e "${Bold}Rename Network Interface${Reset}"

    local all_interfaces=($(get_interfaces_array))
    local interfaces=()

    for iface in "${all_interfaces[@]}"; do
        [[ ! -d "/sys/class/net/$iface/master" ]] && [[ ! "$iface" =~ \. ]] && [[ ! "$iface" =~ ^bond ]] && interfaces+=("$iface")
    done

    if [[ ${#interfaces[@]} -eq 0 ]]; then
        print_warn "No renameable interfaces found"
        return
    fi

    interfaces+=("Return to network menu")
    show_menu "Select interface to rename" ${#interfaces[@]} "${interfaces[@]}"

    if [[ $menu_index -eq $((${#interfaces[@]} - 1)) ]]; then
        return
    fi

    local selected_iface="${interfaces[$menu_index]}"
    local mac_addr=$(cat /sys/class/net/$selected_iface/address 2>/dev/null)

    echo ""
    print_info "Current interface: $selected_iface (MAC: $mac_addr)"

    while true; do
        read -p "  New interface name: " new_name

        if [[ -z "$new_name" ]]; then
            print_warn "Interface name cannot be empty"
            continue
        fi

        if [[ "$new_name" == "$selected_iface" ]]; then
            print_warn "New name is the same as current name"
            return
        fi

        if [[ ! "$new_name" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
            print_warn "Invalid interface name (must start with letter, contain only alphanumeric, _, -)"
            continue
        fi

        if ip link show "$new_name" &>/dev/null; then
            print_warn "Interface $new_name already exists"
            continue
        fi

        break
    done

    echo ""
    print_info "Renaming: $selected_iface → $new_name"
    read -p "  Proceed with rename? [y/N]: " confirm

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        return
    fi

    local udev_rule="/etc/udev/rules.d/70-persistent-net-${new_name}.rules"
    cat > "$udev_rule" <<EOF
# Generated by rocky-setup.sh on $(date)
# Rename $selected_iface to $new_name based on MAC address
SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="$mac_addr", NAME="$new_name"
EOF

    chmod 644 "$udev_rule"
    print_ok "Udev rule created: $udev_rule"

    local existing_conn=$(nmcli -t -f NAME,DEVICE connection show | grep ":$selected_iface$" | cut -d: -f1 | head -1)
    if [[ -n "$existing_conn" ]]; then
        nmcli connection modify "$existing_conn" connection.interface-name "$new_name" &>/dev/null
        nmcli connection modify "$existing_conn" connection.id "$new_name" &>/dev/null
        print_ok "NetworkManager connection updated"
    fi

    print_warn "Reboot required to apply interface rename"
    echo ""
}

# Create a bonded network interface
function create_bond_interface() {
    echo ""
    echo -e "${Bold}Create Bond Interface${Reset}"

    local all_interfaces=($(get_interfaces_array))
    local physical_interfaces=()

    for iface in "${all_interfaces[@]}"; do
        [[ ! "$iface" =~ ^bond ]] && [[ -d "/sys/class/net/$iface/device" ]] && physical_interfaces+=("$iface")
    done

    if [[ ${#physical_interfaces[@]} -lt 2 ]]; then
        print_warn "At least 2 physical interfaces required for bonding"
        print_info "Available: ${physical_interfaces[*]}"
        return
    fi

    echo ""
    echo -e "${Dim}Available interfaces for bonding:${Reset}"
    for i in "${!physical_interfaces[@]}"; do
        local iface="${physical_interfaces[$i]}"
        local mac=$(cat /sys/class/net/$iface/address 2>/dev/null || echo "N/A")
        local state=$(cat /sys/class/net/$iface/operstate 2>/dev/null || echo "N/A")
        printf "  ${Cyan}%d)${Reset} %-10s MAC: %-18s State: %s\n" "$((i+1))" "$iface" "$mac" "$state"
    done
    printf "  ${Cyan}0)${Reset} Return to network menu\n"

    while true; do
        echo ""
        read -p "  Bond interface name (e.g., bond0, or 0 to return): " bond_name

        # Check for return option
        if [[ "$bond_name" == "0" ]]; then
            return
        elif [[ ! "$bond_name" =~ ^bond[0-9]+$ ]]; then
            print_warn "Bond name format: bondX (e.g., bond0, bond1)"
            continue
        fi

        # Check if bond connection already exists in NetworkManager
        if nmcli connection show "$bond_name" &>/dev/null; then
            print_warn "Bond $bond_name already exists"
            continue
        fi

        read -p "  Select slave interfaces (space-separated numbers, e.g., '1 2'): " slave_nums

        local slaves=()
        for num in $slave_nums; do
            [[ "$num" =~ ^[0-9]+$ ]] && (( num >= 1 && num <= ${#physical_interfaces[@]} )) && slaves+=("${physical_interfaces[$((num-1))]}")
        done

        if [[ ${#slaves[@]} -lt 2 ]]; then
            print_warn "At least 2 slave interfaces required"
            continue
        fi

        local bond_modes=("balance-rr (Round-robin)" "active-backup (Failover)" "balance-xor" "broadcast" "802.3ad (LACP)" "balance-tlb" "balance-alb")
        show_menu "Select bond mode" 2 "${bond_modes[@]}"

        local bond_mode="active-backup"
        local bond_opts="miimon=100"

        case $menu_index in
            0) bond_mode="balance-rr";;
            1) bond_mode="active-backup";;
            2) bond_mode="balance-xor";;
            3) bond_mode="broadcast";;
            4) bond_mode="802.3ad"; bond_opts="miimon=100 lacp_rate=1";;
            5) bond_mode="balance-tlb";;
            6) bond_mode="balance-alb";;
        esac

        read -p "  MTU [1500]: " bond_mtu
        [[ -z "$bond_mtu" ]] && bond_mtu="1500"

        if ! [[ "$bond_mtu" =~ ^[0-9]+$ ]] || (( bond_mtu < 576 || bond_mtu > 9000 )); then
            print_warn "Invalid MTU (576-9000)"
            continue
        fi

        select_ip_config

        # Show summary
        local summary_items=(
            "Bond Name:     $bond_name"
            "Bond Mode:     $bond_mode"
            "Slaves:        ${slaves[*]}"
            "MTU:           $bond_mtu"
            "Boot Protocol: $bootproto"
        )
        [[ "$bootproto" == "none" ]] && summary_items+=(
            "IP Address:    $ipaddr"
            "Netmask:       $netmask"
        )
        [[ -n "$gateway" ]] && summary_items+=("Gateway:       $gateway")
        [[ -n "$dns1" ]] && summary_items+=("DNS1:          $dns1")
        [[ -n "$dns2" ]] && summary_items+=("DNS2:          $dns2")
        summary_items+=("Default Route: $defroute")

        print_summary "Bond Configuration" "${summary_items[@]}"

        echo ""
        read -p "  Create this bond? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            break
        else
            read -p "  Return to network menu? [y/N]: " return_menu
            [[ "$return_menu" =~ ^[Yy]$ ]] && return
        fi
    done

    local bond_mode_param=""
    case $bond_mode in
        "balance-rr") bond_mode_param="balance-rr";;
        "active-backup") bond_mode_param="active-backup";;
        "balance-xor") bond_mode_param="balance-xor";;
        "broadcast") bond_mode_param="broadcast";;
        "802.3ad") bond_mode_param="802.3ad";;
        "balance-tlb") bond_mode_param="balance-tlb";;
        "balance-alb") bond_mode_param="balance-alb";;
    esac

    if [[ "$bootproto" == "dhcp" ]]; then
        nmcli connection add type bond con-name "$bond_name" ifname "$bond_name" \
            bond.options "mode=$bond_mode_param,miimon=100" \
            ipv4.method auto \
            ipv6.method disabled \
            802-3-ethernet.mtu "$bond_mtu" \
            connection.autoconnect yes &>/dev/null
    else
        local prefix=$(netmask_to_cidr "$netmask")
        local ipv4_addr="${ipaddr}/${prefix}"

        if [[ -n "$gateway" ]]; then
            local dns_servers="$dns1"
            [[ -n "$dns2" ]] && dns_servers="$dns1 $dns2"

            nmcli connection add type bond con-name "$bond_name" ifname "$bond_name" \
                bond.options "mode=$bond_mode_param,miimon=100" \
                ipv4.method manual \
                ipv4.addresses "$ipv4_addr" \
                ipv4.gateway "$gateway" \
                ipv4.dns "$dns_servers" \
                ipv6.method disabled \
                802-3-ethernet.mtu "$bond_mtu" \
                connection.autoconnect yes &>/dev/null
        else
            nmcli connection add type bond con-name "$bond_name" ifname "$bond_name" \
                bond.options "mode=$bond_mode_param,miimon=100" \
                ipv4.method manual \
                ipv4.addresses "$ipv4_addr" \
                ipv4.never-default yes \
                ipv6.method disabled \
                802-3-ethernet.mtu "$bond_mtu" \
                connection.autoconnect yes &>/dev/null
        fi
    fi

    print_ok "Bond $bond_name created"

    for slave in "${slaves[@]}"; do
        # Delete existing connection for slave if it exists
        local existing_conn=$(nmcli -t -f NAME,DEVICE connection show | grep ":$slave$" | cut -d: -f1 | head -1)
        [[ -n "$existing_conn" ]] && nmcli connection delete "$existing_conn" &>/dev/null

        # Add slave to bond
        nmcli connection add type ethernet con-name "$bond_name-$slave" ifname "$slave" \
            master "$bond_name" \
            connection.autoconnect yes &>/dev/null

        print_ok "Added slave: $slave"
    done

    nmcli connection up "$bond_name" &>/dev/null

    print_ok "Bond configuration applied using NetworkManager"
    print_info "Bond activated: $bond_name"
    echo ""
}

# Create a VLAN interface
function create_vlan_interface() {
    echo ""
    echo -e "${Bold}Create VLAN Interface${Reset}"

    local all_interfaces=($(get_interfaces_array))
    local available_interfaces=()

    for iface in "${all_interfaces[@]}"; do
        [[ ! "$iface" =~ \. ]] && available_interfaces+=("$iface")
    done

    if [[ ${#available_interfaces[@]} -eq 0 ]]; then
        print_warn "No interfaces found for VLAN tagging"
        return
    fi

    echo ""
    echo -e "${Dim}Available interfaces for VLAN tagging:${Reset}"
    for i in "${!available_interfaces[@]}"; do
        local iface="${available_interfaces[$i]}"
        local mac=$(cat /sys/class/net/$iface/address 2>/dev/null || echo "N/A")
        local state=$(cat /sys/class/net/$iface/operstate 2>/dev/null || echo "N/A")
        printf "  ${Cyan}%d)${Reset} %-10s MAC: %-18s State: %s\n" "$((i+1))" "$iface" "$mac" "$state"
    done
    printf "  ${Cyan}0)${Reset} Return to network menu\n"

    while true; do
        echo ""
        read -p "  Select parent interface number [1-${#available_interfaces[@]}, or 0 to return]: " iface_num

        # Check for return option
        if [[ "$iface_num" == "0" ]]; then
            return
        fi

        if ! [[ "$iface_num" =~ ^[0-9]+$ ]] || (( iface_num < 1 || iface_num > ${#available_interfaces[@]} )); then
            print_warn "Invalid selection"
            continue
        fi

        local parent_iface="${available_interfaces[$((iface_num-1))]}"

        read -p "  VLAN ID (1-4094): " vlan_id

        if ! [[ "$vlan_id" =~ ^[0-9]+$ ]] || (( vlan_id < 1 || vlan_id > 4094 )); then
            print_warn "Invalid VLAN ID (must be 1-4094)"
            continue
        fi

        local vlan_name="${parent_iface}.${vlan_id}"

        if [[ -f "/etc/sysconfig/network-scripts/ifcfg-$vlan_name" ]]; then
            print_warn "VLAN interface $vlan_name already exists"
            continue
        fi

        read -p "  MTU [1500]: " vlan_mtu
        [[ -z "$vlan_mtu" ]] && vlan_mtu="1500"

        if ! [[ "$vlan_mtu" =~ ^[0-9]+$ ]] || (( vlan_mtu < 576 || vlan_mtu > 9000 )); then
            print_warn "Invalid MTU (576-9000)"
            continue
        fi

        select_ip_config

        # Show summary
        local summary_items=(
            "VLAN Interface: $vlan_name"
            "Parent Interface: $parent_iface"
            "VLAN ID:        $vlan_id"
            "MTU:            $vlan_mtu"
            "Boot Protocol:  $bootproto"
        )
        [[ "$bootproto" == "none" ]] && summary_items+=(
            "IP Address:     $ipaddr"
            "Netmask:        $netmask"
        )
        [[ -n "$gateway" ]] && summary_items+=("Gateway:        $gateway")
        [[ -n "$dns1" ]] && summary_items+=("DNS1:           $dns1")
        [[ -n "$dns2" ]] && summary_items+=("DNS2:           $dns2")
        summary_items+=("Default Route:  $defroute")

        print_summary "VLAN Configuration" "${summary_items[@]}"

        echo ""
        read -p "  Create this VLAN? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            break
        else
            read -p "  Return to network menu? [y/N]: " return_menu
            [[ "$return_menu" =~ ^[Yy]$ ]] && return
        fi
    done

    if [[ "$bootproto" == "dhcp" ]]; then
        nmcli connection add type vlan con-name "$vlan_name" ifname "$vlan_name" \
            dev "$parent_iface" \
            id "$vlan_id" \
            ipv4.method auto \
            ipv6.method disabled \
            802-3-ethernet.mtu "$vlan_mtu" \
            connection.autoconnect yes &>/dev/null
    else
        local prefix=$(netmask_to_cidr "$netmask")
        local ipv4_addr="${ipaddr}/${prefix}"

        if [[ -n "$gateway" ]]; then
            local dns_servers="$dns1"
            [[ -n "$dns2" ]] && dns_servers="$dns1 $dns2"

            nmcli connection add type vlan con-name "$vlan_name" ifname "$vlan_name" \
                dev "$parent_iface" \
                id "$vlan_id" \
                ipv4.method manual \
                ipv4.addresses "$ipv4_addr" \
                ipv4.gateway "$gateway" \
                ipv4.dns "$dns_servers" \
                ipv6.method disabled \
                802-3-ethernet.mtu "$vlan_mtu" \
                connection.autoconnect yes &>/dev/null
        else
            nmcli connection add type vlan con-name "$vlan_name" ifname "$vlan_name" \
                dev "$parent_iface" \
                id "$vlan_id" \
                ipv4.method manual \
                ipv4.addresses "$ipv4_addr" \
                ipv4.never-default yes \
                ipv6.method disabled \
                802-3-ethernet.mtu "$vlan_mtu" \
                connection.autoconnect yes &>/dev/null
        fi
    fi

    nmcli connection up "$vlan_name" &>/dev/null

    print_ok "VLAN configuration applied using NetworkManager"
    print_info "VLAN activated: $vlan_name"
    echo ""
}

# Network configuration menu
function update_network_settings() {
    print_header "Network Configuration"

    # Check if NetworkManager is available
    if ! command -v nmcli &>/dev/null; then
        print_info "NetworkManager not found, installing..."
        local net_tools=("NetworkManager" "NetworkManager-tui")
        install_applications "${net_tools[@]}"
    fi

    if ! systemctl is-active --quiet NetworkManager; then
        print_info "Enable and start NetworkManager..."
        systemctl enable NetworkManager &>/dev/null
        systemctl start NetworkManager &>/dev/null
        print_ok "NetworkManager service started"
    fi

    # Install additional network tools
    local network_utils=("net-tools" "iproute" "bridge-utils")
    print_info "Installing additional network utilities..."
    install_applications "${network_utils[@]}"

    while true; do
        local net_options=("List network interfaces" "Configure interface" "Create bond interface" "Create VLAN interface" "Back to main menu")
        show_menu "Network Options" 5 "${net_options[@]}"

        case $menu_index in
            0) list_network_interfaces;;
            1) configure_interface;;
            2) create_bond_interface;;
            3) create_vlan_interface;;
            4) return;;
        esac
    done
}

os_name=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
os_version=$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"' | cut -d. -f1)
if [[ "$os_name" != "rocky" ]]; then
    print_error "This script is for Rocky Linux only. Detected: $os_name $os_version"
    exit 1
fi
update_network_settings
