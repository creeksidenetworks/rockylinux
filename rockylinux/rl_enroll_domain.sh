#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; [[ -z "$RL_LIB_LOADED" ]] && source "$SCRIPT_DIR/rl_lib.sh"

# Prompt user to enter AD/LDAP group names (up to 4)
function get_ad_user_groups() {
    local title="$1"
    local domain="$2"
    local groups=""

    echo ""
    echo -e "${Cyan}$title${Reset}"

    local index=1
    while [ $index -le 4 ]; do
        read -p "  [$index] Group name (blank to finish): " group_name
        [[ -z "$group_name" ]] && break

        # Check if group exists, handling both fully qualified and short format
        local group_found=false

        # If domain is provided and group name doesn't contain @, try with domain suffix
        if [[ -n "$domain" && ! "$group_name" =~ @ ]]; then
            # Try with fully qualified name first (SSSD config may not be effective yet)
            if getent group "${group_name}@${domain}" &>/dev/null; then
                group_found=true
            elif getent group "$group_name" &>/dev/null; then
                group_found=true
            fi
        else
            # Check as-is
            if getent group "$group_name" &>/dev/null; then
                group_found=true
            fi
        fi

        if ! $group_found; then
            print_warn "Group '$group_name' not found in directory"
            continue
        fi

        # Store group name without domain suffix for realm permit
        groups+="${group_name%@*} "
        index=$((index + 1))
    done

    USER_GROUPS="$groups"
}

# Update or add a setting in a configuration file section
# Used primarily for SSSD configuration
# Arguments:
#   $1: Setting key
#   $2: Setting value
#   $3: Section name (without brackets)
#   $4: Configuration file path
update_setting() {
    local key="$1"
    local value="$2"
    local section="$3"
    local conf_file="$4"

    if grep -q "^[[:space:]]*$key[[:space:]]*=[[:space:]]*" "$conf_file"; then
        # Replace existing line
        sed -i "/^\[${section}\//,/^\[/ s|^[[:space:]]*$key[[:space:]]*=[[:space:]]*.*|$key = $value|" "$conf_file"
    else
        # Add new line after the domain section header
        sed -i "/^\[${section}\//a $key = $value" "$conf_file"
    fi
}

# Configure SSSD to use specified groups for sudo and regular access
function update_sssd_settings() {

    # Update SSSD configuration in-place
    SSSD_CONF="/etc/sssd/sssd.conf"
    BACKUP_CONF="${SSSD_CONF}.bak.$(date +%Y%m%d_%H%M%S)"
    cp "$SSSD_CONF" "$BACKUP_CONF"

    for key in "${!sssd_settings[@]}"; do
        update_setting "$key" "${sssd_settings[$key]}" "domain" "$SSSD_CONF"
    done
    chmod 600 "$SSSD_CONF"
    print_ok "SSSD configuration updated"

    # Restart SSSD
    systemctl stop sssd
    sss_cache -E
    systemctl start sssd
    print_ok "SSSD cache cleared and service restarted"
}

# Enroll host to Active Directory or FreeIPA domain
function enroll_domain() {
    print_header "Domain Enrollment"

    #---------------------------------------------------------------------------
    print_step "1" "Installing Required Packages"
    #---------------------------------------------------------------------------

    local domain_packages=("realmd" "ipa-client" "oddjob" "oddjob-mkhomedir" "sssd" "sssd-tools" "adcli" "samba-common-tools" "krb5-workstation")

    install_applications "${domain_packages[@]}"

    # Check if already joined
    current_domain=$(realm list | grep domain-name | cut -d ':' -f 2 | xargs)
    if [[ -n $current_domain ]]; then
        print_ok "Already joined to domain: $current_domain"
        return 0
    fi

    # Auto detect FQDN from hostname
    default_fqdn=$(hostname -f 2>/dev/null)
    [[ -z "$default_fqdn" || "$default_fqdn" == "localhost" ]] && default_fqdn=""

    # Derive domain name from FQDN (get last two components)
    local domain_parts=(${default_fqdn//./ })
    if [[ ${#domain_parts[@]} -gt 2 ]]; then
        domain_name="${domain_parts[-2]}.${domain_parts[-1]}"
    elif [[ ${#domain_parts[@]} -eq 2 ]]; then
        domain_name="${domain_parts[-1]}"
    elif [[ ${#domain_parts[@]} -eq 1 ]]; then
        domain_name=""  # no domain derivable
    fi

    while true; do
        echo ""

        # Allow user to override the derived domain name
        read -p "  Enter domain name [$domain_name]: " domain_input
        [[ -n "$domain_input" ]] && domain_name="$domain_input"
        if [[ -z "$domain_name" ]]; then
            print_warn "Domain name cannot be empty"
            continue
        fi

        # Discover domain info
        realm_output=$(realm discover "$domain_name" 2>/dev/null || true)
        domain_type=$(echo "$realm_output" | awk -F': ' '/server-software:/ {if ($2 ~ /active-directory/) print "Active Directory"; else if ($2 ~ /ipa/) print "FreeIPA"; else print "Unknown"}')

        if [[ -z $domain_type || "$domain_type" == "Unknown" ]]; then
            print_warn "Domain $domain_name not found"
            print_info "Check domain name and network connectivity"
            continue
        fi

        # derive default hostname from default_fqdn minus confirmed domain_name
        local_hostname="${default_fqdn%.$domain_name}"

        read -p "  Enter hostname w/o domain suffix [${local_hostname}]: " new_hostname
        [[ -z "$new_hostname" ]] && new_hostname="$local_hostname"
        fqdn_hostname="${new_hostname}.${domain_name}"

        while true; do
            read -p "  Enter admin username for $domain_name: " admin_user
            [[ -n "$admin_user" ]] && break
            print_warn "Admin username cannot be empty"
        done

        while true; do
            read -s -p "  Enter password for $admin_user: " admin_pass
            echo ""
            [[ -n "$admin_pass" ]] && break
            print_warn "Password cannot be empty"
        done

        # Display summary
        local summary_items=(
            "Hostname:    $fqdn_hostname"
            "Domain:      $domain_name"
            "Type:        $domain_type"
            "Admin User:  $admin_user"
        )
        print_summary "Domain Join Configuration" "${summary_items[@]}"

        echo ""
        read -p "  Proceed to join $domain_type? [y/N]: " proceed
        [[ "$proceed" =~ ^[Yy]$ ]] && break
        print_info "Operation cancelled"
        return
    done

    #---------------------------------------------------------------------------
    print_step "2" "Joining Domain"
    #---------------------------------------------------------------------------

    sudo hostnamectl set-hostname "$fqdn_hostname"
    print_ok "Hostname set to $fqdn_hostname"

    if [[ "$domain_type" == "FreeIPA" ]]; then
        if ipa-client-install \
            -p "$admin_user" \
            -w "$admin_pass" \
            --hostname="$fqdn_hostname" \
            --domain="$domain_name" \
            --principal="$admin_user" \
            --mkhomedir \
            --enable-dns-updates \
            --force-join \
            --unattended; then
            print_ok "Joined $domain_name (FreeIPA)"
        else
            print_error "Failed to join FreeIPA domain"
            return 1
        fi

        #-----------------------------------------------------------------------
        print_step "3" "Configuring SSSD"
        #-----------------------------------------------------------------------
        #declare -A sssd_settings=(
        #    ["ipa_dyndns_update"]="True"
        #)
        #update_sssd_settings

        echo ""
        echo -e "${Green}${Bold}✓ FreeIPA enrollment completed${Reset}"
        echo ""
        return 0
    else
        # Join Active Directory domain
        if echo "$admin_pass" | realm join --user="$admin_user" "$domain_name"; then
            print_ok "Joined $domain_name (Active Directory)"
        else
            print_error "Failed to join domain. Check credentials and network."
            return 1
        fi

        #-----------------------------------------------------------------------
        print_step "3" "Configuring SSSD"
        #-----------------------------------------------------------------------
        declare -A sssd_settings=(
            ["use_fully_qualified_names"]="False"
            ["fallback_homedir"]="/home/%u"
            ["ad_gpo_access_control"]="disabled"
            ["ad_gpo_map_remote_interactive"]="+xrdp-sesman"
            ["default_shell"]="/bin/bash"
        #    ["dyndns_update"]="True"
        #    ["dyndns_refresh_interval"]="43200"
        #    ["dyndns_update_ptr"]="True"
        )
        update_sssd_settings

        #-----------------------------------------------------------------------
        print_step "4" "Configuring Access Permissions"
        #-----------------------------------------------------------------------

        get_ad_user_groups "Add groups with sudo access (up to 4)" "$domain_name"
        admin_groups="$USER_GROUPS"

        get_ad_user_groups "Add groups with regular access (up to 4)" "$domain_name"
        access_groups="$USER_GROUPS"

        # Configure sudoers for admin groups
        if [[ -n "$admin_groups" ]]; then
            SUDOERS_FILE="/etc/sudoers.d/90-ad-groups"
            echo "# Sudoers file for AD groups - $(date)" > "$SUDOERS_FILE"
            for group in $admin_groups; do
                echo "%$group ALL=(ALL) NOPASSWD: ALL" >> "$SUDOERS_FILE"
            done
            chmod 440 "$SUDOERS_FILE"
            print_ok "Sudo access configured for: $admin_groups"
        fi

        # Permit access to specified groups
        combined_groups=$(echo "$admin_groups $access_groups" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ' | xargs)
        if [[ -n "$combined_groups" ]]; then
            if realm permit -g $combined_groups 2>/dev/null; then
                print_ok "Login access permitted for: $combined_groups"
            else
                print_warn "Failed to configure realm permissions"
            fi
        fi

        echo ""
        echo -e "${Green}${Bold}✓ Domain enrollment completed${Reset}"
        echo ""
        return 0
    fi
}

os_name=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
os_version=$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"' | cut -d. -f1)
if [[ "$os_name" != "rocky" ]]; then
    print_error "This script is for Rocky Linux only. Detected: $os_name $os_version"
    exit 1
fi
enroll_domain
