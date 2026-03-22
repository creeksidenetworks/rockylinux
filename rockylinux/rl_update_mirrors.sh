#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; [[ -z "$RL_LIB_LOADED" ]] && source "$SCRIPT_DIR/rl_lib.sh"

# Update yum repository mirrors
function update_mirrors() {
    print_header "Update Repository Mirrors"

    detect_location

    while true; do
        echo ""
        printf "  ${Cyan}1.${Reset} Region: ${Green}$COUNTRY${Reset} (Timezone: $TIMEZONE)\n"
        read -p "     Change region? [y/N]: " change_country
        if [[ "$change_country" =~ ^[Yy]$ ]]; then
            show_menu "Select your country/region" "${regions[@]}"
            if (( menu_index >= 0 && menu_index < ${#countries[@]} )); then
                COUNTRY="${countries[$menu_index]}"
                TIMEZONE="${timezones[$menu_index]}"
            fi
        fi

        proxy_url=""
        printf "\n  ${Cyan}2.${Reset} Proxy: "
        read -p "Configure yum proxy? [y/N]: " use_proxy
        if [[ "$use_proxy" =~ ^[Yy]$ ]]; then
            read -p "     Enter proxy host: " proxy_host
            [[ -n "$proxy_host" ]] && proxy_url="http://$proxy_host:3128"
        fi

        echo ""
        read -p "  Proceed with these settings? [Y/n]: " confirm
        if [[ "$confirm" =~ ^[Nn]$ ]]; then
            read -p "  Return to main menu? [y/N]: " confirm
            [[ "$confirm" =~ ^[Yy]$ ]] && return
        else
            break
        fi
    done

    if [[ -n "$proxy_url" ]]; then
        echo "proxy=$proxy_url" | sudo tee -a /etc/yum.conf > /dev/null
        print_ok "Proxy configured"
    fi

    yum_configure_mirror

    echo ""
    echo -e "${Green}${Bold}✓ Repository mirrors updated${Reset}"
    echo ""
}

os_name=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
os_version=$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"' | cut -d. -f1)
if [[ "$os_name" != "rocky" ]]; then
    print_error "This script is for Rocky Linux only. Detected: $os_name $os_version"
    exit 1
fi
update_mirrors
