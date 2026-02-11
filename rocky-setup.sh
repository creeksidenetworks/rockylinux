#!/bin/bash
#===============================================================================
# Rocky Linux Setup Utility
# Version: 1.0
# Author: Jackson Tong / Creekside Networks LLC
# License: MIT
#
# Description:
#   Comprehensive setup and configuration utility for Rocky Linux 8/9.
#   Provides menu-driven interface for system initialization, network
#   configuration, desktop environment installation, and domain enrollment.
#
# Usage:
#   Local:  sudo ./rocky-setup.sh
#   Remote: ssh -t <host> "$(<./rocky-setup.sh)"
#
# Requirements:
#   - Rocky Linux 8 or 9
#   - Root privileges
#   - Network connectivity (for package installation)
#===============================================================================

# Colors for terminal output
Red=$(tput setaf 1)
Green=$(tput setaf 2)
Yellow=$(tput setaf 3)
Blue=$(tput setaf 4)
Cyan=$(tput setaf 6)
Bold=$(tput bold)
Reset=$(tput sgr0)
Dim=$(tput dim)

print_header() {
    local title="$1"
    local width=60
    local padding=$(( (width - ${#title} - 2) / 2 ))
    echo ""
    printf "${Cyan}%s${Reset}\n" "$(printf '═%.0s' $(seq 1 $width))"
    printf "${Cyan}║${Reset}%*s${Bold}%s${Reset}%*s${Cyan}║${Reset}\n" $padding "" "$title" $((width - padding - ${#title} - 2)) ""
    printf "${Cyan}%s${Reset}\n" "$(printf '═%.0s' $(seq 1 $width))"
}

print_step() {
    local step_num="$1"
    local title="$2"
    echo ""
    echo -e "${Yellow}[$step_num]${Reset} ${Bold}$title${Reset}"
    echo -e "${Dim}$(printf '─%.0s' $(seq 1 50))${Reset}"
}

print_ok() {
    echo -e "  ${Green}✓${Reset} $1"
}

print_warn() {
    echo -e "  ${Yellow}⚠${Reset} $1"
}

print_error() {
    echo -e "  ${Red}✗${Reset} $1"
}

print_info() {
    echo -e "  ${Blue}ℹ${Reset} $1"
}

print_summary() {
    local title="$1"
    shift
    local items=("$@")
    echo ""
    echo -e "${Cyan}┌─ $title ───────────-────${Reset}"
    for item in "${items[@]}"; do
        echo -e "${Cyan}│${Reset}  $item"
    done
    echo -e "${Cyan}└$(printf '─%.0s' $(seq 1 40))${Reset}"
}

countries=("CN" "GB" "AE" "US")
regions=("China" "UK" "UAE" "USA")
timezones=("Asia/Shanghai" "Europe/London" "Asia/Dubai" "America/Los_Angeles")

COUNTRY=""
TIMEZONE="UTC"

declare -A BASE_MIRRORS
declare -A EPEL_MIRRORS
BASE_MIRRORS["US"]="http://dl.rockylinux.org"
EPEL_MIRRORS["US"]="http://dl.fedoraproject.org/pub/epel"
BASE_MIRRORS["CN"]="https://mirrors.nju.edu.cn"
EPEL_MIRRORS["CN"]="https://mirrors.nju.edu.cn/epel"
BASE_MIRRORS["GB"]="http://rockylinux.mirrorservice.org"
EPEL_MIRRORS["GB"]="https://www.mirrorservice.org/pub/epel"
BASE_MIRRORS["AE"]="http://dl.rockylinux.org"
EPEL_MIRRORS["AE"]="http://dl.fedoraproject.org/pub/epel"
#BASE_MIRRORS["AE"]="https://mirror.ourhost.az/rockylinux/"
#EPEL_MIRRORS["AE"]="https://mirror.yer.az/fedora-epel/"

tmp_file=$(mktemp /tmp/rocky-setup.XXXXXX)
trap cleanup_existing EXIT

function cleanup_existing() {
    echo ""
    echo -e "${Dim}Cleaning up and exiting...${Reset}"
    rm -f "$tmp_file"
    exit 0
}

function download_apps() {
    local url="$1"
    local dest="$2"
    local path="/resource/apps/"

    url="sftp://ftp.creekside.network:58222"
    curl --silent --list --user downloader:Kkg94290 --insecure ${url}/${path}/

}   

function add_root_ssh_keys() {
    if [[ $(id -u) -ne 0 ]]; then
        echo "This operation must be run as root. Please re-run as root or with sudo."
        exit 1
    fi

    local authorized_keys_file="/root/.ssh/authorized_keys"
    local ssh_dir="/root/.ssh"
    local keys=(
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHrPVbtdHf0aJeRu49fm/lLQPxopvvz6NZZqqGB+bcocZUW3Hw8bflhouTsJ+S4Z3v7L/F6mmZhXU1U3PqUXLVTE4eFMfnDjBlpOl0VDQoy9aT60C1Sreo469FB0XQQYS5CyIWW5C5rQQzgh1Ov8EaoXVGgW07GHUQCg/cmOBIgFvJym/Jmye4j2ALe641jnCE98yE4mPur7AWIs7n7W8DlvfEVp4pnreqKtlnfMqoOSTVl2v81gnp4H3lqGyjjK0Uku72GKUkAwZRD8BIxbA75oBEr3f6Klda2N88uwz4+3muLZpQParYQ+BhOTvldMMXnhqM9kHhvFZb21jTWV7p creeksidenetworks@gmail.com"
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJggtEGPdn91k36jza3Ln+pXivNTjcT+l17fwFaVpecP jtong@creekside.network"
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQChzHPb3CTFUwEPCm1sZQUwiJIWhrw8PtuKWyOOgBjPCGVbavRjHDKlaXSgh3JtEBovQX0CLvqR+dMDJEjYGCRQRyfLT84K7ozEbfw8tX+IlWrLGQ7t6bZQjp1d70ulFWWVwTFLtcA3RGONSAR+Jt0zTzkhFCjPp8CagRe7nY7KNh3kE7y19OlWoP4eNw0ZAaMcUajKd6YJXYs4LnpoyM2lrWZRssa3kiPxzpyJj9z0mrc5hH6WmrKyPAuJO4GuFXNUwGre/H5DIoXUgzmZZTbusE25exGkKpweFo4M/CxB2szebr0XKViwYrp3sT0ELUk92cJC65HkmFTrj/Fq49VEXJ3Z3fwoootyhPFQ/Gk5JrJ+bNsvSRRBS+m7f/afOq9m5jvx907nnP8HN9W0pJkrmJkzz7Lvzm7BfaMMJ9TUWf9olroLXWy+VkH8RdW0MKz7zZ1sCLhIerZz1iUtkVhPTjRYmWQZtFgSc7b4hhm6Xw7bGMhRZa91SJTt3MzUeM8= jsong@creekside.network"
    )

    if [[ ! -d "$ssh_dir" ]]; then
        mkdir -p "$ssh_dir"
        chmod 700 "$ssh_dir"
    fi
    if [[ ! -f "$authorized_keys_file" ]]; then
        touch "$authorized_keys_file"
        chmod 600 "$authorized_keys_file"
    fi

    for key in "${keys[@]}"; do
        if ! grep -qF "$key" "$authorized_keys_file"; then
            echo "$key" >> "$authorized_keys_file"
        fi
    done
}

function show_menu() {
    local title="$1"
    shift
    local default_choice=0
    
    if [[ "$1" =~ ^[0-9]+$ ]]; then
        default_choice=$1
        shift
    fi
    
    local options=("$@")
    echo ""
    echo -e "${Green}${Bold}$title${Reset}"
    for i in "${!options[@]}"; do
        printf "  ${Cyan}%d)${Reset} %s\n" "$((i+1))" "${options[$i]}"
    done
    echo ""
    if [[ $default_choice -gt 0 ]]; then
        echo -n "  Select [$default_choice]: "
    else
        echo -n "  Select: "
    fi
    read user_choice
    
    if [[ -z "$user_choice" ]]; then
        user_choice=$default_choice
    fi
    if ! [[ "$user_choice" =~ ^[0-9]+$ ]] || (( user_choice < 1 || user_choice > ${#options[@]} )); then
        if [[ $default_choice -gt 0 ]]; then
            user_choice=$default_choice
        else
            user_choice=${#options[@]}
        fi
    fi
    menu_index=$((user_choice-1))
}

function detect_location() {
    GEOINFO=$(curl -s --max-time 5 http://ip-api.com/json/)
    if [[ -n "$GEOINFO" && "$GEOINFO" != "{}" ]]; then
        COUNTRY=$(echo "$GEOINFO" | grep -o '"countryCode":"[^"]*"' | cut -d':' -f2 | tr -d '"')
        TIMEZONE=$(echo "$GEOINFO" | grep -o '"timezone":"[^"]*"' | cut -d':' -f2 | tr -d '"')
    fi
    if [[ -z "$COUNTRY" ]] || [[ ! " ${countries[@]} " =~ " $COUNTRY " ]]; then
        echo -e "⚠️  Could not retrieve geolocation info, use USA as default."
        COUNTRY="US"
        TIMEZONE="America/Los_Angeles"
    fi
    export COUNTRY TIMEZONE
}

function select_mirror_country() {
    detect_location
    local detected_country="$COUNTRY"
    
    local default_index=0
    for i in "${!countries[@]}"; do
        if [[ "${countries[$i]}" == "$detected_country" ]]; then
            default_index=$i
            break
        fi
    done
    
    local menu_options=()
    for i in "${!countries[@]}"; do
        local country_code="${countries[$i]}"
        local region_name="${regions[$i]}"
        local mirror_url="${BASE_MIRRORS[$country_code]}"
        
        if [[ "$country_code" == "$detected_country" ]]; then
            menu_options+=("$region_name ($country_code) - $mirror_url [detected]")
        else
            menu_options+=("$region_name ($country_code) - $mirror_url")
        fi
    done
    
    show_menu "Select Yum Mirror Country:" "$((default_index+1))" "${menu_options[@]}"
    
    COUNTRY="${countries[$menu_index]}"
    
    export COUNTRY
    echo -e "${Green}✓${Reset} Selected mirror country: $COUNTRY (${regions[$menu_index]})\n"
}

function yum_configure_mirror() {
    country="$1"
    if [[ -z "$country" ]]; then
        select_mirror_country
    fi

    echo "  Configuring yum repositories for $COUNTRY"
    baseos_url="${BASE_MIRRORS[$COUNTRY]}"
    epel_url="${EPEL_MIRRORS[$COUNTRY]}"
    
    if [[ -z "$baseos_url" ]]; then
        baseos_url="${BASE_MIRRORS[US]}"
        epel_url="${EPEL_MIRRORS[US]}"
    fi

    # Detect if this is NJU mirror which has different path structure
    is_nju_mirror=0
    if [[ "$baseos_url" =~ mirrors.nju.edu.cn ]]; then
        is_nju_mirror=1
    fi

    shopt -s nocaseglob
    for repo in /etc/yum.repos.d/rocky*.repo; do
        [[ ! -f "$repo" ]] && continue
        
        # Use awk to process the file and update baseurl based on the section
        awk -v mirror="${baseos_url}" -v is_nju="${is_nju_mirror}" '
        /^\[baseos\]/ { section="baseos" }
        /^\[appstream\]/ { section="appstream" }
        /^\[extras\]/ { section="extras" }
        /^\[crb\]/ { section="crb" }
        /^\[powertools\]/ { section="powertools" }
        /^\[highavailability\]/ { section="highavailability" }
        /^\[resilientstorage\]/ { section="resilientstorage" }
        /^\[rt\]/ { section="rt" }
        /^\[nfv\]/ { section="nfv" }
        /^\[sap\]/ { section="sap" }
        /^\[saphana\]/ { section="saphana" }
        /^\[devel\]/ { section="devel" }
        /^\[plus\]/ { section="plus" }
        /^#?baseurl=/ {
            if (is_nju == 1) {
                # NJU mirror uses /rocky/ path directly without /pub/
                if (section == "baseos") print "baseurl=" mirror "/rocky/$releasever/BaseOS/$basearch/os/"
                else if (section == "appstream") print "baseurl=" mirror "/rocky/$releasever/AppStream/$basearch/os/"
                else if (section == "extras") print "baseurl=" mirror "/rocky/$releasever/extras/$basearch/os/"
                else if (section == "crb") print "baseurl=" mirror "/rocky/$releasever/CRB/$basearch/os/"
                else if (section == "powertools") print "baseurl=" mirror "/rocky/$releasever/PowerTools/$basearch/os/"
                else if (section == "highavailability") print "baseurl=" mirror "/rocky/$releasever/HighAvailability/$basearch/os/"
                else if (section == "resilientstorage") print "baseurl=" mirror "/rocky/$releasever/ResilientStorage/$basearch/os/"
                else if (section == "rt") print "baseurl=" mirror "/rocky/$releasever/RT/$basearch/os/"
                else if (section == "nfv") print "baseurl=" mirror "/rocky/$releasever/NFV/$basearch/os/"
                else if (section == "sap") print "baseurl=" mirror "/rocky/$releasever/SAP/$basearch/os/"
                else if (section == "saphana") print "baseurl=" mirror "/rocky/$releasever/SAPHANA/$basearch/os/"
                else if (section == "devel") print "baseurl=" mirror "/rocky/$releasever/devel/$basearch/os/"
                else if (section == "plus") print "baseurl=" mirror "/rocky/$releasever/plus/$basearch/os/"
                else print
            } else {
                # Standard mirrors use /$contentdir/ path
                if (section == "baseos") print "baseurl=" mirror "/$contentdir/$releasever/BaseOS/$basearch/os/"
                else if (section == "appstream") print "baseurl=" mirror "/$contentdir/$releasever/AppStream/$basearch/os/"
                else if (section == "extras") print "baseurl=" mirror "/$contentdir/$releasever/extras/$basearch/os/"
                else if (section == "crb") print "baseurl=" mirror "/$contentdir/$releasever/CRB/$basearch/os/"
                else if (section == "powertools") print "baseurl=" mirror "/$contentdir/$releasever/PowerTools/$basearch/os/"
                else if (section == "highavailability") print "baseurl=" mirror "/$contentdir/$releasever/HighAvailability/$basearch/os/"
                else if (section == "resilientstorage") print "baseurl=" mirror "/$contentdir/$releasever/ResilientStorage/$basearch/os/"
                else if (section == "rt") print "baseurl=" mirror "/$contentdir/$releasever/RT/$basearch/os/"
                else if (section == "nfv") print "baseurl=" mirror "/$contentdir/$releasever/NFV/$basearch/os/"
                else if (section == "sap") print "baseurl=" mirror "/$contentdir/$releasever/SAP/$basearch/os/"
                else if (section == "saphana") print "baseurl=" mirror "/$contentdir/$releasever/SAPHANA/$basearch/os/"
                else if (section == "devel") print "baseurl=" mirror "/$contentdir/$releasever/devel/$basearch/os/"
                else if (section == "plus") print "baseurl=" mirror "/$contentdir/$releasever/plus/$basearch/os/"
                else print
            }
            next
        }
        /^mirrorlist=/ { print "#" $0; next }
        { print }
        ' "$repo" > "$repo.tmp" && mv "$repo.tmp" "$repo"
    done
    shopt -u nocaseglob
    print_ok "Rocky Linux repos → $baseos_url"

    for repo in /etc/yum.repos.d/epel*.repo; do
        [[ ! -f "$repo" ]] && continue
        
        # Handle cisco-openh264 repo separately (uses different URL structure)
        if grep -q "epel-cisco-openh264" "$repo"; then
            sed -i -E 's|^#?baseurl=.*|baseurl=http://codecs.fedoraproject.org/openh264/$releasever/$basearch/|' "$repo"
            sed -i -E 's/^(metalink=.*)/#\1/' "$repo"
        else
            # Standard EPEL repos
            sed -i -E 's|^#?baseurl=.*|baseurl='"${epel_url}"'/$releasever/Everything/$basearch/|' "$repo"
            sed -i -E 's/^(metalink=.*)/#\1/' "$repo"
        fi
    done
    print_ok "EPEL repos → $epel_url"
}

# Install packages using dnf, skipping already-installed packages
function install_applications() {
    local packages=("$@")
    local installed=0
    local failed=0
    local skipped=0
    
    for package in "${packages[@]}"; do
        if rpm -q --quiet "$package" 2>/dev/null; then
            ((skipped++))
        elif dnf install -yq "$package" &>/dev/null; then
            ((installed++))
        else
            print_warn "Failed: $package"
            ((failed++))
        fi
    done
    
    local summary="Installed: $installed"
    [[ $skipped -gt 0 ]] && summary+=", Skipped: $skipped"
    [[ $failed -gt 0 ]] && summary+=", Failed: $failed"
    print_ok "$summary"
}

function initialization() {
    print_header "System Initialization"

    detect_location

    while true; do
        # Collect configuration
        echo ""
        echo -e "${Bold}Configuration Options${Reset}"
        echo ""
        printf "  ${Cyan}1.${Reset} Region:   ${Green}$COUNTRY${Reset} (Timezone: $TIMEZONE)\n"
        read -p "     Change region? [y/N]: " change_country
        if [[ "$change_country" =~ ^[Yy]$ ]]; then
            show_menu "Select your country/region" "${regions[@]}"
            if (( menu_index >= 0 && menu_index < ${#countries[@]} )); then
                COUNTRY="${countries[$menu_index]}"
                TIMEZONE="${timezones[$menu_index]}"
            fi
        fi

        proxy_url=""
        printf "\n  ${Cyan}2.${Reset} Proxy:    "
        read -p "Configure yum proxy? [y/N]: " use_proxy
        if [[ "$use_proxy" =~ ^[Yy]$ ]]; then
            read -p "     Enter proxy host (hostname or IP): " proxy_host
            if [[ -n "$proxy_host" ]] && \
               ([[ "$proxy_host" =~ ^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$ ]] || \
                [[ "$proxy_host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]); then
                proxy_url="http://$proxy_host:3128"
            else
                print_warn "Invalid hostname or IP. Skipping proxy."
            fi
        fi

        printf "\n  ${Cyan}3.${Reset} Hostname: "
        read -p "Enter new hostname [skip]: " new_hostname

        # Display summary
        local summary_items=(
            "Country:   $COUNTRY"
            "Timezone:  $TIMEZONE"
            "Proxy:     ${proxy_url:-(none)}"
            "Hostname:  ${new_hostname:-(unchanged)}"
        )
        print_summary "Configuration Summary" "${summary_items[@]}"

        echo ""
        read -p "  Proceed with these settings? [Y/n]: " confirm
        if [[ "$confirm" =~ ^[Nn]$ ]]; then
            read -p "  Return to main menu? [y/N]: " confirm
            [[ "$confirm" =~ ^[Yy]$ ]] && return
            continue
        fi
        break
    done

    #---------------------------------------------------------------------------
    print_step "1" "Configuring System Settings"
    #---------------------------------------------------------------------------
    
    if [[ -n "$proxy_url" ]]; then
        if grep -q "^proxy=" /etc/yum.conf; then
            sudo sed -i "s|^proxy=.*|proxy=$proxy_url|" /etc/yum.conf
        else
            echo "proxy=$proxy_url" | sudo tee -a /etc/yum.conf > /dev/null
        fi
        print_ok "Yum proxy configured"

        # Set proxy environment variables for root user
        if ! grep -q "http_proxy=" /root/.bashrc; then
            cat <<EOF >> /root/.bashrc
export http_proxy=$proxy_url
export https_proxy=$proxy_url
export ftp_proxy=$proxy_url
export no_proxy="localhost,127.0.0.1,::1"
EOF
            print_ok "Proxy environment variables set"
        fi
    fi

    sudo timedatectl set-timezone "${TIMEZONE}"
    print_ok "Timezone: ${TIMEZONE}"

    if [[ -n "$new_hostname" ]]; then
        sudo hostnamectl set-hostname "$new_hostname"
        print_ok "Hostname: $new_hostname"
    fi

    sudo setenforce 0 2>/dev/null || true
    sudo sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    print_ok "SELinux disabled"

    #---------------------------------------------------------------------------
    print_step "2" "Configuring Repositories"
    #---------------------------------------------------------------------------
    
    if ! dnf repolist enabled | grep -q epel 2>/dev/null; then
        if dnf install -y epel-release &>/dev/null; then
            dnf makecache -y &>/dev/null
            print_ok "EPEL repository installed"
        else
            print_error "Failed to install EPEL repository"
            exit 1
        fi
    else
        print_ok "EPEL repository (already installed)"
    fi 

    if [[ $os_version == "8" ]]; then
        yum config-manager --set-enabled powertools &>/dev/null
        print_ok "PowerTools repository enabled"
    else
        yum config-manager --set-enabled crb &>/dev/null
        print_ok "CRB repository enabled"
    fi

    cat <<EOF > /etc/yum.repos.d/rpmfusion-free.repo
[rpmfusion-free-updates]
name=RPM Fusion for EL ${os_version} - Free - Updates
baseurl=http://download1.rpmfusion.org/free/el/updates/${os_version}/\$basearch/
enabled=1
gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rpmfusion-free-el-${os_version}
EOF

    cat <<EOF > /etc/yum.repos.d/rpmfusion-nonfree.repo
[rpmfusion-nonfree-updates]
name=RPM Fusion for EL ${os_version} - Nonfree - Updates
baseurl=http://download1.rpmfusion.org/nonfree/el/updates/${os_version}/\$basearch/
enabled=1
gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rpmfusion-nonfree-el-${os_version}
EOF
    print_ok "RPM Fusion repositories enabled"

    yum_configure_mirror "$COUNTRY"

    #---------------------------------------------------------------------------
    print_step "3" "Updating System Packages"
    #---------------------------------------------------------------------------
    
    print_info "Running system update (this may take a few minutes)..."
    if dnf update -y &>/dev/null; then
        print_ok "System packages updated successfully"
    else
        print_warn "System update completed with some warnings"
    fi

    #---------------------------------------------------------------------------
    print_step "4" "Installing Essential Packages"
    #---------------------------------------------------------------------------
    
    local default_packages=(
        "zsh" "ksh" "tcsh" "xterm" "ethtool" "vim"
        "yum-utils" "util-linux" "tree" "ncurses" 
        "nano" "ed" "fontconfig" "nedit" "htop" "pwgen"
        "nfs-utils" "cifs-utils" "samba-client" "autofs" 
        "subversion" "ansible" "git"
        "iperf3" "traceroute" "mtr" "rsnapshot"
        "tar"  "zip" "unzip" "p7zip" "p7zip-plugins" "cabextract"
        "rsync" "curl" "ftp" "wget" "cloud-utils-growpart" "cloud-init"
        "telnet" "jq"  "lsof" "bind-utils" "tcpdump" "net-tools"
        "openssl" "cyrus-sasl" "cyrus-sasl-plain" "cyrus-sasl-ldap"
        "openldap-clients" "ipa-client"
        "sssd" "realmd" "oddjob" "oddjob-mkhomedir"
        "adcli" "samba-common" "samba-common-tools" "krb5-workstation"
        "firewalld" "dnf-plugins-core" "policycoreutils-python-utils"
    )

    print_info "Installing ${#default_packages[@]} packages..."
    install_applications "${default_packages[@]}"

    #---------------------------------------------------------------------------
    print_step "5" "Configuring Firewall"
    #---------------------------------------------------------------------------
    
    if systemctl is-active --quiet firewalld; then
        print_ok "Firewalld is already running"
    else
        print_info "Starting firewalld service..."
        if systemctl enable firewalld &>/dev/null && systemctl start firewalld &>/dev/null; then
            print_ok "Firewalld enabled and started"
        else
            print_error "Failed to start firewalld"
        fi
    fi

    #---------------------------------------------------------------------------
    print_step "6" "Disabling SELinux"
    #---------------------------------------------------------------------------
    
    current_selinux=$(getenforce 2>/dev/null || echo "Unknown")
    if [[ "$current_selinux" == "Disabled" ]]; then
        print_ok "SELinux is already disabled"
    else
        print_info "Current SELinux mode: $current_selinux"
        # Set to permissive for current session
        if setenforce 0 &>/dev/null; then
            print_ok "SELinux set to permissive (current session)"
        fi
        
        # Disable permanently in config
        if [[ -f /etc/selinux/config ]]; then
            sed -i 's/^SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
            sed -i 's/^SELINUX=permissive/SELINUX=disabled/' /etc/selinux/config
            print_ok "SELinux disabled in config (will be disabled after reboot)"
        else
            # Create SELinux config directory and file
            mkdir -p /etc/selinux
            cat > /etc/selinux/config <<EOF
SELINUX=disabled
SELINUXTYPE=targeted
EOF
            print_ok "SELinux config created and set to disabled"
        fi
        
        # Disable SELinux at boot via kernel command line
        if command -v grubby &>/dev/null; then
            grubby --update-kernel ALL --args selinux=0 &>/dev/null
            print_ok "SELinux disabled at boot (kernel args)"
        fi
        
        # Prevent cloud-init from re-enabling SELinux
        if command -v cloud-init &>/dev/null || [[ -d /etc/cloud ]]; then
            # Create cloud-init config to preserve SELinux disabled state
            mkdir -p /etc/cloud/cloud.cfg.d
            cat > /etc/cloud/cloud.cfg.d/99-disable-selinux.cfg <<EOF
#cloud-config
# Prevent cloud-init from modifying SELinux settings
# Generated by rocky-setup.sh on $(date)
bootcmd:
  - [ setenforce, 0 ]
  - [ grubby, --update-kernel, ALL, --args, selinux=0 ]
runcmd:
  - [ setenforce, 0 ]
EOF
            print_ok "Cloud-init configured to preserve SELinux disabled state"
        fi
    fi

    #---------------------------------------------------------------------------
    print_step "7" "Update Root Password (Optional)"
    #---------------------------------------------------------------------------
    
    echo ""
    read -p "  Enter new root password (leave blank to skip): " new_root_password
    
    if [[ -n "$new_root_password" ]]; then
        if echo "root:$new_root_password" | chpasswd; then
            print_ok "Root password updated successfully"
        else
            print_error "Failed to update root password"
        fi
    else
        print_info "Root password unchanged"
    fi

    #---------------------------------------------------------------------------
    echo ""
    echo -e "${Green}${Bold}✓ Initialization completed successfully${Reset}"
    echo ""
}

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

# Install desktop environments and GUI applications
# Install Xfce Desktop Environment
function install_xfce_desktop() {
    print_header "Xfce Desktop Environment Installation"

    if command -v xfce4-session >/dev/null 2>&1; then
        print_ok "Xfce Desktop Environment already installed"
        return 0
    fi

    echo ""
    read -p "  Install Xfce Desktop Environment? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        return
    fi

    #---------------------------------------------------------------------------
    print_step "1" "Installing Xfce Desktop Environment"
    #---------------------------------------------------------------------------
    if dnf groupinstall -y "Xfce" &>/dev/null; then
        print_ok "Xfce Desktop Environment installed"
    else
        print_error "Failed to install Xfce Desktop Environment"
        return 1
    fi

    #---------------------------------------------------------------------------
    print_step "2" "Setting Default Target"
    #---------------------------------------------------------------------------
    systemctl set-default graphical.target &>/dev/null
    print_ok "Graphical target set as default"

    echo ""
    echo -e "${Green}${Bold}✓ Xfce Desktop Environment installation completed${Reset}"
    echo ""
}

# Install MATE Desktop Environment
function install_mate_desktop() {
    print_header "MATE Desktop Environment Installation"

    if command -v mate-session >/dev/null 2>&1; then
        print_ok "MATE Desktop Environment already installed"
        return 0
    fi

    echo ""
    read -p "  Install MATE Desktop Environment? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        return
    fi

    local mate_packages=(
        abrt-desktop abrt-java-connector adwaita-gtk2-theme alsa-plugins-pulseaudio 
        atril atril-caja atril-thumbnailer caja caja-actions 
        caja-image-converter caja-open-terminal caja-sendto caja-wallpaper caja-xattr-tags 
        dconf-editor engrampa eom firewall-config 
        gnome-disk-utility gnome-epub-thumbnailer gstreamer1-plugins-ugly-free gtk2-engines 
        gucharmap gvfs-afc gvfs-afp gvfs-archive 
        gvfs-fuse gvfs-gphoto2 gvfs-mtp gvfs-smb initial-setup-gui 
        libmatekbd libmatemixer libmateweather libsecret lm_sensors marco mate-applets 
        mate-backgrounds mate-calc mate-control-center mate-desktop mate-dictionary 
        mate-disk-usage-analyzer mate-icon-theme mate-media 
        mate-menus mate-menus-preferences-category-menu mate-notification-daemon 
        mate-panel mate-polkit mate-power-manager mate-screensaver 
        mate-screenshot mate-search-tool mate-session-manager mate-settings-daemon 
        mate-system-log mate-system-monitor mate-terminal mate-themes 
        mate-user-admin mate-user-guide mozo network-manager-applet 
        nm-connection-editor pluma seahorse seahorse-caja 
        xdg-user-dirs-gtk slick-greeter-mate  
    )

    #---------------------------------------------------------------------------
    print_step "1" "Installing MATE Desktop Environment"
    #---------------------------------------------------------------------------
    print_info "Installing ${#mate_packages[@]} MATE packages..."
    install_applications "${mate_packages[@]}"

    #---------------------------------------------------------------------------
    print_step "2" "Setting Default Target"
    #---------------------------------------------------------------------------
    systemctl set-default graphical.target &>/dev/null
    print_ok "Graphical target set as default"

    echo ""
    echo -e "${Green}${Bold}✓ MATE Desktop Environment installation completed${Reset}"
    echo ""
}

# Install GNOME Desktop Environment
function install_gnome_desktop() {
    print_header "GNOME Desktop Environment Installation"

    if command -v gnome-session >/dev/null 2>&1; then
        print_ok "GNOME Desktop Environment already installed"
        return 0
    fi

    echo ""
    read -p "  Install GNOME Desktop Environment? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        return
    fi

    #---------------------------------------------------------------------------
    print_step "1" "Installing GNOME Desktop Environment"
    #---------------------------------------------------------------------------
    if dnf groupinstall -y "Server with GUI" &>/dev/null; then
        print_ok "GNOME Desktop Environment installed"
    else
        print_error "Failed to install GNOME Desktop Environment"
        return 1
    fi

    #---------------------------------------------------------------------------
    print_step "2" "Installing Additional GNOME Packages"
    #---------------------------------------------------------------------------
    local gnome_extras=(
        gnome-tweaks gnome-extensions-app gnome-shell-extension-appindicator
        gnome-terminal-nautilus file-roller-nautilus
    )
    install_applications "${gnome_extras[@]}"

    #---------------------------------------------------------------------------
    print_step "3" "Setting Default Target"
    #---------------------------------------------------------------------------
    systemctl set-default graphical.target &>/dev/null
    print_ok "Graphical target set as default"

    echo ""
    echo -e "${Green}${Bold}✓ GNOME Desktop Environment installation completed${Reset}"
    echo ""
}

# Install Desktop Applications
function install_desktop_applications() {
    print_header "Desktop Applications Installation"

    # Check for desktop environment
    local desktop_name=""
    if command -v xfce4-session &>/dev/null; then
        desktop_name="Xfce"
    elif command -v mate-session &>/dev/null; then
        desktop_name="MATE"
    elif command -v gnome-session &>/dev/null; then
        desktop_name="GNOME"
    fi

    if [[ -z "$desktop_name" ]]; then
        print_warn "No desktop environment detected"
        print_info "Please install a desktop environment first"
        return 1
    fi

    print_ok "$desktop_name desktop detected"

    echo ""
    read -p "  Install desktop applications (browsers, editors, etc.)? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        return
    fi

    #---------------------------------------------------------------------------
    print_step "1" "Adding Third-Party Repositories"
    #---------------------------------------------------------------------------

    # Tilix repository
    cat <<EOF > /etc/yum.repos.d/tilix.repo
[ivoarch-Tilix]
name=Copr repo for Tilix owned by ivoarch
baseurl=https://copr-be.cloud.fedoraproject.org/results/ivoarch/Tilix/epel-7-\$basearch/
type=rpm-md
skip_if_unavailable=True
gpgcheck=0
gpgkey=https://copr-be.cloud.fedoraproject.org/results/ivoarch/Tilix/pubkey.gpg
repo_gpgcheck=0
enabled=1
enabled_metadata=1
EOF
    print_ok "Tilix repository added"

    # Sublime Text repository
    rpm -v --import https://download.sublimetext.com/sublimehq-rpm-pub.gpg 2>/dev/null
    if dnf config-manager --add-repo https://download.sublimetext.com/rpm/stable/x86_64/sublime-text.repo &>/dev/null; then
        print_ok "Sublime Text repository added"
    else
        print_warn "Failed to add Sublime Text repository"
    fi

    # Google Chrome repository
    cat <<EOF > /etc/yum.repos.d/google-chrome.repo
[google-chrome]
name=Google Chrome
baseurl=https://dl.google.com/linux/chrome/rpm/stable/x86_64
enabled=1
gpgcheck=0
gpgkey=https://dl-ssl.google.com/linux/linux_signing_key.pub
EOF
    print_ok "Google Chrome repository added"

    #---------------------------------------------------------------------------
    print_step "2" "Installing Desktop Applications"
    #---------------------------------------------------------------------------
    local desktop_apps=(
        "firefox" "thunderbird" "vlc" "gimp" "file-roller" "nautilus" 
        "ristretto" "transmission-gtk" "hexchat" "gnome-calculator" 
        "evince" "pluma-plugins" "engrampa" "tilix" "sublime-text"
        "filezilla" "google-chrome-stable" "libreoffice"
    )

    print_info "Installing ${#desktop_apps[@]} desktop applications..."
    install_applications "${desktop_apps[@]}" 

    echo ""
    echo -e "${Green}${Bold}✓ Desktop Applications installation completed${Reset}"
    echo ""
}

# Desktop Environment menu
function install_desktop() {
    print_header "Desktop Environment Installation"

    while true; do
        echo ""
        local desktop_options=(
            "Install Xfce Desktop"
            "Install MATE Desktop"
            "Install GNOME Desktop"
            "Install Desktop Applications"
            "Back to main menu"
        )

        show_menu "Desktop Environment Options" "${desktop_options[@]}"

        case $menu_index in
            0) install_xfce_desktop;;
            1) install_mate_desktop;;
            2) install_gnome_desktop;;
            3) install_desktop_applications;;
            4) return;;
        esac
    done
}

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
        declare -A sssd_settings=(
            ["ipa_dyndns_update"]="True"
        )
        update_sssd_settings

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
            ["dyndns_update"]="True"
            ["dyndns_refresh_interval"]="43200"
            ["dyndns_update_ptr"]="True"
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

# Install Docker CE
function install_docker_ce() {
    print_header "Docker CE Installation"
    
    local os_version
    os_version=$(rpm -E %rhel)
    
    #---------------------------------------------------------------------------
    print_step "1" "Installing Docker CE"
    #---------------------------------------------------------------------------
    
    if command -v docker >/dev/null 2>&1; then
        docker_version=$(docker --version 2>/dev/null | cut -d' ' -f3 | tr -d ',')
        compose_version=$(docker compose version 2>/dev/null | cut -d' ' -f4)
        print_ok "Docker CE already installed (v$docker_version)"
        [[ -n "$compose_version" ]] && print_ok "Docker Compose (v$compose_version)"
    else
        # Add Docker repository based on region
        if [[ "$COUNTRY" == "CN" ]]; then
            # Overwrite with Aliyun
            cat <<EOF | sudo tee /etc/yum.repos.d/docker-ce.repo
[docker-ce-stable]
name=Docker CE Stable - \$basearch
baseurl=https://mirrors.aliyun.com/docker-ce/linux/centos/9/\$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://mirrors.aliyun.com/docker-ce/linux/centos/gpg
EOF
            print_ok "Docker CE repository (NJU mirror)"
        else
            dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo &>/dev/null
            print_ok "Docker CE repository added"
        fi
        
        # Install Docker CE and plugins
        if dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin &>/dev/null; then
            systemctl enable docker &>/dev/null
            systemctl start docker &>/dev/null
            
            docker_version=$(docker --version 2>/dev/null | cut -d' ' -f3 | tr -d ',')
            compose_version=$(docker compose version 2>/dev/null | cut -d' ' -f4)
            print_ok "Docker CE installed (v$docker_version)"
            print_ok "Docker Compose (v$compose_version)"
            print_ok "Docker service enabled and started"
        else
            print_error "Failed to install Docker CE"
        fi
    fi
    
    echo ""
    echo -e "${Green}${Bold}✓ Docker CE installation completed${Reset}"
    echo ""
}

# Install Python 3.9+
function install_python39() {
    print_header "Python 3.9+ Installation"
    
    #---------------------------------------------------------------------------
    print_step "1" "Installing Python 3.9+"
    #---------------------------------------------------------------------------
    
    current_python=""
    if command -v python3 >/dev/null 2>&1; then
        current_python=$(python3 --version 2>&1 | awk '{print $2}')
        python_major=$(echo "$current_python" | cut -d. -f1)
        python_minor=$(echo "$current_python" | cut -d. -f2)
        
        if [[ "$python_major" -ge 3 && "$python_minor" -ge 9 ]]; then
            print_ok "Python $current_python already installed"
        else
            print_info "Current Python $current_python is older than 3.9"
        fi
    fi
    
    if ! command -v python3.11 >/dev/null 2>&1; then
        print_info "Installing Python 3.11..."
        if dnf install -y python3.11 python3.11-pip python3.11-devel &>/dev/null; then
            print_ok "Python 3.11 installed"
            print_info "Use 'python3.11' or 'pip3.11' to access Python 3.11"
        else
            print_warn "Failed to install Python 3.11, trying Python 3.9..."
            if dnf install -y python3.9 python3.9-pip python3.9-devel &>/dev/null; then
                print_ok "Python 3.9 installed"
                print_info "Use 'python3.9' or 'pip3.9' to access Python 3.9"
            else
                print_error "Failed to install Python 3.9+"
            fi
        fi
    else
        print_ok "Python 3.11 already installed"
    fi
    
    if command -v python3.11 >/dev/null 2>&1; then
        py_version=$(python3.11 --version 2>&1)
        print_ok "$py_version available as python3.11"
    elif command -v python3.9 >/dev/null 2>&1; then
        py_version=$(python3.9 --version 2>&1)
        print_ok "$py_version available as python3.9"
    fi
    
    echo ""
    echo -e "${Green}${Bold}✓ Python installation completed${Reset}"
    echo ""
}

# Install compilers and build tools
function install_compilers() {
    print_header "Compilers and Build Tools Installation"
    
    #---------------------------------------------------------------------------
    print_step "1" "Installing Development Tools Group"
    #---------------------------------------------------------------------------
    if dnf groupinstall -y "Development Tools" &>/dev/null; then
        print_ok "Development Tools group installed"
    else
        print_error "Failed to install Development Tools group"
    fi
    
    #---------------------------------------------------------------------------
    print_step "2" "Installing Development Libraries"
    #---------------------------------------------------------------------------
    
    local dev_packages=(
        "kernel-devel" "kernel-headers" "bison" "flex" "gdb" "strace" 
        "ltrace" "valgrind" "ncurses-devel" "libtool" "pkgconfig" 
        "openssl-devel"  "libcurl-devel" "libxml2-devel" 
        "zlib-devel" "bzip2-devel"  "xz-devel"  "libffi-devel"
        "python3-devel"  "perl-devel"  "java-11-openjdk-devel"
        "gcc" "make" "ncurses-devel" "gnutls-devel" "libX11-devel" "libXext-devel" 
        "libXfixes-devel" "libXft-devel" "libXt-devel" "libXi-devel" "gtk3-devel" 
        "libpng-devel" "libjpeg-turbo-devel" "giflib-devel" 
        "libtiff-devel" "hunspell" "hunspell-en"
    )
    
    print_info "Installing ${#dev_packages[@]} packages..."
    install_applications "${dev_packages[@]}"
    
    echo ""
    echo -e "${Green}${Bold}✓ Compilers and build tools installation completed${Reset}"
    echo ""
}

# Install Visual Studio Code
function install_vscode() {
    print_header "Visual Studio Code Installation"
    
    #---------------------------------------------------------------------------
    print_step "1" "Installing Visual Studio Code"
    #---------------------------------------------------------------------------
    if ! command -v code &>/dev/null; then
        rpm -v --import https://packages.microsoft.com/keys/microsoft.asc 2>/dev/null
        cat <<EOF > /etc/yum.repos.d/vscode.repo
[code]
name=Visual Studio Code
baseurl=https://packages.microsoft.com/yumrepos/vscode
enabled=1
gpgcheck=1
gpgkey=https://packages.microsoft.com/keys/microsoft.asc
EOF
        if dnf install -y code &>/dev/null; then
            print_ok "Visual Studio Code installed"
        else
            print_error "Failed to install Visual Studio Code"
        fi
    else
        print_ok "Visual Studio Code (already installed)"
    fi

    #---------------------------------------------------------------------------
    print_step "2" "Configuring VS Code launch options"
    #---------------------------------------------------------------------------
    if [[ -f /usr/bin/code ]]; then
        local proxy_line=""
        local vscode_opts="--disable-gpu"
        
        # Check if proxy is configured in yum.conf
        if grep -q '^proxy=' /etc/yum.conf; then
            proxy_line=$(grep '^proxy=' /etc/yum.conf | head -1 | cut -d'=' -f2)
            if [[ -n "$proxy_line" ]]; then
                vscode_opts="--disable-gpu --proxy-server=$proxy_line"
            fi
        fi
        
        # Check if options already configured
        if ! grep -qF 'VSCODE_CLI_OPTIONS' /usr/bin/code; then
            # Backup original
            cp /usr/bin/code /usr/bin/code.bak
            
            # Create patched version with options
            cat > /usr/bin/code <<'ENDOFCODE'
#!/usr/bin/env bash
# Patched by rocky-setup.sh - VS Code launch options
ENDOFCODE
            echo "VSCODE_CLI_OPTIONS=\"$vscode_opts\"" >> /usr/bin/code
            cat >> /usr/bin/code <<'ENDOFCODE'

# Get the actual code binary path
VSCODE_PATH="$(dirname "$(readlink -f "$0")")"
if [[ -f "$VSCODE_PATH/code.bak" ]]; then
    ELECTRON_RUN_AS_NODE=1 exec "$VSCODE_PATH/code.bak" "$VSCODE_PATH/code.bak" $VSCODE_CLI_OPTIONS "$@"
else
    ELECTRON="$VSCODE_PATH/../lib/code/code"
    CLI="$VSCODE_PATH/../lib/code/out/cli.js"
    ELECTRON_RUN_AS_NODE=1 exec "$ELECTRON" "$CLI" $VSCODE_CLI_OPTIONS "$@"
fi
ENDOFCODE
            chmod +x /usr/bin/code
            print_ok "VS Code configured with: $vscode_opts"
        else
            print_ok "VS Code launch options already configured"
        fi
    else
        print_warn "/usr/bin/code not found for launch option patching"
    fi
    
    echo ""
    echo -e "${Green}${Bold}✓ Visual Studio Code installation completed${Reset}"
    echo ""
}

# Install EDA (Electronic Design Automation) libraries
function install_eda_libraries() {
    print_header "EDA Libraries Installation"
    
    #---------------------------------------------------------------------------
    print_step "1" "Installing EDA (Electronic Design Automation) Packages"
    #---------------------------------------------------------------------------
    
    local eda_packages=(
        "gtkwave" "gdk-pixbuf2" "gdk-pixbuf2.i686" "gtk2" "gtk2.i686"
        "gtk3" "gtk3.i686" "motif" "motif.i686" "libXpm" "libXpm.i686"
        "libXScrnSaver" "libXScrnSaver.i686" "glibc.i686" "glibc-devel.i686"
        "libstdc++.i686" "libgcc.i686" "libusb.i686" "krb5-libs.i686"
        "libICE.i686" "libSM.i686" "libXau.i686" "libXext.i686" "libXft.i686"
        "libXt.i686" "libXrender.i686" "libXcursor.i686" "libXrandr.i686"
        "libmount.i686" "libsepol.i686" "graphite2.i686" "harfbuzz.i686"
        "jbigkit-libs.i686" "jasper-libs.i686" "libvpx.i686"
        "libwayland-client.i686" "libwayland-server.i686"
        "libsigc++20" "libsigc++20-devel" "glibmm24" "glibmm24-devel"
        "libmount-devel" "gperf" "webkit2gtk3" "webkit2gtk3-devel"
        "libvpx" "libvpx-devel" "libwayland-client" "libwayland-server"
        "mariadb-server" "mariadb" "php" "php-cli" "php-common" "libqb"
        "ipmitool" "vsftpd" "links" "ntfs-3g" "gc" "gc-devel"
    )

    print_info "Installing ${#eda_packages[@]} EDA packages..."
    install_applications "${eda_packages[@]}"
    
    echo ""
    echo -e "${Green}${Bold}✓ EDA libraries installation completed${Reset}"
    echo ""
}

# Install development tools and libraries
function install_devtools() {
    print_header "Development Tools Installation"

    while true; do
        local devtools_options=(
            "Install Compilers and Build Tools" 
            "Install Python 3.9+" 
            "Install Docker CE" 
            "Install VS Code" 
            "Install EDA Libraries" 
            "Install All" 
            "Back to main menu"
        )
        show_menu "Development Tools Options" 7 "${devtools_options[@]}"

        case $menu_index in
            0) install_compilers;;
            1) install_python39;;
            2) install_docker_ce;;
            3) install_vscode;;
            4) install_eda_libraries;;
            5) 
                install_compilers
                install_python39
                install_docker_ce
                install_vscode
                install_eda_libraries
                echo ""
                echo -e "${Green}${Bold}✓ All development tools installation completed${Reset}"
                echo ""
                ;;
            6) return;;
        esac
    done
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
        fi
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

# Install xrdp remote desktop
function install_xrdp() {
    print_header "xrdp Remote Desktop Installation"

    if rpm -q --quiet xrdp; then
        print_ok "xrdp already installed"
        return 0
    fi

    local allow_clipboard="N"
    local allow_drivemap="N"

    while true; do
        echo ""
        printf "  ${Cyan}1.${Reset} Allow clipboard (cut/copy from server)? "
        read -p "[y/N]: " clipboard_input
        [[ "$clipboard_input" =~ ^[Yy]$ ]] && allow_clipboard="Y"

        printf "  ${Cyan}2.${Reset} Allow drive mapping (map remote drives)? "
        read -p "[y/N]: " drivemap_input
        [[ "$drivemap_input" =~ ^[Yy]$ ]] && allow_drivemap="Y"

        local summary_items=(
            "Clipboard:     $allow_clipboard"
            "Drive Mapping: $allow_drivemap"
        )
        print_summary "xrdp Configuration" "${summary_items[@]}"

        echo ""
        read -p "  Proceed with installation? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            break
        else
            read -p "  Return to remote desktop menu? [y/N]: " return_menu
            [[ "$return_menu" =~ ^[Yy]$ ]] && return
        fi
    done

    #---------------------------------------------------------------------------
    print_step "1" "Installing xrdp packages"
    #---------------------------------------------------------------------------
    local xrdp_packages=("tigervnc" "tigervnc-server" "xrdp")
    install_applications "${xrdp_packages[@]}"

    #---------------------------------------------------------------------------
    print_step "2" "Configuring xrdp"
    #---------------------------------------------------------------------------
    local xrdp_ini="/etc/xrdp/xrdp.ini"

    sed -i 's/^allow_channels=.*/allow_channels=true/' "$xrdp_ini" 2>/dev/null || echo "allow_channels=true" >> "$xrdp_ini"

    if [[ "$allow_drivemap" == "Y" ]]; then
        sed -i 's/^rdpdr=.*/rdpdr=true/' "$xrdp_ini" 2>/dev/null
    else
        sed -i 's/^rdpdr=.*/rdpdr=false/' "$xrdp_ini" 2>/dev/null
    fi

    sed -i 's/^rdpsnd=.*/rdpsnd=true/' "$xrdp_ini" 2>/dev/null

    if [[ "$allow_clipboard" == "Y" ]]; then
        sed -i 's/^cliprdr=.*/cliprdr=true/' "$xrdp_ini" 2>/dev/null
    else
        sed -i 's/^cliprdr=.*/cliprdr=false/' "$xrdp_ini" 2>/dev/null
    fi

    print_ok "xrdp.ini configured"

    #---------------------------------------------------------------------------
    print_step "3" "Configuring Firewall"
    #---------------------------------------------------------------------------
    firewall-cmd --permanent -q --add-port=3389/tcp
    firewall-cmd -q --reload
    print_ok "Port 3389/tcp opened"

    #---------------------------------------------------------------------------
    print_step "4" "Starting xrdp Service"
    #---------------------------------------------------------------------------
    systemctl enable xrdp -q
    systemctl restart xrdp -q
    print_ok "xrdp service enabled and started"

    #---------------------------------------------------------------------------
    print_step "5" "Configuring User Session"
    #---------------------------------------------------------------------------
    echo "mate-session" > /etc/skel/.Xclients
    chmod a+x /etc/skel/.Xclients
    print_ok "Default session set to MATE"

    # Update existing user homes
    for user_home in /home/*; do
        if [[ -d "$user_home" ]]; then
            local user=$(basename "$user_home")
            cp /etc/skel/.Xclients "$user_home/.Xclients"
            chown "$user:" "$user_home/.Xclients"
            chmod a+x "$user_home/.Xclients"
        fi
    done
    print_ok "Existing user homes updated"

    echo ""
    echo -e "${Green}${Bold}✓ xrdp installation completed${Reset}"
    echo ""
}
 

# Install ETX Connection Node
function install_etx_node() {
    print_header "ETX Connection Node Installation"

    local etx_cn_path="/opt/etx/cn"
    local install_path="/opt/etx/packages"
    local http_base="https://download.creekside.network/resource/apps/etx"
    local http_user="downloader"
    local http_pass="Khyp04682"
    mkdir -p "$install_path"

    if systemctl is-enabled otetxcn.service &>/dev/null; then
        print_ok "ETX Connection Node already installed at $etx_cn_path"
        return 0
    fi

    #---------------------------------------------------------------------------
    print_step "1" "Checking Available Versions"
    #---------------------------------------------------------------------------
    local etx_versions=()
    
    while read -r dirname; do
        # Filter for version-like directories (e.g., 12.5.3, 12.5.4)
        if [[ "$dirname" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            etx_versions+=("$dirname")
        fi
    done < <(curl --silent --user "$http_user:$http_pass" "$http_base/" 2>/dev/null | grep -oP 'href="\K[0-9]+\.[0-9]+\.[0-9]+(?=/")')

    if [[ ${#etx_versions[@]} -eq 0 ]]; then
        print_error "No ETX versions found"
        return 1
    fi

    # Sort versions and show menu
    IFS=$'\n' etx_versions=($(sort -V <<<"${etx_versions[*]}")); unset IFS
    
    echo ""
    show_menu "Select ETX version" 1 "${etx_versions[@]}"
    local selected_version="${etx_versions[$menu_index]}"
    print_info "Selected version: $selected_version"

    #---------------------------------------------------------------------------
    print_step "2" "Finding Linux Package"
    #---------------------------------------------------------------------------
    local etx_file=""
    
    local search_paths=(
        "$http_base/$selected_version/ETXConnectionNode/"
        "$http_base/$selected_version/"
    )
    
    for search_path in "${search_paths[@]}"; do
        while read -r filename; do
            if [[ "$filename" == *"linux-x64"* && "$filename" == *".tar.gz" ]]; then
                etx_file="$filename"
                print_info "Found package: $etx_file"
                break 2
            fi
        done < <(curl --silent --user "$http_user:$http_pass" "$search_path" 2>/dev/null | grep -oP 'href="\K[^"]+linux-x64[^"]*\.tar\.gz')
    done

    if [[ -z "$etx_file" ]]; then
        print_error "No Linux package found for version $selected_version"
        return 1
    fi

    #---------------------------------------------------------------------------
    print_step "3" "Downloading Package"
    #---------------------------------------------------------------------------
    local download_url="$http_base/$selected_version/ETXConnectionNode/$etx_file"
    local install_file="$install_path/$etx_file"
    
    curl -# --user "$http_user:$http_pass" "$download_url" -o "$install_file"

    if [[ ! -f "$install_file" ]] || [[ ! -s "$install_file" ]]; then
        print_error "Download failed"
        return 1
    fi
    print_ok "Downloaded: $etx_file"

    #---------------------------------------------------------------------------
    print_step "4" "Installing ETX Connection Node"
    #---------------------------------------------------------------------------
    mkdir -p "$etx_cn_path"
    tar xzf "$install_file" --strip-components=1 -C "$etx_cn_path"

    local work_dir=$(mktemp -d)
    cat > "$work_dir/install_options" <<EOF
install.etxcn.ListenPort=5510
install.etxcn.StartNow=1
install.etxcn.AllowMigrate=0
install.etxcn.CreateETXProxyUser=0
install.etxcn.CreateETXXstartUser=0
install.service.createservice=1
install.service.bBootStart=1
install.register.bAutoRegister=0
install.register.r_WebAdaptor=0
install.register.WebAdaptorPort=5510
install.register.r_auth=0
install.register.r_appscan=0
install.register.r_firstdisplay=1
install.register.r_maxtotalsessions=30
install.register.r_maxsessperuser=2
install.register.r_allownewsess=1
install.register.r_ssrconfig=0
install.register.r_selinuxsetup=0
install.register.r_vdinode=0
EOF
    "$etx_cn_path/bin/install" -s "$work_dir/install_options" &>/dev/null
    print_ok "ETX Connection Node installed"

    #---------------------------------------------------------------------------
    print_step "5" "Configuring Authentication"
    #---------------------------------------------------------------------------
    cp /etc/pam.d/sshd /etc/pam.d/exceed-connection-node
    print_ok "PAM authentication configured"

    echo 'ulimit -c 0 > /dev/null 2>&1' > /etc/profile.d/disable-coredumps.sh
    print_ok "Core dumps disabled"

    #---------------------------------------------------------------------------
    print_step "5" "Configuring Firewall"
    #---------------------------------------------------------------------------
    firewall-cmd -q --permanent --add-port=5510/tcp
    firewall-cmd -q --reload
    print_ok "Port 5510/tcp opened"

    rm -rf "$work_dir"

    echo ""
    echo -e "${Green}${Bold}✓ ETX Connection Node installation completed${Reset}"
    echo ""
}

# Install ETX Server
function install_etx_server() {
    print_header "ETX Server Installation"

    local install_path="/opt/etx/packages"
    local http_base="https://download.creekside.network/resource/apps/etx"
    local http_user="downloader"
    local http_pass="Khyp04682"
    mkdir -p "$install_path"

    if systemctl is-enabled otetxsvr.service &>/dev/null; then
        print_ok "ETX Server already installed"
        return 0
    fi

    local etx_admin_passwd="Good2Great"
    local standalone="Y"

    while true; do
        echo ""
        printf "  ${Cyan}1.${Reset} Standalone mode (N for cluster)? "
        read -p "[Y/n]: " standalone_input
        [[ "$standalone_input" =~ ^[Nn]$ ]] && standalone="N" || standalone="Y"

        printf "  ${Cyan}2.${Reset} ETX admin password "
        read -p "[$etx_admin_passwd]: " passwd_input
        [[ -n "$passwd_input" ]] && etx_admin_passwd="$passwd_input"

        local summary_items=(
            "Mode:           $([ "$standalone" == "Y" ] && echo "Standalone" || echo "Cluster")"
            "Admin Password: $etx_admin_passwd"
        )
        print_summary "ETX Server Configuration" "${summary_items[@]}"

        echo ""
        read -p "  Proceed with installation? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            break
        else
            read -p "  Return to remote desktop menu? [y/N]: " return_menu
            [[ "$return_menu" =~ ^[Yy]$ ]] && return
        fi
    done

    #---------------------------------------------------------------------------
    print_step "1" "Checking Available Versions"
    #---------------------------------------------------------------------------
    local etx_versions=()
    
    # List version directories (12.5.3, 12.5.4, etc.)
    while read -r dirname; do
        # Filter for version-like directories (e.g., 12.5.3, 12.5.4)
        if [[ "$dirname" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            etx_versions+=("$dirname")
        fi
    done < <(curl --silent --user "$http_user:$http_pass" "$http_base/" 2>/dev/null | grep -oP 'href="\K[0-9]+\.[0-9]+\.[0-9]+(?=/")')

    if [[ ${#etx_versions[@]} -eq 0 ]]; then
        print_error "No ETX versions found"
        return 1
    fi

    # Sort versions and show menu
    IFS=$'\n' etx_versions=($(sort -V <<<"${etx_versions[*]}")); unset IFS
    
    echo ""
    show_menu "Select ETX version" 1 "${etx_versions[@]}"
    local selected_version="${etx_versions[$menu_index]}"
    print_info "Selected version: $selected_version"

    #---------------------------------------------------------------------------
    print_step "2" "Finding Linux Package"
    #---------------------------------------------------------------------------
    local etx_file=""
    
    # Look for linux-x64 package in ETXServer directory
    local search_paths=(
        "$http_base/$selected_version/ETXServer/"
        "$http_base/$selected_version/"
    )
    
    for search_path in "${search_paths[@]}"; do
        while read -r filename; do
            if [[ "$filename" == *"linux-x64"* && "$filename" == *".tar.gz" ]]; then
                etx_file="$filename"
                print_info "Found package: $etx_file"
                break 2
            fi
        done < <(curl --silent --user "$http_user:$http_pass" "$search_path" 2>/dev/null | grep -oP 'href="\K[^"]+linux-x64[^"]*\.tar\.gz')
    done

    if [[ -z "$etx_file" ]]; then
        print_error "No Linux package found for version $selected_version"
        return 1
    fi

    #---------------------------------------------------------------------------
    print_step "3" "Downloading Package"
    #---------------------------------------------------------------------------
    local download_url="$http_base/$selected_version/ETXServer/$etx_file"
    local install_file="$install_path/$etx_file"
    
    curl -# --user "$http_user:$http_pass" "$download_url" -o "$install_file"

    if [[ ! -f "$install_file" ]] || [[ ! -s "$install_file" ]]; then
        print_error "Download failed"
        return 1
    fi
    print_ok "Downloaded: $etx_file"

    #---------------------------------------------------------------------------
    print_step "4" "Installing ETX Server"
    #---------------------------------------------------------------------------
    local etx_svr_path="/opt/etx/svr"
    mkdir -p "$etx_svr_path"
    tar xzf "$install_file" --strip-components=1 -C "$etx_svr_path"

    if [[ "$standalone" == "Y" ]]; then
        "$etx_svr_path/bin/etxsvr" datastore init
        "$etx_svr_path/bin/etxsvr" bootstart enable
        "$etx_svr_path/bin/etxsvr" config eulaAccepted=1
        "$etx_svr_path/bin/etxsvr" etxadmin setpasswd -p "$etx_admin_passwd"
        print_ok "Standalone mode configured"
    fi

    #---------------------------------------------------------------------------
    print_step "5" "Configuring Firewall"
    #---------------------------------------------------------------------------
    firewall-cmd -q --permanent --add-port={5510/tcp,5610/tcp,8080/tcp,8443/tcp}
    firewall-cmd -q --reload
    print_ok "Ports 5510,5610,8080,8443/tcp opened"

    #---------------------------------------------------------------------------
    print_step "6" "Starting ETX Server"
    #---------------------------------------------------------------------------
    "$etx_svr_path/bin/etxsvr" start
    print_ok "ETX Server started"

    echo ""
    echo -e "${Green}${Bold}✓ ETX Server installation completed${Reset}"
    echo ""
}

# Install TurboVNC Server
function install_turbovnc() {
    print_header "TurboVNC Server Installation"

    #---------------------------------------------------------------------------
    # Pre-flight checks
    #---------------------------------------------------------------------------
    
    # Check if already installed
    if rpm -q --quiet turbovnc; then
        print_ok "TurboVNC Server already installed"
        return 0
    fi

    # Check for domain membership (required for UnixLogin authentication)
    local current_domain=$(realm list 2>/dev/null | grep "domain-name" | cut -d ':' -f 2 | xargs)
    if [[ -z "$current_domain" ]]; then
        print_error "System is not joined to a domain (FreeIPA or Active Directory)"
        print_info "TurboVNC with UnixLogin requires domain membership for authentication"
        print_info "Please join a domain first using 'Join Domain (AD/FreeIPA)' option"
        return 1
    fi
    print_ok "Domain membership detected: $current_domain"

    # Detect installed desktop environments
    local available_desktops=()
    local desktop_sessions=()
    
    if command -v xfce4-session &>/dev/null; then
        available_desktops+=("Xfce")
        desktop_sessions+=("xfce")
    fi
    if command -v mate-session &>/dev/null; then
        available_desktops+=("MATE")
        desktop_sessions+=("mate")
    fi
    if command -v gnome-session &>/dev/null; then
        available_desktops+=("GNOME")
        desktop_sessions+=("gnome")
    fi
    if [[ -f /usr/share/xsessions/gnome-classic.desktop ]]; then
        available_desktops+=("GNOME Classic")
        desktop_sessions+=("gnome-classic")
    fi

    if [[ ${#available_desktops[@]} -eq 0 ]]; then
        print_error "No desktop environment detected"
        print_info "Please install a desktop environment first"
        return 1
    fi

    #---------------------------------------------------------------------------
    # User configuration
    #---------------------------------------------------------------------------
    local selected_desktop=""
    local selected_session=""
    local allow_copy="N"
    local allow_paste="Y"

    while true; do
        echo ""
        echo -e "${Dim}Available desktop environments:${Reset}"
        for i in "${!available_desktops[@]}"; do
            printf "  ${Cyan}%d)${Reset} %s\n" "$((i+1))" "${available_desktops[$i]}"
        done

        echo ""
        read -p "  Select desktop environment [1-${#available_desktops[@]}]: " desktop_num
        
        if ! [[ "$desktop_num" =~ ^[0-9]+$ ]] || (( desktop_num < 1 || desktop_num > ${#available_desktops[@]} )); then
            print_warn "Invalid selection"
            continue
        fi

        selected_desktop="${available_desktops[$((desktop_num-1))]}"
        selected_session="${desktop_sessions[$((desktop_num-1))]}"

        # Clipboard configuration
        echo ""
        printf "  ${Cyan}Clipboard Settings:${Reset}\n"
        printf "    Allow copy (server -> viewer)? "
        read -p "[y/N]: " copy_input
        [[ "$copy_input" =~ ^[Yy]$ ]] && allow_copy="Y" || allow_copy="N"

        printf "    Allow paste (viewer -> server)? "
        read -p "[Y/n]: " paste_input
        [[ "$paste_input" =~ ^[Nn]$ ]] && allow_paste="N" || allow_paste="Y"

        # Build clipboard summary
        local clipboard_summary=""
        if [[ "$allow_copy" == "Y" && "$allow_paste" == "Y" ]]; then
            clipboard_summary="Copy & Paste enabled"
        elif [[ "$allow_copy" == "Y" ]]; then
            clipboard_summary="Copy only (server -> viewer)"
        elif [[ "$allow_paste" == "Y" ]]; then
            clipboard_summary="Paste only (viewer -> server)"
        else
            clipboard_summary="Disabled"
        fi

        local summary_items=(
            "Domain:         $current_domain"
            "Desktop:        $selected_desktop"
            "Session Type:   $selected_session"
            "Config File:    /opt/TurboVNC/config/vncuser.conf"
            "Authentication: UnixLogin (PAM/Domain)"
            "Clipboard:      $clipboard_summary"
            "Security:       TLS encrypted"
        )
        print_summary "TurboVNC Configuration" "${summary_items[@]}"

        echo ""
        read -p "  Proceed with installation? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            break
        else
            read -p "  Return to remote desktop menu? [y/N]: " return_menu
            [[ "$return_menu" =~ ^[Yy]$ ]] && return
        fi
    done

    #---------------------------------------------------------------------------
    print_step "1" "Downloading TurboVNC Package"
    #---------------------------------------------------------------------------
    local work_dir=$(mktemp -d)
    local turbovnc_version=""
    local turbovnc_rpm=""
    
    # Get latest release from GitHub API
    local release_info=$(curl -s "https://api.github.com/repos/TurboVNC/turbovnc/releases/latest" 2>/dev/null)
    turbovnc_version=$(echo "$release_info" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
    
    if [[ -z "$turbovnc_version" ]]; then
        print_error "Failed to get TurboVNC version from GitHub"
        rm -rf "$work_dir"
        return 1
    fi
    print_info "Latest version: $turbovnc_version"
    
    # Download RPM for x86_64
    turbovnc_rpm="turbovnc-${turbovnc_version}.x86_64.rpm"
    local download_url="https://github.com/TurboVNC/turbovnc/releases/download/${turbovnc_version}/${turbovnc_rpm}"
    
    if ! curl -L -# -o "$work_dir/$turbovnc_rpm" "$download_url" 2>/dev/null; then
        print_error "Failed to download TurboVNC package"
        rm -rf "$work_dir"
        return 1
    fi
    
    if [[ ! -s "$work_dir/$turbovnc_rpm" ]]; then
        print_error "Downloaded package is empty"
        rm -rf "$work_dir"
        return 1
    fi
    print_ok "Downloaded: $turbovnc_rpm"

    #---------------------------------------------------------------------------
    print_step "2" "Installing TurboVNC"
    #---------------------------------------------------------------------------
    if dnf install -y "$work_dir/$turbovnc_rpm" &>/dev/null; then
        print_ok "TurboVNC installed to /opt/TurboVNC"
    else
        print_error "Failed to install TurboVNC"
        rm -rf "$work_dir"
        return 1
    fi

    #---------------------------------------------------------------------------
    print_step "3" "Configuring Security Settings"
    #---------------------------------------------------------------------------
    # Create security configuration file
    cat > /etc/turbovncserver-security.conf <<EOF
# TurboVNC Security Configuration
# Generated by rocky-setup.sh on $(date)

# Allow UnixLogin (PAM) authentication - TLSPlain for encrypted, UnixLogin for unencrypted
permitted-security-types = TLSPlain, UnixLogin

# Enable PAM sessions for proper user login
pam-service-name = turbovnc

# Disable clipboard for security
permitted-clipboard-send = 0
permitted-clipboard-recv = 0

# Disable reverse connections
no-reverse-connections
EOF
    chmod 644 /etc/turbovncserver-security.conf
    print_ok "Security configuration created"

    #---------------------------------------------------------------------------
    print_step "4" "Configuring PAM Authentication"
    #---------------------------------------------------------------------------
    # Create PAM configuration for TurboVNC (must match pam-service-name)
    # Simplified config that works with domain users and remote VNC logins
    cat > /etc/pam.d/turbovnc <<EOF
#%PAM-1.0
# PAM configuration for TurboVNC
# Works with SSSD/FreeIPA/AD domain users
auth       substack     password-auth
auth       include      postlogin
account    required     pam_nologin.so
account    include      password-auth
password   include      password-auth
session    optional     pam_keyinit.so force revoke
session    include      password-auth
EOF
    chmod 644 /etc/pam.d/turbovnc
    print_ok "PAM configuration created"

    # Configure SELinux to allow VNC connections
    if command -v setsebool &>/dev/null; then
        setsebool -P xserver_clients_write_xshm 1 &>/dev/null || true
        setsebool -P xserver_execmem 1 &>/dev/null || true
        setsebool -P authlogin_nsswitch_use_ldap 1 &>/dev/null || true
    fi
    print_ok "SELinux configured for VNC"

    #---------------------------------------------------------------------------
    print_step "5" "Creating Server Configuration"
    #---------------------------------------------------------------------------
    # Create system-wide turbovncserver.conf
    cat > /etc/turbovncserver.conf <<EOF
# TurboVNC Server Configuration
# Generated by rocky-setup.sh on $(date)

# Window manager to use
\$wm = "$selected_session";

# Security settings
\$securityTypes = "TLSPlain,UnixLogin";

# Disable clipboard
\$sendClipboard = 0;
\$recvClipboard = 0;

# Session geometry (can be changed by client)
\$geometry = "1920x1080";

# Enable multi-threading for better performance
# Uses number of CPU cores (up to 4)

# Other settings
\$generateOTP = 0;
\$authTypeVNC = 0;
EOF
    chmod 644 /etc/turbovncserver.conf
    print_ok "Server configuration created"

    #---------------------------------------------------------------------------
    print_step "6" "Creating Systemd Services"
    #---------------------------------------------------------------------------
    # Create a template service for VNC sessions
    cat > /etc/systemd/system/turbovnc@.service <<EOF
[Unit]
Description=TurboVNC Server - Display %i
After=syslog.target network.target sssd.service

[Service]
Type=forking
ExecStart=/opt/TurboVNC/bin/vncserver :%i -securitytypes UnixLogin,TLSPlain -noclipboardsend -noclipboardrecv
ExecStop=/opt/TurboVNC/bin/vncserver -kill :%i
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    print_ok "Systemd template service created"

    # Create a master service to start all VNC sessions
    cat > /etc/systemd/system/turbovnc-sessions.service <<EOF
[Unit]
Description=TurboVNC Multi-Session Startup
After=network-online.target sssd.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 10
ExecStart=/opt/TurboVNC/bin/turbovnc-start-sessions.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    print_ok "Multi-session startup service created"

    # Create config directory and initial vncuser.conf
    mkdir -p /opt/TurboVNC/config
    if [[ ! -f /opt/TurboVNC/config/vncuser.conf ]]; then
        cat > /opt/TurboVNC/config/vncuser.conf <<EOF
# TurboVNC User Session Configuration
# Generated by rocky-setup.sh on $(date)
#
# Format: <username> : <display_id> [: clipboard_options]
#
# Basic format (uses global clipboard defaults):
#   root : 0
#   john.doe : 1
#
# With per-user clipboard overrides:
#   jtong : 1 : copy : paste   (enable both copy and paste)
#   jane : 2 : copy            (enable copy only)
#   bob : 3 : paste            (enable paste only)
#   alice : 4                  (use global defaults)
#
# Clipboard options:
#   copy  = enable copy from server to viewer
#   paste = enable paste from viewer to server
#   (omit option to use global default set during installation)
#
# Display :0 (port 5900) is reserved for root by default
# Display :1 through :99 are available for users (ports 5901-5999)
#
# After editing this file, run:
#   /opt/TurboVNC/bin/turbovnc-start-sessions.sh
# to apply changes (sessions will be stopped/started as needed)
#
root : 0
EOF
        chmod 644 /opt/TurboVNC/config/vncuser.conf
        print_ok "User configuration file created"
    else
        print_ok "User configuration file exists (preserved)"
    fi

    # Create TurboVNC settings configuration file
    cat > /opt/TurboVNC/config/turbovnc.conf <<EOF
# TurboVNC Settings Configuration
# Generated by rocky-setup.sh on $(date)

# Window manager to use for VNC sessions
WM="$selected_session"

# Global clipboard defaults
# Y = enabled, N = disabled
# These are used unless overridden per-user in vncuser.conf
GLOBAL_COPY="$allow_copy"
GLOBAL_PASTE="$allow_paste"
EOF
    chmod 644 /opt/TurboVNC/config/turbovnc.conf
    print_ok "TurboVNC settings configuration created"

    # Download the startup script from GitHub
    local scripts_base_url="https://raw.githubusercontent.com/creeksidenetworks/linux-tools/main/setup/rocky/scripts"
    
    if curl -fsSL "${scripts_base_url}/turbovnc-start-sessions.sh" -o /opt/TurboVNC/bin/turbovnc-start-sessions.sh; then
        chmod 755 /opt/TurboVNC/bin/turbovnc-start-sessions.sh
        print_ok "Startup script downloaded"
    else
        print_error "Failed to download startup script"
        return 1
    fi

    # Download the shutdown script from GitHub
    if curl -fsSL "${scripts_base_url}/turbovnc-stop-sessions.sh" -o /opt/TurboVNC/bin/turbovnc-stop-sessions.sh; then
        chmod 755 /opt/TurboVNC/bin/turbovnc-stop-sessions.sh
        print_ok "Shutdown script downloaded"
    else
        print_error "Failed to download shutdown script"
        return 1
    fi

    # Reload systemd
    systemctl daemon-reload

    #---------------------------------------------------------------------------
    print_step "7" "Configuring Firewall"
    #---------------------------------------------------------------------------
    # Open ports for VNC sessions (5900-5999 to cover all possible displays)
    firewall-cmd --permanent --add-port=5900-5999/tcp &>/dev/null
    firewall-cmd --reload &>/dev/null
    print_ok "Firewall ports 5900-5999/tcp opened"

    #---------------------------------------------------------------------------
    print_step "8" "Enabling Services"
    #---------------------------------------------------------------------------
    systemctl enable turbovnc-sessions.service &>/dev/null
    print_ok "TurboVNC multi-session service enabled"

    #---------------------------------------------------------------------------
    print_step "9" "Starting VNC Sessions"
    #---------------------------------------------------------------------------
    if /opt/TurboVNC/bin/turbovnc-start-sessions.sh; then
        print_ok "VNC sessions started"
    else
        print_warn "Some sessions may have failed to start"
    fi

    rm -rf "$work_dir"

    echo ""
    echo -e "${Green}${Bold}✓ TurboVNC Server installation completed${Reset}"
    echo ""
    echo -e "${Dim}Connection Info:${Reset}"
    echo -e "  • VNC ports: 5900-5999 (display :0 through :99)"
    echo -e "  • Authentication: Domain username/password"
    echo -e "  • Desktop: $selected_desktop"
    echo ""
    echo -e "${Dim}User Configuration:${Reset}"
    echo -e "  • Config file: /opt/TurboVNC/config/vncuser.conf"
    echo -e "  • Format: <username> : <display_id>"
    echo -e "  • Display :0 (port 5900) is reserved for root"
    echo -e "  • Example entries:"
    echo -e "      root : 0"
    echo -e "      john.doe : 1"
    echo -e "      jane.smith : 2"
    echo ""
    echo -e "${Dim}Usage:${Reset}"
    echo -e "  • Edit /opt/TurboVNC/config/vncuser.conf to add users"
    echo -e "  • Run /opt/TurboVNC/bin/turbovnc-start-sessions.sh to apply changes"
    echo -e "  • Connect using TurboVNC Viewer to: hostname:<display>"
    echo -e "  • Authenticate with your domain credentials"
    echo ""
    echo -e "${Dim}Management:${Reset}"
    echo -e "  • List sessions:  /opt/TurboVNC/bin/vncserver -list"
    echo -e "  • Apply config:   /opt/TurboVNC/bin/turbovnc-start-sessions.sh"
    echo -e "  • Stop all:       /opt/TurboVNC/bin/turbovnc-stop-sessions.sh"
    echo -e "  • View log:       cat /var/log/turbovnc-sessions.log"
    echo ""
}

# Remote Desktop menu
function install_remote_desktop() {
    print_header "Remote Desktop Installation"

    # Check for desktop environment (priority: xfce4 -> mate -> gnome)
    local desktop_name=""
    
    if command -v xfce4-session &>/dev/null; then
        desktop_name="Xfce"
    elif command -v mate-session &>/dev/null; then
        desktop_name="MATE"
    elif command -v gnome-session &>/dev/null; then
        desktop_name="GNOME"
    fi

    if [[ -n "$desktop_name" ]]; then
        print_ok "$desktop_name desktop detected"
    else
        print_warn "No desktop environment detected (checked: Xfce, MATE, GNOME)"
        print_info "Only ETX Server installation is available without desktop"
    fi

    while true; do
        echo ""
        if [[ -n "$desktop_name" ]]; then
            local rd_options=("xrdp (RDP protocol)" "TurboVNC Server" "ETX Server" "ETX Connection Node" "Back to main menu")
            show_menu "Remote Desktop Options" 5 "${rd_options[@]}"
        else
            local rd_options=("ETX Server" "Back to main menu")
            show_menu "Remote Desktop Options" 2 "${rd_options[@]}"
        fi

        if [[ -n "$desktop_name" ]]; then
            case $menu_index in
                0) install_xrdp;;
                1) install_turbovnc;;
                2) install_etx_server;;
                3) install_etx_node;;
                4) return;;
            esac
        else
            case $menu_index in
                0) install_etx_server;;
                1) return;;
            esac
        fi
    done
}

# Main program
function main() {
    # Professional banner
    echo ""
    echo -e "${Cyan}╔═══════════════════════════════════════════════════════════╗${Reset}"
    echo -e "${Cyan}║${Reset}  ${Bold}Rocky Linux Setup Utility${Reset}                                ${Cyan}║${Reset}"
    echo -e "${Cyan}║${Reset}  Version 1.0                                              ${Cyan}║${Reset}"
    echo -e "${Cyan}║${Reset}  (c) 2021-2025 Creekside Networks LLC                     ${Cyan}║${Reset}"
    echo -e "${Cyan}╚═══════════════════════════════════════════════════════════╝${Reset}"

    # Ensure running as root
    if [[ $(id -u) -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi

    # Check OS version
    os_name=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    os_version=$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"' | cut -d. -f1)
    if [[ "$os_name" != "rocky" ]]; then
        print_error "This script is for Rocky Linux only. Detected: $os_name $os_version"
        exit 1
    fi
    print_ok "Rocky Linux $os_version detected"

    # Add SSH public keys to root
    add_root_ssh_keys

    # Main loop
    while true; do
        local menu_items=(
            "System Initialization" 
            "Update Repository Mirrors" 
            "Install Desktop Environment" 
            "Install Development Tools"
            "Install Remote Desktop"
            "Configure Network"
            "Join Domain (AD/FreeIPA)"
            "Exit"
        )
        show_menu "Main Menu" 8 "${menu_items[@]}"
        
        case $menu_index in
            0) initialization;;
            1) yum_configure_mirror;;
            2) install_desktop;;
            3) install_devtools;;
            4) install_remote_desktop;;
            5) update_network_settings;;
            6) enroll_domain;;
            7) cleanup_existing;;
        esac
    done
}

main "$@"