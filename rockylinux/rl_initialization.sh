#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; [[ -z "$RL_LIB_LOADED" ]] && source "$SCRIPT_DIR/rl_lib.sh"

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
    if [[ -f /etc/default/grub ]] && ! sudo grep -q 'selinux=0' /etc/default/grub; then
        sudo sed -i 's/\(GRUB_CMDLINE_LINUX="[^"]*\)"/\1 selinux=0"/' /etc/default/grub
        if [[ -d /sys/firmware/efi ]]; then
            sudo grub2-mkconfig -o /boot/efi/EFI/rocky/grub.cfg &>/dev/null || true
        else
            sudo grub2-mkconfig -o /boot/grub2/grub.cfg &>/dev/null || true
        fi
    fi
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

    # Enable ruby:3.0 and nodejs:14 modules before package install
    dnf -y module enable ruby:3.0 nodejs:14 &>/dev/null || true

    local default_packages=(
        "zsh" "ksh" "tcsh" "xterm" "ethtool" "vim-enhanced"
        "NetworkManager" "NetworkManager-tui" "net-tools"
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
        "sssd" "sssd-tools" "authselect" "realmd" "oddjob" "oddjob-mkhomedir"
        "adcli" "samba-common" "samba-common-tools" "krb5-workstation"
        "firewalld" "dnf-plugins-core" "policycoreutils-python-utils"
        "bash-completion"
        "@Development Tools"
        "munge" "munge-devel"
        "bzip2"
        "readline-devel" "numactl-devel" "pam-devel" "glib2-devel" "hwloc-devel"
        "openssl-devel" "libcurl-devel" "mariadb-devel" "mariadb"
        "python3-numpy"
        "kitty-terminfo" "stress" "pcp"
    )

    # Version-specific packages
    if [[ "$os_version" == "8" ]]; then
        default_packages+=("python39" "python39-devel" "libcgroup")
    else
        default_packages+=("python3-devel")
    fi

    print_info "Installing ${#default_packages[@]} packages..."
    install_applications "${default_packages[@]}"

    # Set Python 3.9 as default
    if command -v python3.9 &>/dev/null; then
        alternatives --set python /usr/bin/python3.9 &>/dev/null || \
            alternatives --install /usr/bin/python python /usr/bin/python3.9 10 &>/dev/null
        alternatives --set python3 /usr/bin/python3.9 &>/dev/null || \
            alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 10 &>/dev/null
        print_ok "Python default set to $(python3.9 --version 2>&1)"
    fi

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

        # Disable SELinux permanently via GRUB kernel args
        if [[ -f /etc/default/grub ]]; then
            if ! grep -q 'selinux=0' /etc/default/grub; then
                sed -i 's/\(GRUB_CMDLINE_LINUX_DEFAULT="[^"]*\)"/\1 selinux=0"/' /etc/default/grub
            fi
            if [[ -d /sys/firmware/efi ]]; then
                grub2-mkconfig -o /boot/efi/EFI/rocky/grub.cfg &>/dev/null
            else
                grub2-mkconfig -o /boot/grub2/grub.cfg &>/dev/null
            fi
            print_ok "SELinux disabled in GRUB (will be disabled after reboot)"
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
    print_step "7" "Expand Boot Disk (Optional)"
    #---------------------------------------------------------------------------

    _root_source=$(findmnt -n -o SOURCE /)
    _is_lvm=false
    _pv_part=""

    if [[ "$_root_source" == /dev/mapper/* ]]; then
        _pv_part=$(pvs --noheadings -o pv_name 2>/dev/null | awk '{print $1}' | head -1)
        _is_lvm=true
    else
        _pv_part="$_root_source"
    fi

    if [[ -n "$_pv_part" && -b "$_pv_part" ]] && command -v parted &>/dev/null; then
        _disk=$(lsblk -ndo pkname "$_pv_part" 2>/dev/null)
        _disk_dev="/dev/$_disk"
        _part_num=$(echo "$_pv_part" | grep -o '[0-9]*$')

        if [[ -b "$_disk_dev" ]]; then
            _free_mb=$(parted "$_disk_dev" unit MB print free 2>/dev/null | \
                       awk '/Free Space/{gsub(/MB/,"",$3); if ($3+0 > 1024) print $3+0}' | tail -1)

            if [[ -n "$_free_mb" ]]; then
                _free_gb=$(awk "BEGIN {printf \"%.1f\", $_free_mb / 1024}")
                echo ""
                print_info "Detected ${_free_gb}GB of unallocated space on $_disk_dev"
                read -p "  Expand to use this space? [y/N]: " _expand_disk

                if [[ "$_expand_disk" =~ ^[Yy]$ ]]; then
                    print_info "Expanding partition $_part_num on $_disk_dev..."
                    if growpart "$_disk_dev" "$_part_num" &>/dev/null; then
                        print_ok "Partition $_part_num expanded"

                        if $_is_lvm; then
                            pvresize "$_pv_part" &>/dev/null
                            _lv=$(lvs --noheadings -o lv_path 2>/dev/null | awk '{print $1}' | grep -v swap | head -1)
                            if [[ -n "$_lv" ]]; then
                                lvextend -l +100%FREE "$_lv" &>/dev/null
                                _fs_type=$(findmnt -n -o FSTYPE /)
                                if [[ "$_fs_type" == "xfs" ]]; then
                                    xfs_growfs / &>/dev/null && print_ok "XFS filesystem expanded"
                                else
                                    resize2fs "$_lv" &>/dev/null && print_ok "ext4 filesystem expanded"
                                fi
                            fi
                        else
                            _fs_type=$(findmnt -n -o FSTYPE /)
                            if [[ "$_fs_type" == "xfs" ]]; then
                                xfs_growfs / &>/dev/null && print_ok "XFS filesystem expanded"
                            else
                                resize2fs "$_root_source" &>/dev/null && print_ok "ext4 filesystem expanded"
                            fi
                        fi
                        print_ok "Disk expansion completed"
                    else
                        print_warn "Could not expand partition (no free space or already at maximum)"
                    fi
                fi
            else
                print_ok "No significant unallocated space detected on $_disk_dev"
            fi
        fi
    else
        print_info "Skipping disk expansion check (parted not available)"
    fi

    #---------------------------------------------------------------------------
    print_step "8" "Update Root Password (Optional)"
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

os_name=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
os_version=$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"' | cut -d. -f1)
if [[ "$os_name" != "rocky" ]]; then
    print_error "This script is for Rocky Linux only. Detected: $os_name $os_version"
    exit 1
fi
initialization
