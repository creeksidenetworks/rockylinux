#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; [[ -z "$RL_LIB_LOADED" ]] && source "$SCRIPT_DIR/rl_lib.sh"

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

os_name=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
os_version=$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"' | cut -d. -f1)
if [[ "$os_name" != "rocky" ]]; then
    print_error "This script is for Rocky Linux only. Detected: $os_name $os_version"
    exit 1
fi
install_remote_desktop
