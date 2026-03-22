#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; [[ -z "$RL_LIB_LOADED" ]] && source "$SCRIPT_DIR/rl_lib.sh"

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

os_name=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
os_version=$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"' | cut -d. -f1)
if [[ "$os_name" != "rocky" ]]; then
    print_error "This script is for Rocky Linux only. Detected: $os_name $os_version"
    exit 1
fi
install_desktop
