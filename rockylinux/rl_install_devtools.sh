#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; [[ -z "$RL_LIB_LOADED" ]] && source "$SCRIPT_DIR/rl_lib.sh"

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
        "ipmitool" "vsftpd" "links" "ntfs-3g" "gc" "gc-devel" "verilator"
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

os_name=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
os_version=$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"' | cut -d. -f1)
if [[ "$os_name" != "rocky" ]]; then
    print_error "This script is for Rocky Linux only. Detected: $os_name $os_version"
    exit 1
fi
install_devtools
