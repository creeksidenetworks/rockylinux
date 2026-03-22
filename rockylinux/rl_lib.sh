#!/bin/bash
# Shared library for Rocky Linux Setup Utility
RL_LIB_LOADED=1

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

LOG_FILE="/var/log/rl-setup.log"

log() {
    local level="${1:-INFO}"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
}

print_ok() {
    echo -e "  ${Green}✓${Reset} $1"
    log "DONE" "$1"
}

print_warn() {
    echo -e "  ${Yellow}⚠${Reset} $1"
    log "WARN" "$1"
}

print_error() {
    echo -e "  ${Red}✗${Reset} $1"
    log "ERROR" "$1"
}

print_info() {
    echo -e "  ${Blue}ℹ${Reset} $1"
    log "INFO" "$1"
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
BASE_MIRRORS["AE"]="https://sa.mirrors.cicku.me"
EPEL_MIRRORS["AE"]="https://sa.mirrors.cicku.me/epel"
#BASE_MIRRORS["AE"]="https://mirror.ourhost.az/rockylinux/"
#EPEL_MIRRORS["AE"]="https://mirror.yer.az/fedora-epel/"

trap cleanup_existing EXIT

function cleanup_existing() {
    trap - EXIT
    echo ""
    echo -e "${Dim}Cleaning up and exiting...${Reset}"
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

    print_info "Configuring yum repositories for $COUNTRY"
    baseos_url="${BASE_MIRRORS[$COUNTRY]}"
    epel_url="${EPEL_MIRRORS[$COUNTRY]}"

    if [[ -z "$baseos_url" ]]; then
        baseos_url="${BASE_MIRRORS[US]}"
        epel_url="${EPEL_MIRRORS[US]}"
    fi

    # Detect if this is NJU mirror which has different path structure
    is_nju_mirror=0
    if [[ "$baseos_url" =~ mirrors.nju.edu.cn ]] || [[ "$baseos_url" =~ mirrors.cicku.me ]]; then
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
            sed -i -E 's/^enabled=.*/enabled=0/' "$repo"
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
        # For dnf groups (@...), check via group list; for regular packages use rpm
        local already_installed=false
        if [[ "$package" == @* ]]; then
            local group_name="${package:1}"
            dnf group list --installed 2>/dev/null | grep -qi "$group_name" && already_installed=true
        else
            rpm -q --quiet "$package" 2>/dev/null && already_installed=true
        fi

        if $already_installed; then
            printf "  ${Yellow}-${Reset} %-38s${Yellow}[skipped]${Reset}\n" "$package"
            ((skipped++))
        else
            local dnf_output
            dnf_output=$(dnf install -yq --setopt=skip_if_unavailable=True "$package" 2>&1)
            if [[ $? -eq 0 ]]; then
                printf "  ${Green}✓${Reset} %-38s${Green}[installed]${Reset}\n" "$package"
                ((installed++))
            else
                printf "  ${Red}✗${Reset} %-38s${Red}[failed]${Reset}\n" "$package"
                local error_line
                error_line=$(echo "$dnf_output" | grep -iE "^Error|No match for|nothing provides" | head -1 | sed 's/^ *//')
                [[ -n "$error_line" ]] && printf "    ${Red}↳ %s${Reset}\n" "$error_line"
                ((failed++))
            fi
        fi
    done

    local summary="Installed: $installed"
    [[ $skipped -gt 0 ]] && summary+=", Skipped: $skipped"
    [[ $failed -gt 0 ]] && summary+=", Failed: $failed"
    print_ok "$summary"
}
