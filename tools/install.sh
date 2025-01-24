#!/bin/sh
#
# This script should be run via curl:
#   sh -c "$(curl -fsSL https://raw.githubusercontent.com/linuxxer/slimnode/main/tools/install.sh)"
# or via wget:
#   sh -c "$(wget -qO- https://raw.githubusercontent.com/linuxxer/slimnode/main/tools/install.sh)"
# or via fetch:
#   sh -c "$(fetch -o - https://raw.githubusercontent.com/linuxxer/slimnode/main/tools/install.sh)"
#
# As an alternative, you can first download the install script and run it afterwards:
#   wget https://raw.githubusercontent.com/linuxxer/slimnode/main/tools/install.sh
#   sh install.sh
#
# You can tweak the install behavior by setting variables when running the script. For
# example, to change the path to the Oh My Zsh repository:
#   ZSH=~/.zsh sh install.sh
#
# Respects the following environment variables:
#   ZDOTDIR - path to Zsh dotfiles directory (default: unset). See [1][2]
#             [1] https://zsh.sourceforge.io/Doc/Release/Parameters.html#index-ZDOTDIR
#             [2] https://zsh.sourceforge.io/Doc/Release/Files.html#index-ZDOTDIR_002c-use-of
#   ZSH     - path to the Oh My Zsh repository folder (default: $HOME/.oh-my-zsh)
#   REPO    - name of the GitHub repo to install from (default: ohmyzsh/ohmyzsh)
#   REMOTE  - full remote URL of the git repo to install (default: GitHub via HTTPS)
#   BRANCH  - branch to check out immediately after install (default: master)
#
# Other options:
#   CHSH       - 'no' means the installer will not change the default shell (default: yes)
#   RUNZSH     - 'no' means the installer will not run zsh after the install (default: yes)
#   KEEP_ZSHRC - 'yes' means the installer will not replace an existing .zshrc (default: no)
#
# You can also pass some arguments to the install script to set some these options:
#   --skip-chsh: has the same behavior as setting CHSH to 'no'
#   --unattended: sets both CHSH and RUNZSH to 'no'
#   --keep-zshrc: sets KEEP_ZSHRC to 'yes'
# For example:
#   sh install.sh --unattended
# or:
#   sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
#
set -e

# Make sure important variables exist if not already defined
#
# $USER is defined by login(1) which is not always executed (e.g. containers)
# POSIX: https://pubs.opengroup.org/onlinepubs/009695299/utilities/id.html
USER=${USER:-$(id -u -n)}
# $HOME is defined at the time of login, but it could be unset. If it is unset,
# a tilde by itself (~) will not be expanded to the current user's home directory.
# POSIX: https://pubs.opengroup.org/onlinepubs/009696899/basedefs/xbd_chap08.html#tag_08_03
HOME="${HOME:-$(getent passwd $USER 2>/dev/null | cut -d: -f6)}"
# macOS does not have getent, but this works even if $HOME is unset
HOME="${HOME:-$(eval echo ~$USER)}"


# Track if $ZSH was provided
custom_zsh=${ZSH:+yes}

# Use $zdot to keep track of where the directory is for zsh dotfiles
# To check if $ZDOTDIR was provided, explicitly check for $ZDOTDIR
zdot="${ZDOTDIR:-$HOME}"

# Default value for $ZSH
# a) if $ZDOTDIR is supplied and not $HOME: $ZDOTDIR/ohmyzsh
# b) otherwise, $HOME/.oh-my-zsh
if [ -n "$ZDOTDIR" ] && [ "$ZDOTDIR" != "$HOME" ]; then
  ZSH="${ZSH:-$ZDOTDIR/ohmyzsh}"
fi
ZSH="${ZSH:-$HOME/.oh-my-zsh}"

# Default settings
REPO=${REPO:-ohmyzsh/ohmyzsh}
REMOTE=${REMOTE:-https://github.com/${REPO}.git}
BRANCH=${BRANCH:-master}

# Other options
CHSH=${CHSH:-yes}
RUNZSH=${RUNZSH:-yes}
KEEP_ZSHRC=${KEEP_ZSHRC:-no}

command_exists() {
  command -v "$@" >/dev/null 2>&1
}

user_can_sudo() {
  # Check if sudo is installed
  command_exists sudo || return 1
  # Termux can't run sudo, so we can detect it and exit the function early.
  case "$PREFIX" in
  *com.termux*) return 1 ;;
  esac
  # The following command has 3 parts:
  #
  # 1. Run `sudo` with `-v`. Does the following:
  #    • with privilege: asks for a password immediately.
  #    • without privilege: exits with error code 1 and prints the message:
  #      Sorry, user <username> may not run sudo on <hostname>
  #
  # 2. Pass `-n` to `sudo` to tell it to not ask for a password. If the
  #    password is not required, the command will finish with exit code 0.
  #    If one is required, sudo will exit with error code 1 and print the
  #    message:
  #    sudo: a password is required
  #
  # 3. Check for the words "may not run sudo" in the output to really tell
  #    whether the user has privileges or not. For that we have to make sure
  #    to run `sudo` in the default locale (with `LANG=`) so that the message
  #    stays consistent regardless of the user's locale.
  #
  ! LANG= sudo -n -v 2>&1 | grep -q "may not run sudo"
}

# The [ -t 1 ] check only works when the function is not called from
# a subshell (like in `$(...)` or `(...)`, so this hack redefines the
# function at the top level to always return false when stdout is not
# a tty.
if [ -t 1 ]; then
  is_tty() {
    true
  }
else
  is_tty() {
    false
  }
fi

# This function uses the logic from supports-hyperlinks[1][2], which is
# made by Kat Marchán (@zkat) and licensed under the Apache License 2.0.
# [1] https://github.com/zkat/supports-hyperlinks
# [2] https://crates.io/crates/supports-hyperlinks
#
# Copyright (c) 2021 Kat Marchán
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
supports_hyperlinks() {
  # $FORCE_HYPERLINK must be set and be non-zero (this acts as a logic bypass)
  if [ -n "$FORCE_HYPERLINK" ]; then
    [ "$FORCE_HYPERLINK" != 0 ]
    return $?
  fi

  # If stdout is not a tty, it doesn't support hyperlinks
  is_tty || return 1

  # DomTerm terminal emulator (domterm.org)
  if [ -n "$DOMTERM" ]; then
    return 0
  fi

  # VTE-based terminals above v0.50 (Gnome Terminal, Guake, ROXTerm, etc)
  if [ -n "$VTE_VERSION" ]; then
    [ $VTE_VERSION -ge 5000 ]
    return $?
  fi

  # If $TERM_PROGRAM is set, these terminals support hyperlinks
  case "$TERM_PROGRAM" in
  Hyper|iTerm.app|terminology|WezTerm|vscode) return 0 ;;
  esac

  # These termcap entries support hyperlinks
  case "$TERM" in
  xterm-kitty|alacritty|alacritty-direct) return 0 ;;
  esac

  # xfce4-terminal supports hyperlinks
  if [ "$COLORTERM" = "xfce4-terminal" ]; then
    return 0
  fi

  # Windows Terminal also supports hyperlinks
  if [ -n "$WT_SESSION" ]; then
    return 0
  fi

  # Konsole supports hyperlinks, but it's an opt-in setting that can't be detected
  # https://github.com/ohmyzsh/ohmyzsh/issues/10964
  # if [ -n "$KONSOLE_VERSION" ]; then
  #   return 0
  # fi

  return 1
}

# Adapted from code and information by Anton Kochkov (@XVilka)
# Source: https://gist.github.com/XVilka/8346728
supports_truecolor() {
  case "$COLORTERM" in
  truecolor|24bit) return 0 ;;
  esac

  case "$TERM" in
  iterm           |\
  tmux-truecolor  |\
  linux-truecolor |\
  xterm-truecolor |\
  screen-truecolor) return 0 ;;
  esac

  return 1
}

fmt_link() {
  # $1: text, $2: url, $3: fallback mode
  if supports_hyperlinks; then
    printf '\033]8;;%s\033\\%s\033]8;;\033\\\n' "$2" "$1"
    return
  fi

  case "$3" in
  --text) printf '%s\n' "$1" ;;
  --url|*) fmt_underline "$2" ;;
  esac
}

fmt_underline() {
  is_tty && printf '\033[4m%s\033[24m\n' "$*" || printf '%s\n' "$*"
}

# shellcheck disable=SC2016 # backtick in single-quote
fmt_code() {
  is_tty && printf '`\033[2m%s\033[22m`\n' "$*" || printf '`%s`\n' "$*"
}

fmt_error() {
  printf '%sError: %s%s\n' "${FMT_BOLD}${FMT_RED}" "$*" "$FMT_RESET" >&2
}

setup_color() {
  # Only use colors if connected to a terminal
  if ! is_tty; then
    FMT_RAINBOW=""
    FMT_RED=""
    FMT_GREEN=""
    FMT_YELLOW=""
    FMT_BLUE=""
    FMT_BOLD=""
    FMT_RESET=""
    return
  fi

  if supports_truecolor; then
    FMT_RAINBOW="
      $(printf '\033[38;2;255;0;0m')
      $(printf '\033[38;2;255;97;0m')
      $(printf '\033[38;2;247;255;0m')
      $(printf '\033[38;2;0;255;30m')
      $(printf '\033[38;2;77;0;255m')
      $(printf '\033[38;2;168;0;255m')
      $(printf '\033[38;2;245;0;172m')
    "
  else
    FMT_RAINBOW="
      $(printf '\033[38;5;196m')
      $(printf '\033[38;5;202m')
      $(printf '\033[38;5;226m')
      $(printf '\033[38;5;082m')
      $(printf '\033[38;5;021m')
      $(printf '\033[38;5;093m')
      $(printf '\033[38;5;163m')
    "
  fi

  FMT_RED=$(printf '\033[31m')
  FMT_GREEN=$(printf '\033[32m')
  FMT_YELLOW=$(printf '\033[33m')
  FMT_BLUE=$(printf '\033[34m')
  FMT_BOLD=$(printf '\033[1m')
  FMT_RESET=$(printf '\033[0m')
}

ask_yes_or_no() {
    read -p "$1 ([y]es or [N]o): "
    case $(echo $REPLY | tr '[A-Z]' '[a-z]') in
        y|yes) echo "yes" ;;
        *)     echo "no" ;;
    esac
}

ask_to_continue() {
  CONTINUE=0
  echo "$1${FMT_YELLOW} Do you want to continue? [Y/n] " "$FMT_RESET"
  read -r opt
  case $opt in
    y*|Y*|"") CONTINUE=1;;
    n*|N*) ;;
    *) echo "Invalid choice. Exiting."; exit ;;
  esac
}

install_packages() {
  ask_to_continue "Install software packages and configure SSH?"
  if [ $CONTINUE -eq 1 ];then
    sudo apt update 
    sudo apt full-upgrade -y 
    sudo apt install -y jq pipx ufw htop btop iptraf fail2ban tor autoconf automake build-essential git libtool libsqlite3-dev libffi-dev python3 python3-pip net-tools zlib1g-dev libsodium-dev gettext python3-mako git automake autoconf-archive libtool build-essential pkg-config libev-dev libcurl4-gnutls-dev libsqlite3-dev python3-poetry python3-venv wireguard python3-json5 python3-flask python3-gunicorn python3-gevent python3-websockets python3-flask-cors python3-flask-socketio python3-gevent-websocket python3-grpcio nodejs npm python3-grpc-tools python3-psutil ripgrep golang-go 
    sudo systemctl enable fail2ban
    sudo systemctl enable tor
#    sudo echo -e "ChallengeResponseAuthentication no\nPasswordAuthentication no\nUsePAM no\nPermitRootLogin yes" >/etc/ssh/sshd_config.d/99-disable_root_login.conf
  fi
}

create_bitcoin_user() {
  ask_to_continue "Create a 'bitcoin' system user?"
  if [ $CONTINUE -eq 1 ];then
    sudo useradd -m bitcoin -s /bin/bash
    sudo adduser bitcoin sudo
    sudo usermod -a -G debian-tor bitcoin
    echo "${FMT_YELLOW}Set a password for the 'bitcoin' system user and write it down/store it in a password manager.${FMT_RESET}"
    sudo passwd bitcoin
  fi
}

setup_firewall() {
  ask_to_continue "Setup firewall?"
  if [ $CONTINUE -eq 1 ];then
    sudo ufw default deny incoming 
    sudo ufw default allow outgoing
    sudo ufw allow 51820/udp 
    sudo ufw allow 22,9735,9736/tcp
    sudo ufw allow proto tcp from 10.0.0.0/24 to 10.0.0.0/24 port 3000,8332,50002
    sudo ufw logging off 
    sudo ufw enable
    sudo systemctl enable ufw
  fi
}

reboot_system() {
  ask_to_continue "Reboot the system?"
  if [ $CONTINUE -eq 1 ];then
    sudo shutdown -r now
  fi
}

create_ssh_keys() {
  ask_to_continue "Create SSH keys?"
  if [ $CONTINUE -eq 1 ];then
    sudo -u bitcoin sh -c "ssh-keygen -t rsa -b 4096"
  fi
}

install_bitcoin_core() {
  VERSION="27.0"
  ask_to_continue "Install Bitcoin Core ${VERSION}?"
  if [ $CONTINUE -eq 1 ];then
    sudo -u bitcoin sh -c "wget https://bitcoincore.org/bin/bitcoin-core-${VERSION}/bitcoin-${VERSION}-x86_64-linux-gnu.tar.gz -P ~"
    sudo -u bitcoin sh -c "wget https://bitcoincore.org/bin/bitcoin-core-${VERSION}/SHA256SUMS -P ~"
    sudo -u bitcoin sh -c "wget https://bitcoincore.org/bin/bitcoin-core-${VERSION}/SHA256SUMS.asc -P ~"
    sudo -u bitcoin sh -c "cd && sha256sum --ignore-missing --check ~/SHA256SUMS"
    sudo -u bitcoin sh -c 'curl -s "https://api.github.com/repositories/355107265/contents/builder-keys" | grep download_url | grep -oE "https://[a-zA-Z0-9./-]+" | while read url; do curl -s "$url" | gpg --import; done'
    sudo -u bitcoin sh -c "gpg --verify ~/SHA256SUMS.asc"
    echo "${FMT_YELLOW}Check validity of signatures.${FMT_RESET}"
    ask_to_continue "Signatures valid?"
    sudo -u bitcoin sh -c "tar -xvf ~/bitcoin-${VERSION}-x86_64-linux-gnu.tar.gz -C ~"
    sudo -u bitcoin sh -c "sudo install -m 0755 -o root -g root -t /usr/local/bin ~/bitcoin-${VERSION}/bin/*"  
    sudo -u bitcoin sh -c "mkdir -p ~/.bitcoin"
    sudo -u bitcoin sh -c "tee >~/.bitcoin/bitcoin.conf <<EOF
daemon=1
server=1
prune=60000
onion=127.0.0.1:9050
listen=1
deprecatedrpc=create_bdb
walletbroadcast=0
rpcbind=0.0.0.0:8332
rpcallowip=0.0.0.0/0
whitelist=0.0.0.0/0
rpcuser=bitcoin
rpcpassword=${BITCOIND_PW}
zmqpubrawblock=tcp://127.0.0.1:28332
zmqpubrawtx=tcp://127.0.0.1:28333
EOF"
    sudo sh -c "tee  /etc/systemd/system/bitcoind.service <<EOF
[Unit]
Description=Bitcoin daemon

[Service]
User=bitcoin
Group=bitcoin
Type=forking
PIDFile=/home/bitcoin/.bitcoin/bitcoind.pid
ExecStart=/usr/local/bin/bitcoind -pid=/home/bitcoin/.bitcoin/bitcoind.pid
KillMode=process
TimeoutSec=120

[Install]
WantedBy=multi-user.target
EOF"
  fi
  sudo systemctl enable bitcoind.service
  BITCOIND_INSTALLED=true
}

install_core_lightning() {
  ask_to_continue "Install c-lightning?"
  if [ $CONTINUE -eq 1 ];then
    sudo -u bitcoin sh -c "mkdir -p ~/.lightning/bitcoin/backups/"
    sudo -u bitcoin sh -c "git clone https://github.com/ElementsProject/lightning.git ~/lightning && cd ~/lightning && git checkout v24.11.1"
    if [ "$VERSION_ID" == "$VER24" ]; then
      sudo -u bitcoin sh -c "cd ~/lightning && poetry install && ./configure --disable-rust && poetry run make -j`nproc --all` && sudo make install"
    else
      sudo -u bitcoin sh -c "cd ~/lightning && ./configure && make -j`nproc --all` && sudo make install"
    fi
    sudo -u bitcoin sh -c "pip3 install --user pyln-client websockets flask-cors flask-restx pyln-client flask-socketio gevent gevent-websocket --break-system-packages"
    sudo -u bitcoin sh -c 'tee ~/.lightning/config <<EOF
network=bitcoin
log-file=cl.log
clnrest-host=0.0.0.0
clnrest-port=3010
important-plugin=/home/bitcoin/plugins/backup/backup.py
wallet=sqlite3:///home/bitcoin/.lightning/bitcoin/lightningd.sqlite3:/home/bitcoin/.lightning/bitcoin/backups/lightningd.sqlite3
bitcoin-retry-timeout=3600
proxy=127.0.0.1:9050
bind-addr=127.0.01:9735
rpc-file-mode=0664
bitcoin-rpcuser=bitcoin
bitcoin-rpcport=8332
bitcoin-rpcconnect=127.0.0.1
bitcoin-rpcpassword='${BITCOIND_PW}'
bind-addr='${PUBLIC_IP}':9735
announce-addr='${PUBLIC_IP}':9735
EOF'
    sudo -u bitcoin sh -c "git clone https://github.com/lightningd/plugins.git ~/plugins"
    if [ "$VERSION_ID" == "$VER22" ]; then
      sudo apt-remove -y python3-poetry
      sudo -u bitcoin sh -c "cd ~/plugins/backup && pipx install poetry && pipx ensurepath"
      sudo -u bitcoin sh -c 'tee ~/plugins/backup/pyproject.toml <<EOF
[project]
name = "cln-backup"
version = "0.1.0"
description = "Keep your Core-Lightning node save by backing it up, in real-time (allows recovering without channel closures)."

[tool.poetry]
authors = ["Christian Decker <decker@blockstream.com>"]
packages = [
    { include = "*.py" }
]

[tool.poetry.dependencies]
python = "^3.8"
pyln-client = "^23.11"
click = "^8.0.4"
psutil = "^5.9.4"
flask = "^2.2"
werkzeug = "<4"

[tool.poetry.group.dev.dependencies]
pyln-testing = "^23.11"
flaky = "^3.7.0"
pytest-timeout = "^2.2.0"
pytest-xdist = "^3.1.0"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
EOF'
    fi
    sudo -u bitcoin sh -c "cd ~/plugins/backup && /home/bitcoin/.local/bin/poetry install && /home/bitcoin/.local/bin/poetry run ./backup-cli init --lightning-dir /home/bitcoin/.lightning/bitcoin file:///home/bitcoin/.lightning/bitcoin/backups/lightningd.sqlite3.bkp"
    sudo sh -c "tee /etc/systemd/system/lightningd.service <<EOF
[Unit]
Description=c-lightning daemon on mainnet
After=bitcoind.service

[Service]
ExecStart=/usr/local/bin/lightningd --conf=/home/bitcoin/.lightning/config  --pid-file=/run/lightningd/lightningd.pid
RuntimeDirectory=lightningd
User=bitcoin
Group=bitcoin
Type=simple
PIDFile=/run/lightningd/lightningd.pid
TimeoutSec=60
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true
PrivateDevices=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
EOF"
  fi
  sudo mkdir -p /run/lightningd/
  sudo chown bitcoin:bitcoin /run/lightningd/
  sudo chmod 755 /run/lightningd/
  sudo systemctl enable lightningd.service
  LIGHTNINGD_INSTALLED=true
}

install_lnd() {
  ask_to_continue "Install lnd?"
  if [ $CONTINUE -eq 1 ];then
    LND_VERSION="v0.18.4-beta"
    sudo -u bitcoin sh -c "mkdir ~/.lnd"
    sudo -u bitcoin sh -c "wget https://github.com/lightningnetwork/lnd/releases/download/${LND_VERSION}/lnd-linux-386-${LND_VERSION}.tar.gz -P ~"
    sudo -u bitcoin sh -c "tar -xvf ~/lnd-linux-386-${LND_VERSION}.tar.gz -C ~"
    sudo -u bitcoin sh -c "ln -s ~/lnd-linux-386-${LND_VERSION} ~/lnd"
    sudo -u bitcoin sh -c 'tee  ~/.lnd/lnd.conf <<EOF
[Application Options]
listen='${PUBLIC_IP}':9736
externalip='${PUBLIC_IP}':9736
debuglevel=debug

[Bitcoin]
bitcoin.mainnet=true
bitcoin.node=bitcoind
EOF'
    sudo sh -c "tee  /etc/systemd/system/lnd.service <<EOF
[Unit]
Description=lnd

[Service]
User=bitcoin
Group=bitcoin
Type=simple
ExecStart=/home/bitcoin/lnd/lnd --externalip=${PUBLIC_IP}
PIDFile=/home/bitcoin/.lnd/lnd.pid
KillMode=process
TimeoutSec=60

[Install]
WantedBy=multi-user.target
EOF"
  fi
  sudo systemctl enable lnd.service
  sudo -u bitcoin sh -c 'tee >>~/.profile <<EOF 
# set PATH to include lnd binaries
if [ -d "$HOME/lnd" ] ; then
    PATH="$HOME/lnd:$PATH"
fi'
  LND_INSTALLED=true
}

install_rtl() {
  ask_to_continue "Install Ride The Lightning?"
  if [ $CONTINUE -eq 1 ];then
    sudo -u bitcoin sh -c "git clone https://github.com/Ride-The-Lightning/RTL.git ~/RTL && cd ~/RTL && npm install --omit=dev --legacy-peer-deps" 
    sudo -u bitcoin sh -c 'tee ~/RTL/RTL-Config.json <<EOF
{
  "port": "3000",
  "defaultNodeIndex": 1,
  "dbDirectoryPath": "/home/bitcoin/RTL/",
  "SSO": {
    "rtlSSO": 0,
    "rtlCookiePath": "",
    "logoutRedirectLink": ""
  },
  "nodes": [
    {
      "index": 1,
      "lnNode": "Core Lightning",
      "lnImplementation": "CLN",
      "authentication": {
        "runePath": "/home/bitcoin/RTL/rune.txt"
      },
      "settings": {
        "userPersona": "OPERATOR",
        "themeMode": "DAY",
        "themeColor": "PURPLE",
        "logLevel": "INFO",
        "lnServerUrl": "https://127.0.0.1:3010",
        "fiatConversion": false,
        "unannouncedChannels": false,
        "blockExplorerUrl": "https://mempool.space"
      }
    }
  ],
  "multiPass": "'"${RTL_PW}"'"
}
EOF'
    sudo sh -c "tee /etc/systemd/system/rtl.service <<EOF
[Unit]
Description=Ride The Lightning
After=bitcoind.service lightningd.service wg-quick@wg0.service

[Service]
User=bitcoin
Group=bitcoin
WorkingDirectory=/home/bitcoin/RTL
ExecStart=/usr/bin/node rtl
Type=simple

[Install]
WantedBy=multi-user.target
EOF"
    RUNE=`sudo -u bitcoin sh -c "lightning-cli createrune | jq .rune"`
    sudo -u bitcoin sh -c "echo LIGHTNING_RUNE='${RUNE}' >~/RTL/rune.txt"
    sudo systemctl enable rtl.service
    RTL_INSTALLED=true
  fi
}

configure_wireguard() {
  ask_to_continue "Configure Wireguard?"
#  if [ $CONTINUE -eq 1 ];then
#  fi
  WIREGUARD_INSTALLED=true
}


print_summary() {
  echo "${FMT_GREEN}Installation done.${FMT_RESET}"
  echo "${FMT_YELLOW}Summary:${FMT_RESET}"
  if [ "$BITCOIND_INSTALLED" = true ] ; then
    echo 'bitcoind will be started.'
  fi
  if [ "$LIGHTNINGD_INSTALLED" = true ] ; then
    echo 'lightningd will be started.'
  fi
  if [ "$LND_INSTALLED" = true ] ; then
    echo 'lnd will be started.'
  fi
  if [ "$RTL_INSTALLED" = true ] ; then
    echo 'rtl will be started.'
  fi
  if [ "$WIREGUARD_INSTALLED" = true ] ; then
    echo 'wireguard will be started.'
  fi
}

setup_install() {
  if user_can_sudo; then
    echo "${FMT_GREEN}sudo for user allowed.${FMT_RESET}"
    install_packages
    create_bitcoin_user
    setup_firewall
    create_ssh_keys
    install_bitcoin_core
    install_core_lightning
    install_lnd
    install_rtl
    print_summary
#    configure_wireguard
#    reboot_system

  else
    fmt_error 'user cannot run sudo'
    exit 1
  fi
}
main() {
  PUBLIC_IP=`wget -qO- https://ipecho.net/plain ; echo`
  BITCOIND_PW=`cat /dev/urandom | LC_ALL=C tr -dc 'a-zA-Z0-9' | fold -w 50 | head -n 1`
  RTL_PW=`cat /dev/urandom | LC_ALL=C tr -dc 'a-zA-Z0-9' | fold -w 50 | head -n 1`
  . /etc/os-release
  VER24="24.04"
  VER22="22.04"
  VER20="20.04"

if [[ "$VERSION_ID" != "$VER22" && "$VERSION_ID" != "$VER20" && "$VERSION_ID" != "$VER24" ]]; then
    fmt_error 'Unsupported Ubuntu version'
    exit 1
  fi

  # Parse arguments
  while [ $# -gt 0 ]; do
    case $1 in
      --externalip) PUBLIC_IP=$2 ;;
      --bitcoind_password) BITCOIND_PW=$2 ;;
    esac
    shift
  done
  setup_color
  setup_install
 # setup_ohmyzsh
 # setup_zshrc
 # setup_shell

#  print_success

#  exec zsh -l
}

main "$@"
