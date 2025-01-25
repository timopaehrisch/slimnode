# SlimNode - Set up minimalistic Bitcoin and Lightning node with a few steps

This guide explains how to set up a Bitcoin and a Lightning node on a VPS (Virtual Private Server), 
but the script should also work on a Raspberry Pi.

The following components can be installed:

* bitcoind (Pruned Bitcoin core)
* lightningd (Core Lightning - CLN)
* lnd (Lightning Network Daemon)
* RTL (Ride The Lightning)
* VPN access via WireGuard

There are plenty of VPS providers out there, for about $5/month you can rent a VPS that’s more than
enough for our purposte. Look for specs like these:

    8 GB RAM
    100 GB Disk Storage
    Ubuntu 22.04 or 24.04

6 GB of RAM is fine too, but you shouldn’t go much lower than 80 GB of storage. Ubuntu 22.04 or 24.04
is mandatory, I found the latest version easier to handle.

I did this project, because I wanted to get rid of my Raspberry Pi at home. It's shaky hardware and 
I encountered quite same fails due to errors on the hard disk resulting in a broken blockchain, so I had 
to download everything again - which can take several weeks, especially if you do it via Tor. Also, I wasn't
happy with most node distributions, which can be tricky to debug, if you run into problems, e.g. synchronisation
stops. Also, the load on my Raspberry Pis was usually very high due to status scripts that run every
few seconds to display information about the blockchain, the channel count etc.. This data is only
interesting every now and then, so no need to stress the system all the time. SlimNode is the opposite
to rich menu-driven node distributions, I tried to keep the system simple and clean, and easy to debug,
with log files in obvious places and not spread across multiple mount points. 

Turns out: You can run a Bitcoin node and two Lightning nodes on the same tiny VPS without problems, if
you cut out the noise (unless you open a vast amount of channels).

# Installation

When you rented your VPS, you'll also get a public IP address of your server. For simplicity, I added 
an entry to /etc/hosts on my local machine:

```
185.170.58.xyz  vps
```

You should also have set up a root password in the provider’s web interface and optionally added
some SSH keys already.

You should now be logged into your VPS as root or as a user with sudo permissions.

Download and execute the installer script:

```console
wget https://raw.githubusercontent.com/timopaehrisch/slimnode/refs/heads/main/tools/install.sh
bash ./install.sh
```
The script will guide you through the installation process and ask, which steps you want to perform. 
The setup process for a Bitcoin node is usally pretty straight-forward:

- Install/Update system software, create bitcoin user, firewall configuration etc.
- Install Bitcoin and Lightning node software
- Tools, VPN & Wallets (RTL und ZeusLN)

You can also leave out steps, if they have already been performed and you re-run the installer script.

Most software runs as the bitcoin user (home directory /home/bitcoin). 

## Important Logfiles

| Node Software | Path |
| -------- | ------- |
| bitcoind  | ~/.bitcoin/debug.log   |
| lightningd | ~/.lightning/bitcoin/cl.log  |
| lnd | ~/.lnd/logs/bitcoin/mainnet/lnd.log  |








### Optional NFS

ww /etc/systemd/system/multi-user.target.wants/wg-quick@wg0.service


### add
————————
Before=mnt-odroidnfs.mount
————————


apt install nfs-common

vi /etc/fstab

————————
10.0.0.1:/mnt/hdd/remote-shares/frnfs /mnt/odroidnfs nfs defaults 0 0
————————

# on odroid as root
vi /etc/exports

————————
/mnt/hdd/remote-shares/litnfs 10.0.0.2(rw,sync,no_subtree_check,no_root_squash)
/mnt/hdd/remote-shares/frnfs 10.0.0.3(rw,sync,no_subtree_check,no_root_squash)
/mnt/hdd/remote-shares/usanfs 10.0.0.4(rw,sync,no_subtree_check,no_root_squash)
————————

# on vps
mount /mnt/nfsshare
mkdir /mnt/nfsshare/backups


### NFS END

# END BACKUPS

## Set up ZeusLN on mobile

Host: 10.0.0.1
Rune
REST Port 3010

### BITCOIN USER

# OPTIONAL EPS

```
cd
EPS_VERSION="v0.2.4"
wget https://github.com/chris-belcher/electrum-personal-server/archive/refs/tags/eps-${EPS_VERSION}.tar.gz
tar xvfz eps-${EPS_VERSION}.tar.gz
cd electrum-personal-server-eps-${EPS_VERSION}/

tee config.ini <<EOF
[master-public-keys]
wallet1 = xpub661MyMwAqRbcFseXCwRdRVkhVuzEiskg4QUp5XpUdNf2uGXvQmnD4zcofZ1MN6Fo8PjqQ5cemJQ39f7RTwDVVputHMFjPUn8VRp2pJQMgEF
wallet2 = xpub6CMAJ67vZWVXuzjzYXUoJgWrmuvFRiqiUG4dwoXNFmJtpTH3WgviANNxGyZYo27zxbMuqhDDym6fnBxmGaYoxr6LHgNDo1eEghkXHTX4Jnx
wallet3 = xpub6CMAJ67vZWVXyTJEaZndxZy9ACUufsmNuJwp9k5dHHKa22zQdsgALxXvMRFSwtvB8BRJzsd8h17pKqoAyHtkBrAoSqC9AUcXB1cPrSYATsZ

[bitcoin-rpc]
host = 127.0.0.1
port = 8332
rpc_user = bitcoin
rpc_password = ${BITCOIND_PWD}
wallet_filename = electrumpersonalserver
poll_interval_listening = 30
poll_interval_connected = 1
initial_import_count = 1000
gap_limit = 25

[electrum-server]
host = 0.0.0.0
port = 50001

ip_whitelist = *

#certfile = /home/bitcoin/electrum-personal-server-eps-v0.2.4/env/lib/python3.12/site-packages/electrumpersonalserver/certs/server.csr
#keyfile = /home/bitcoin/electrum-personal-server-eps-v0.2.4/env/lib/python3.12/site-packages/electrumpersonalserver/certs/server.key

disable_mempool_fee_histogram = false
mempool_update_interval = 60
broadcast_method = tor-or-own-node
tor_host = localhost
tor_port = 9050

[watch-only-addresses]
#addr = 1DuqpoeTB9zLvVCXQG53VbMxvMkijk494n

[logging]
log_level_stdout = DEBUG
append_log = false
log_format = %(levelname)s:%(asctime)s: %(message)s
EOF
```

```
CERT_DIR="electrumpersonalserver/certs"
rm ${CERT_DIR}/*
openssl genrsa -des3 -passout pass:x -out ${CERT_DIR}/server.pass.key 2048
openssl rsa -passin pass:x -in ${CERT_DIR}/server.pass.key -out ${CERT_DIR}/cert.key
rm ${CERT_DIR}/server.pass.key
openssl req -new -key ${CERT_DIR}/cert.key -out ${CERT_DIR}/cert.csr
openssl x509 -req -days 1825 -in ${CERT_DIR}/cert.csr -signkey ${CERT_DIR}/cert.key -out ${CERT_DIR}/cert.crt
openssl x509 -enddate -in ${CERT_DIR}/cert.crt

python3 -m venv env
source env/bin/activate

# Patch EPS

head -146 electrumpersonalserver/server/common.py >tmp.py
printf "                context = ssl.SSLContext(ssl.PROTOCOL_TLS)\n                context.load_cert_chain(certfile=certfile, keyfile=keyfile)\n                sock = context.wrap_socket(sock, server_side=True)\n" >>tmp.py
tail -414 electrumpersonalserver/server/common.py >>tmp.py
cp tmp.py electrumpersonalserver/server/common.py
python3 -m pip install . setuptools
```

```
bitcoin-cli createwallet electrumpersonalserver true true "" false false true
electrum-personal-server config.ini
electrum-personal-server config.ini
```


### END EPS

