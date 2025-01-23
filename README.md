# Slim node - set up Bitcoin and Lightning node with a few commands

Dieser Guide beschreibt das Aufsetzen des Nodes auf einem VPS. Es gibt eine Vielzahl von Anbietern, für ca. 5$/Monat kann man einen VPS bekommen, der vollkommen ausreicht und der etwa folgende Eigenschaften aufweist:    


- 8 GB RAM
- 100 GB SSD
- Ubuntu 24+

6 GB RAM reichen auch, viel weniger als 80 GB Storage sollten es aber nicht sein.

Desweiteren sollte dir die öffentliche IP deines Servers bekannt sein, die wir der Einfachheit halber  in /etc/hosts unseres Arbeitsrechners eintragen:

```
185.170.58.134  vps
```

Ein root-Passwort solltest du auch über die Oberfläche des Anbieters vergeben können und ggf. ssh-Keys eintragen.

Als ersten werden wir ein paar Sicherheitseinstellungen vornehmen. Zunächste kopieren wir die SSH-Keys unseres aktuellen Users auf unseren Server:

```console
ssh-copy-id root@vps
ssh root@vps
```
Du solltest nun auf deinem VPS eingeloggt sein.


### Turn of password authentication, update system & install some software


```console
apt update && apt full-upgrade -y && apt install -y ufw htop btop iptraf fail2ban tor autoconf automake build-essential git libtool libsqlite3-dev libffi-dev python3 python3-pip net-tools zlib1g-dev libsodium-dev gettext python3-mako git automake autoconf-archive libtool build-essential pkg-config libev-dev libcurl4-gnutls-dev libsqlite3-dev python3-poetry python3-venv wireguard python3-json5 python3-flask python3-gunicorn python3-gevent python3-websockets python3-flask-cors python3-flask-socketio python3-gevent-websocket valgrind libpq-dev shellcheck cppcheck libsecp256k1-dev lowdown cargo rustfmt protobuf-compiler python3-grpcio nodejs npm python3-grpc-tools python3-psutil && systemctl enable fail2ban && systemctl enable tor && echo "PasswordAuthentication no" >>/etc/ssh/sshd_config
```

# Create Bitcoin user and give some permissions

```console
useradd -m bitcoin -s /bin/bash && sudo adduser bitcoin sudo && usermod -a -G debian-tor bitcoin
passwd bitcoin
```

Password 1: Set a password here and save it in your password manager (e.g. as 'VPS bitcoin user')

## Configure Firewall & Reboot

```console
ufw default deny incoming
ufw default allow outgoing
ufw allow 51820/udp
ufw allow ssh
ufw allow 9735/tcp
ufw allow proto tcp from 10.0.0.0/24 to 10.0.0.0/24 port 3000,3010,8332,50001,50002
ufw logging off
ufw enable
systemctl enable ufw
reboot
```


## Login as bitcoin User & Generate SSH Keys

```console
ssh bitcoin@vps
ssh-keygen -t rsa -b 4096
```



## On Work Station

```console
ssh-copy-id bitcoin@vps
ssh bitcoin@vps
```

## Install Bitcoin Core

```console
VERSION="27.0"
wget https://bitcoincore.org/bin/bitcoin-core-${VERSION}/bitcoin-${VERSION}-x86_64-linux-gnu.tar.gz
wget https://bitcoincore.org/bin/bitcoin-core-${VERSION}/SHA256SUMS
wget https://bitcoincore.org/bin/bitcoin-core-${VERSION}/SHA256SUMS.asc
sha256sum --ignore-missing --check SHA256SUMS
curl -s "https://api.github.com/repositories/355107265/contents/builder-keys" | grep download_url | grep -oE "https://[a-zA-Z0-9./-]+" | while read url; do curl -s "$url" | gpg --import; done
gpg --verify SHA256SUMS.asc
```

Check signatures here.

```console
tar -xvf bitcoin-${VERSION}-x86_64-linux-gnu.tar.gz
sudo install -m 0755 -o root -g root -t /usr/local/bin bitcoin-${VERSION}/bin/*
mkdir -p .bitcoin .lightning/bitcoin/backups/

BITCOIND_PW=`cat /dev/urandom | LC_ALL=C tr -dc 'a-zA-Z0-9' | fold -w 50 | head -n 1`
```

Set your public/external IP

```
PUBLIC_IP="23.94.235.61"
tee >~/.bitcoin/bitcoin.conf <<EOF
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
EOF
```

## Install Core Lightning

```console
git clone https://github.com/ElementsProject/lightning.git && cd lightning && git checkout v24.11.1 && poetry install && ./configure --disable-rust && poetry run make && sudo make install
 ```

 Enter bitcoin user PW.
 ```console
pip3 install --user pyln-client websockets --break-system-packages
pip3 install --user flask-cors flask-restx pyln-client flask-socketio gevent gevent-websocket --break-system-packages

tee ~/.lightning/config <<EOF
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
bitcoin-rpcpassword=${BITCOIND_PW}
bind-addr=${PUBLIC_IP}:9735
announce-addr=${PUBLIC_IP}:9735
EOF
```

### Configure Backup Plugin

```console
cd
git clone https://github.com/lightningd/plugins.git && cd plugins/backup && poetry install && poetry run ./backup-cli init --lightning-dir /home/bitcoin/.lightning/bitcoin file:///home/bitcoin/.lightning/bitcoin/backups/lightningd.sqlite3.bkp

sudo su -
```

## AS ROOT USER


### Start scripts for bitcoind, lightningd and RTL

```console
tee  /etc/systemd/system/bitcoind.service <<EOF
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
EOF

tee /etc/systemd/system/lightningd.service <<EOF
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
EOF

tee /etc/systemd/system/rtl.service <<EOF
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
EOF

```

### Start bitcoin and check log file

```console
systemctl enable bitcoind && systemctl enable lightningd.service && systemctl start bitcoind
tail -f /home/bitcoin/.bitcoin/debug.log
<CTRL-c>
```

```
systemctl enable lightningd.service && systemctl start lightningd.service
tail -f /home/bitcoin/.lightning/bitcoin/cl.log
<CTRL-c>
```

### Bitcoin & Lightning running

## Install RTL

### BITCOIN USER

```console
su - bitcoin
git clone https://github.com/Ride-The-Lightning/RTL.git
cd RTL
npm install --omit=dev --legacy-peer-deps
```

Password 2: Change WEB_PW to your future RTL web login password and save the PW in you PW manager (e.g. as 'RTL web login')

```console
WEB_PW="changeme" 
tee RTL-Config.json <<EOF
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
  "multiPass": "${WEB_PW}"
}
EOF

echo "LIGHTNING_RUNE=`lightning-cli createrune | jq .rune`" >rune.txt

sudo systemctl enable rtl.service && sudo systemctl start rtl.service
```

### END RTL

exit

### ROOT USER

## Configure wireguard - set the first two variable with the public keys for your phone & desktop pc

```console
PHONE_PUBLIC_KEY=<SET ME>
DESKTOP_PUBLIC_KEY=<SET_ME>
wg genkey | sudo tee /etc/wireguard/private.key && chmod go= /etc/wireguard/private.key && cat /etc/wireguard/private.key | wg pubkey | tee /etc/wireguard/public.key

PRIV_KEY=`cat /etc/wireguard/private.key` tee /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = ${PRIV_KEY}

PostUp = ufw route allow in on wg0 out on eth0
PostUp = iptables -t nat -I POSTROUTING -o eth0 -j MASQUERADE
PostUp = ip6tables -t nat -I POSTROUTING -o eth0 -j MASQUERADE
PreDown = ufw route delete allow in on wg0 out on eth0
PreDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
PreDown = ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Phone
[Peer]
PublicKey = ${PHONE_PUBLIC_KEY}
AllowedIPs = 10.0.0.2/32
PersistentKeepalive = 15

# Desktop
[Peer]
PublicKey = ${DESKTOP_PUBLIC_KEY}
AllowedIPs = 10.0.0.3/32
EOF
```

```console
echo "net.ipv4.ip_forward=1" >>/etc/sysctl.conf
sysctl -p

systemctl restart wg-quick@wg0 && wg show
```

<wireguard-screenshot iphone>

## Wireguard Config Arbeitsrechner

```console
[Interface]
PrivateKey = <DESKTOP PRIVATE KEY>
Address = 10.0.0.3/24

# VPS
[Peer]
PublicKey = mC0p+VBgBJImwlb7D2MehElGuY+F9r3yF7mFd4pFYDk=
AllowedIPs = 10.0.0.1/32
Endpoint = 185.170.58.134:51820
```

# Backups & Maintenance

```console
tee /etc/cron.hourly/backuptasks <<EOF
#!/bin/sh
rsync -av /home/bitcoin/.lightning/bitcoin/emergency.recover /home/bitcoin/.lightning/bitcoin/backups/emergency.recover.bak
rsync -av /home/bitcoin/.lightning/bitcoin/hsm_secret /home/bitcoin/.lightning/bitcoin/backups/hsm_secret.bak
EOF

chmod 755 /etc/cron.hourly/backuptasks

echo "55 4    * * *   bitcoin lightning-cli backup-compact"  >>/etc/crontab

systemctl restart cron.service
```

## Optional NFS

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
wget https://github.com/chris-belcher/electrum-personal-server/archive/refs/tags/eps-v0.2.4.tar.gz
tar xvfz eps-v0.2.4.tar.gz
cd electrum-personal-server-eps-v0.2.4/
vi config.ini
```

```
[master-public-keys]
any_name_works = xpub661MyMwAqRbcFseXCwRdRVkhVuzEiskg4QUp5XpUdNf2uGXvQmnD4zcofZ1MN6Fo8PjqQ5cemJQ39f7RTwDVVputHMFjPUn8VRp2pJQMgEF
wallet2 = xpub6CMAJ67vZWVXuzjzYXUoJgWrmuvFRiqiUG4dwoXNFmJtpTH3WgviANNxGyZYo27zxbMuqhDDym6fnBxmGaYoxr6LHgNDo1eEghkXHTX4Jnx
wallet3 = xpub6CMAJ67vZWVXyTJEaZndxZy9ACUufsmNuJwp9k5dHHKa22zQdsgALxXvMRFSwtvB8BRJzsd8h17pKqoAyHtkBrAoSqC9AUcXB1cPrSYATsZ

[bitcoin-rpc]
host = 127.0.0.1
port = 8332
rpc_user = bitcoin
rpc_password = 2z0HNxvB3Bbog6aNynVO8IXcE80wPq36uk6P4dBKsFqv5ktEMF
wallet_filename = electrumpersonalserver
poll_interval_listening = 30
poll_interval_connected = 1
initial_import_count = 1000
gap_limit = 25

[electrum-server]
host = 0.0.0.0
port = 50001

ip_whitelist = *

#certfile = certs/server.csr
#keyfile = certs/server.key

disable_mempool_fee_histogram = false
mempool_update_interval = 60
broadcast_method = tor-or-own-node
tor_host = localhost
tor_port = 9050


[watch-only-addresses]
#addr = 1DuqpoeTB9zLvVCXQG53VbMxvMkijk494n

[logging]
log_level_stdout = INFO
append_log = false
log_format = %(levelname)s:%(asctime)s: %(message)s
```

```
rm electrumpersonalserver/certs/*
openssl genrsa -des3 -passout pass:x -out electrumpersonalserver/certs/server.pass.key 2048
openssl rsa -passin pass:x -in electrumpersonalserver/certs/server.pass.key -out electrumpersonalserver/certs/server.key
rm electrumpersonalserver/certs/server.pass.key
openssl req -new -key electrumpersonalserver/certs/server.key -out electrumpersonalserver/certs/server.csr

python3 -m venv env
source env/bin/activate
pip3 install .
python3 -m pip install setuptools
ww electrumpersonalserver/server/common.py
```

```
Zeilen 147-149 ersetzen durch:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                context.load_cert_chain(certfile=certfile, keyfile=keyfile)
                sock = context.wrap_socket(sock, server_side=True)
```

```
bitcoin-cli createwallet electrumpersonalserver true true "" false false true
electrum-personal-server config.ini
electrum-personal-server config.ini
```


### END EPS

