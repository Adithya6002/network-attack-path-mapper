#!/bin/sh
# One-shot setup for lab-web or lab-db. Run while the VM's NAT adapter is connected:
#   wget http://10.0.3.2:8000/lab/setup-server.sh && sudo sh setup-server.sh web
#   wget http://10.0.3.2:8000/lab/setup-server.sh && sudo sh setup-server.sh db
# (VirtualBox NAT on adapter 2 puts the host at 10.0.3.2.)
set -e
case "$1" in
    web) IP=10.10.20.10; GW=10.10.20.1 ;;
    db)  IP=10.10.30.20; GW=10.10.30.1 ;;
    *)   echo "usage: sudo sh setup-server.sh web|db"; exit 1 ;;
esac

# lab-web was cloned from lab-db, so set the hostname explicitly.
hostnamectl set-hostname "lab$1"
sed -i "s/^127\.0\.1\.1 .*/127.0.1.1 lab$1/" /etc/hosts

echo "== Static lab address $IP (lab traffic via $GW)"
cat > /etc/netplan/60-lab.yaml <<EOF
network:
  version: 2
  ethernets:
    enp0s3:
      addresses: [$IP/24]
      routes: [{to: 10.10.0.0/16, via: $GW}]
EOF
chmod 600 /etc/netplan/60-lab.yaml
netplan apply
sleep 2

DEBIAN_FRONTEND=noninteractive apt-get update -qq
if [ "$1" = web ]; then
    echo "== nginx (ports 80, 443)"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx ssl-cert
    # HTTPS with the self-signed "snakeoil" cert that ssl-cert generates.
    cat > /etc/nginx/sites-enabled/lab-https <<'EOF'
server {
    listen 443 ssl default_server;
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    root /var/www/html;
}
EOF
    nginx -t && systemctl restart nginx
else
    echo "== PostgreSQL (port 5432, listening on the lab network)"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postgresql
    VER=$(ls /etc/postgresql | sort -V | tail -1)
    echo "listen_addresses = '*'" > "/etc/postgresql/$VER/main/conf.d/lab.conf"
    systemctl restart postgresql
fi

echo
ip -br addr show enp0s3
echo "Listening TCP ports:"
ss -tln | awk 'NR>1 {print "  " $4}'
echo "lab-$1 ready."
