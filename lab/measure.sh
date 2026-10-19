#!/bin/bash
# Measure real TCP reachability from this VM to every other lab host.
# Usage:  bash measure.sh <policy-label>      e.g.  bash measure.sh baseline
# Prints one CSV row per test:  policy,source,destination,port,result
#   open    = TCP handshake completed (firewall allowed, service listening)
#   refused = RST received            (firewall allowed, nothing listening)
#   timeout = no answer in 3 s        (dropped, e.g. by the router firewall)
# Results are also saved to ~/results-<policy>-<source>.csv

POLICY=${1:?usage: bash measure.sh <policy-label>}
HOSTS="10.10.10.5 10.10.20.10 10.10.30.20"
PORTS="22 80 443 445 5432 8080"
SRC=$(ip -4 -o addr show | awk '{split($4, a, "/"); if (a[1] ~ /^10\.10\./) {print a[1]; exit}}')
OUT=~/results-$POLICY-$SRC.csv

: > "$OUT"
for dst in $HOSTS; do
    [ "$dst" = "$SRC" ] && continue
    for port in $PORTS; do
        timeout 3 bash -c "</dev/tcp/$dst/$port" 2>/dev/null
        case $? in
            0)   result=open ;;
            124) result=timeout ;;
            *)   result=refused ;;
        esac
        echo "$POLICY,$SRC,$dst,$port,$result" | tee -a "$OUT"
    done
done
echo "saved $OUT"
