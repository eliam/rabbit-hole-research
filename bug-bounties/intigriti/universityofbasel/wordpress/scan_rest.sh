#!/usr/bin/env bash
UA="Intigriti-UniBas-VDP-eliam Mozilla/5.0 (compatible; BugBountyResearcher)"
for HOST in dmi-sphexa.dmi.unibas.ch ispdc2022.dmi.unibas.ch; do
  echo "=== scanning $HOST ==="
  timeout 1500 wpscan --url "https://$HOST/" \
    --user-agent "$UA" --headers "X-Intigriti-Username: eliam" \
    --throttle 250 --disable-tls-checks \
    --enumerate vp,vt,cb,dbe --format cli-no-color \
    -o "logs/wpscan_$HOST.txt" 2>&1 | tail -5
done
echo "=== both scans finished ==="
