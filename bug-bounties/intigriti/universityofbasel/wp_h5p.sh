#!/usr/bin/env bash
UA="Intigriti-UniBas-VDP-eliam Mozilla/5.0 (compatible; BugBountyResearcher)"
timeout 1500 wpscan --url "http://nmc-hp5-24.nmc.unibas.ch:8080/" \
  --user-agent "$UA" --headers "X-Intigriti-Username: eliam" \
  --throttle 250 --disable-tls-checks --force \
  --enumerate vp,vt,cb,dbe --format cli-no-color \
  -o "logs/wpscan_nmc-hp5-24.txt" 2>&1 | tail -3
