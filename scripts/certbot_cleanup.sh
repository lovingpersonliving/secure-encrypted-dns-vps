#!/bin/bash
# Certbot DNS-01 validation cleanup hook for DuckDNS
TOKEN="YOUR_DUCKDNS_TOKEN"
DOMAIN="YOUR_SUBDOMAIN"

curl -s "https://www.duckdns.org/update?domains=${DOMAIN}&token=${TOKEN}&clear=true"
