#!/bin/bash
# Certbot DNS-01 validation authenticator hook for DuckDNS
TOKEN="YOUR_DUCKDNS_TOKEN"
DOMAIN="YOUR_SUBDOMAIN"

curl -s "https://www.duckdns.org/update?domains=${DOMAIN}&token=${TOKEN}&txt=${CERTBOT_VALIDATION}"
# Sleep to allow DuckDNS servers to propagate DNS records
sleep 30
