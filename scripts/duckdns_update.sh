#!/bin/bash
# Update DuckDNS domain with your current IPv4/IPv6 address
DOMAIN="YOUR_SUBDOMAIN"
TOKEN="YOUR_DUCKDNS_TOKEN"

echo url="https://www.duckdns.org/update?domains=${DOMAIN}&token=${TOKEN}&ip=" | curl -k -o /var/log/duckdns.log -K -
