# Prometheus DNS Exporter

This is a very simple Prometheus exporter to gather timings for various DNS requests. It currently supports:

- DNS over UDP, TCP and DoT
- specify target DNS server, resource type and domain

All you need is a simple configuration file:

```yaml
---
interval_seconds: 15
http_bind_address: 127.0.0.1
http_port: 5353
log_level: info
checks:
  - servers:
      - 9.9.9.9
    domain: www.google.de
    type: A
    protocols:
      - dot
      - tcp
      - udp
  - servers:
      - 1.1.1.1
    domain: de
    type: SOA
    protocols:
      - udp
  - servers:
      - 127.0.0.1
    domain: something.local
    type: A
    protocols:
      - udp
```

Metrics will be available under the `/metrics` endpoint on the configured bind IP / port.