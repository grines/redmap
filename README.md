![](https://github.com/grines/redmap/blob/main/redmap.gif)

# RedMap - External Attack Surface Mapping

Map external attack surface through opensource and paid APIs.

## Status
- This is still an active work in progress. Migh have some bugs

## Ingestion Modules
- [x] Censys
- [X] Shodan
- [X] Virus Total
- [X] Security Trails
- [X] CRT.sh
- [ ] DNSDumpster

# Output Modules
- [X] Elasticsearch
- [X] CSV
- [ ] JSON
- [ ] Splunk
- [ ] Postgres
- [ ] Mongo

# Features
- [X] Common Port Scan


## Prereqs
- API Keys * Security Trails / Censys / Shodan / Virus Total
 
## Getting Started
- go get github.com/redmap

## CLI
- ./redmap -domain example.com 
- ./redmap -domain example.com -scan
