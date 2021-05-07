![](https://github.com/grines/redmap/blob/main/redmap.gif)

# RedMap - External Attack Surface Mapping

Map external attack surface through opensource and paid APIs.

## Status
- This is still an active work in progress. Bugs
- Not ready for production

## Ingestion Modules
- [x] Censys
- [X] Shodan
- [X] Virus Total
- [X] Security Trails
- [X] CRT.sh
- [ ] DNSDumpster
- [ ] https://dns.bufferover.run
- [ ] https://index.commoncrawl.org 
- [ ] https://riddler.io 
- [ ] https://api.certspotter.com
- [ ] https://api.hackertarget.com 
- [ ] https://api.threatminer.org
- [ ] https://community.riskiq.com
- [ ] https://docs.binaryedge.io
- [ ] https://graph.facebook.com
- [ ] https://otx.alienvault.com
- [ ] https://rapiddns.io
- [ ] https://spyse.com
- [ ] https://urlscan.io
- [ ] https://www.dnsdb.info
- [ ] https://www.virustotal.com
- [ ] https://threatcrowd.org
- [ ] https://web.archive.org


# Output Modules
- [X] Elasticsearch
- [X] CSV
- [ ] JSON
- [ ] Splunk
- [ ] Postgres
- [ ] Mongo

# Features
- [X] Common Port Scan
- [ ] Slack Notifications


## Prereqs
- API Keys * Security Trails / Censys / Shodan / Virus Total
 
## Getting Started
- go get github.com/redmap
- cp config/config.json.example config.json

## CLI
- ./redmap -domain example.com 
- ./redmap -domain example.com -scan
