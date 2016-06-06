# Safebrowsing Interstitial Web Server
Safebrowsing Interstitial Web Server (in development) written in Go

The goal is the have a local web server that can be called by a SIEM as a workflow process, which would then call the sbserver to get an opinion on a URL.  This was created because there are CORS issues with attempting to call the local SB server directly from the SIEM. This serves as an intermediary which would not have same CORS issue since both it and sbserver are running locally. This also avoids having to modify the sbserver to add CORS headers, or to have it redirect to a site that it thinks is SAFE but perhaps is not but just isn't catalogued by SB (not good!).

SIEM --> sbiws --> sbserver --> [sb data]

# Usage
```
./sbiws -p=[port number]
```
Note: port number used by sbiws must be different than port used by sbserver, since both are running on same host.

# Requirements
* Go
* sbserver
