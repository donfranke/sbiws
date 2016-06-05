# sbws
Safebrowsing interstitial web server (in development) written in Go

**In development**
The goal is the have a local web server that can be called by a SIEM as a workflow process, which would then call the sbserver to get an opinion on a URL being researched by a security analyst.  Need to add a call to sbserver that will return Safe Browsing lookup result. The poiint is that there are CORS issues with attempting to call the local SB server from the SIEM, so this would serve as an intermediary which would not have same CORS issue since both it and sbserver are local. This also avoid having to modify code of sbserver to add CORS headers or to have it redirect to a site that it thinks is SAFE but perhaps is not but just isn't catalogued by SB.

SIEM --> sbws --> sbserver --> [sb data]

# Requirements
* Go
* sbserver
