// This is an "interstitial" eb server that handles individual Google Safebrowsing requests;
//   it's a proxy for the proxy
// It was created for use with SIEM (e.g. Splunk) workflow lookups, so that an analyst
//   can click a proxy domain/destination host and select SafeBrowsing to
//   view the Google SafeBrowsing opinion of the domain

// Request flow: SIEM -- workflow item --> SBWS --> sbserver --> [data]

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// Model of content to render on web page
type Display struct {
	Opinion         string
	URL             string
	ThreatType      string
	PlatformType    string
	ThreatEntryType string
	Description     string
}

// response from sbserver POST request
type Results struct {
	Matches []Match
}

// nested within sbserver response
type Match struct {
	ThreatType      string
	PlatformType    string
	ThreatEntryType string
	Threat          struct {
		URL string
	}
}

// messages to display to user
const DESC_SAFE = "Safebrowsing did not find match in its database for this URL.  This is not the same as 100% safe."
const DESC_UNSAFE = "Safebrowsing has reason to believe that this URL is dangerous and should not be visited."
const DESC_ERROR = "There was a problem processing this request. It may be that the URL provided does not meet RFC 3986 (example: http://www.google.com/)"

// web server request handler
func handler(w http.ResponseWriter, r *http.Request) {
	// get query string values
	URL := r.URL.Query().Get("url")
	error := ""

	// ensure URL follows RFC 3986 (last slash is optional)
	u, err := url.Parse(URL)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Println(u.Scheme, u.Host)
	if u.Scheme == "" || u.Host == "" {
		error = "Could not parse URL!!"
	} else {
		URL = u.Scheme + "://" + u.Host + "/"
	}

	// create page content model
	var dis Display
	dis.URL = URL

	if error != "" {
		dis.ThreatType = "ERROR"
		dis.PlatformType = "ERROR"
		dis.ThreatEntryType = "ERROR"
		dis.Opinion = "UNDETERMINED"
		dis.Description = DESC_ERROR
	} else {
		// send JSON request to sbserver
		sbURL := "http://localhost:8080/v4/threatMatches:find"
		jsonSend := "{\"threatInfo\":{\"threatEntries\": [{\"url\":\"" + URL + "apiv4/ANY_PLATFORM/MALWARE/URL/\"}]}}"
		jsonBytes := []byte(jsonSend)
		req, err := http.NewRequest("POST", sbURL, bytes.NewBuffer(jsonBytes))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()

		// process JSON response
		body, _ := ioutil.ReadAll(resp.Body)
		res := &Results{}
		err = json.Unmarshal([]byte(body), res)
		if err != nil {
			log.Fatal(err)
		}

		// empty response means no matches means Safebrowser thinks it's safe
		// we're expecting only 1 response so not iterating the Matches array
		if len([]byte(body)) > 2 {
			// build display object
			dis.ThreatType = res.Matches[0].ThreatType
			dis.PlatformType = res.Matches[0].PlatformType
			dis.ThreatEntryType = res.Matches[0].ThreatEntryType
			dis.Opinion = "UNSAFE"
			dis.Description = DESC_UNSAFE
		} else {
			dis.ThreatType = "NA"
			dis.PlatformType = "NA"
			dis.ThreatEntryType = "NA"
			dis.Opinion = "SAFE"
			dis.Description = DESC_SAFE
		}
	}

	// render web page
	var indexTemplate = template.Must(template.ParseFiles("display.tmpl"))
	if err := indexTemplate.Execute(w, dis); err != nil {
		log.Fatal(err)
	}
}

// default web server request handler
func defaultHandler(w http.ResponseWriter, r *http.Request) {
	// render page
	var indexTemplate = template.Must(template.ParseFiles("default.tmpl"))
	if err := indexTemplate.Execute(w, nil); err != nil {
		log.Fatal(err)
	}
}

// start web server and listen for requests
func main() {
	// get startup params
	port := flag.String("p", "", "Provide a port for web server to use. Must be different than port used by bserver.")
	flag.Parse()
	webport := *port
	if port == nil || webport == "" {
		log.Fatal("EXECUTION HALTED: Not enough arguments supplied. Usage:\n" + showUsage())
	}

	// create web server handlers
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css"))))
	http.HandleFunc("/r", handler)
	http.HandleFunc("/", defaultHandler)

	// start the web server
	fmt.Printf("Safebrowsing Interstitial Web Server (SBWS) now listening to port %s\n", webport)
	fmt.Println(http.ListenAndServe(":"+webport, nil))
}

func showUsage() string {
	var message string
	message = strings.Repeat("-", 75) + "\n"
	message += "\t-p = port to run on (e.g. p=8090)\n"
	message += strings.Repeat("-", 75) + "\n"
	return message
}
