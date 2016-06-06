// This is a web server that handles individual safe browsing requests
// It was created for use with SIEM (e.g. Splunk) workflow lookups, so that an analyst
//  can click a proxy domain/destination host and select SafeBrowsing to
//  view the Google SafeBrowsing opinion of the domain
package main

import (
    "fmt"
    "net/http"
    "html/template"
    "flag"
    "io/ioutil"
    "log"
    "bytes"
    "encoding/json"     
)

// Model of content to render on web page
type Display struct {
    Opinion  string
    URL      string
    ThreatType   string
    PlatformType string 
    ThreatEntryType string 
}

type Results struct {
    Matches []Match     
}

type Match struct {
    ThreatType string 
    PlatformType string 
    ThreatEntryType string 
    Threat struct {
        URL string
    }
}

// web server request handler
func handler(w http.ResponseWriter, r *http.Request) {
    // get query string values
    URL := r.URL.Query().Get("url")

    // create page content model
    var dis Display
    // get opinion from sbserver
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

    body, _ := ioutil.ReadAll(resp.Body)
    
    res := &Results{}
    err = json.Unmarshal([]byte(body), res)
    if(err!=nil) {
        log.Fatal(err)
    }
    
    // no results means no matches means its safe (per Safebrowser)
    if(len([]byte(body))>2) {
        // build display object
        dis.ThreatType=res.Matches[0].ThreatType
        dis.PlatformType=res.Matches[0].PlatformType
        dis.ThreatEntryType=res.Matches[0].ThreatEntryType
        dis.Opinion="UNSAFE"
    } else {
        dis.ThreatType="NA"
        dis.PlatformType="NA"
        dis.ThreatEntryType="NA"
        dis.Opinion="SAFE"
    }
    dis.URL = URL

    // render page
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
    port := flag.String("p","","Provide a port for web server to use")
    flag.Parse()
    webport := *port
    if(port==nil||webport=="") {
        log.Fatal("Need to provide a port...exiting!")
    }
    
    // create web server handlers
    http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css")))) 
    http.HandleFunc("/r", handler)
    http.HandleFunc("/", defaultHandler)

    // start web server
    fmt.Printf("Web server at port %s\n",webport)
    fmt.Println(http.ListenAndServe(":"+webport, nil))
}

