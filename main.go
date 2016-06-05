// This is a web server that handles individual safe browsing requests
// It was created for use with Splunk workflow lookups, so that an analyst
//  can click a proxy domain/destination host and select SafeBrowsing to
//  view the Google SafeBrowsing opinion of the domain
//  Don Franke, 02 June 2016
package main

import (
    "fmt"
    "net/http"
   	"html/template"
)

// Model of content to render on web page
type Result struct {
	Opinion  string
	URL      string
}

// web server request handler
func handler(w http.ResponseWriter, r *http.Request) {

	// get query string values
	sURL := r.URL.Query().Get("url")
	sAPIKey := r.URL.Query().Get("apikey")

	// create page content model
	m := getData(sAPIKey, sURL)

    // render page
    var indexTemplate = template.Must(template.ParseFiles("display.tmpl"))
	if err := indexTemplate.Execute(w, m); err != nil {
		fmt.Println(err)
	}
}

// start web server and listen for requests
func main() {	
	
	// create web server handlers
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css")))) 
    http.HandleFunc("/r", handler)
    
    // start web server
    fmt.Printf("Web server at port 8080")
	http.ListenAndServe(":8080", nil)
}

// get results from safebrowsing
func getData(a string, u string) Result {
	m := Result{Opinion:"UNKNOWN: Need to call sbserver to get result",URL:u}
	return m
}