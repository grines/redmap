package netscan

import (
	"bytes"
	"fmt"
	"net/http"
	"time"
)

//AddData ...
func ElasticOut(data []byte) {

	//TODO load from config
	urls := "http://localhost:9200/scans/doc"

	checks := []byte(data)

	// initialize http client
	client := &http.Client{Timeout: 2 * time.Second}

	// set the HTTP method, url, and request body
	req, err := http.NewRequest(http.MethodPost, urls, bytes.NewBuffer(checks))
	if err != nil {
		fmt.Println(err)
	}

	// set the request header Content-Type for json
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 201 {

	} else {
		fmt.Printf("Elastic Failed: %v", resp.StatusCode)
	}
}
