package config

import (
	"encoding/json"
	"fmt"
	"os"
)

//Configuration for sensitive data and settings
var Configuration config

type config struct {
	Apishodan       string `json:"apiShodan"`
	Apitrails       string `json:"apiTrails"`
	Apivirustotal   string `json:"apiVirustotal"`
	Apicensysuid    string `json:"apiCensysUID"`
	Apicensyssecret string `json:"apiCensysSecret"`
	Apisplunk       string `json:"apiSplunk"`
	Splunkendpoint  string `json:"splunkEndpoint"`
	Slackwebhookurl string `json:"slackWebhookURL"`
}

//Load configuration function
func Load(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
	}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&Configuration)
	if err != nil {
		fmt.Println(err)
	}

}
