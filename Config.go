package main

import (
	"github.com/BurntSushi/toml"
	"net/url"
)


var config = Config{}

// Represents database server and credentials
type Config struct {
	OpenLawUsername        string
	OpenLawPassword        string
	OpenLawUsernameAdmin   string
	OpenLawPasswordAdmin   string
	CoinPaymentsPublic     string
	CoinPaymentsPrivate    string
	CoinPaymentsIPN        string
	CoinPaymentsMerchantId string
	AdminEmail             string
	BasicAuthUser          string
	BasicAuthPass          string
	StripePublic           string
	StripePrivate          string
	StripeWebHookSecret    string
	MailGunPrivate         string
	MailGunPublic          string
	OpenLawInstance        string
	OpenLawInstanceBase    string
	OpenLawInstanceName    string
	ServerLocation         string
}

// Read and parse the configuration file
func (c *Config) Read() {
	if _, err := toml.DecodeFile("config.toml", &c); err != nil {
		log.Fatal().Msg(err.Error())
	}
}

func (c *Config) GetOpenLawUrl(endpoint string) string{
	resource := config.OpenLawInstanceBase + config.OpenLawInstanceName +  endpoint
	u, _ := url.ParseRequestURI(config.OpenLawInstance)
	u.Path = resource
	return u.String()
}