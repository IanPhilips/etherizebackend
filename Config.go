package etherizeBackend

import "github.com/BurntSushi/toml"

// Represents database server and credentials
type Config struct {
	Username string
	Password string
}

// Read and parse the configuration file
func (c *Config) Read() {
	if _, err := toml.DecodeFile("config.toml", &c); err != nil {
		log.Fatal().Msg(err.Error())
	}
}