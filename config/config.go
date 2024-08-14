package config

import (
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	HTTPServer HTTPServer `yaml:"http_server"`
}

type HTTPServer struct {
	Address string        `yaml:"address" env-default:":8080"`
	Timeout time.Duration `yaml:"timeout" env-default:"5s"`
}

func Parse(s string) (*Config, error) {
	c := &Config{}
	if err := cleanenv.ReadConfig(s, c); err != nil {
		return nil, err
	}

	return c, nil
}
