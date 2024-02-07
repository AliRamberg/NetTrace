package config

import (
	"github.com/gopacket/gopacket/layers"
)

type Config struct {
	Version string            `mapstructure:"version"`
	Filters map[string]Filter `mapstructure:"filters"`
}

type Filter struct {
	DataLink    DataLinkConfig    `mapstructure:"datalink"`
	Network     NetworkConfig     `mapstructure:"network"`
	Transport   TransportConfig   `mapstructure:"transport"`
	Application ApplicationConfig `mapstructure:"application"`
}

type DataLinkConfig struct {
	Ethernet *layers.Ethernet `mapstructure:"ethernet"`
}

type NetworkConfig struct {
	IPv4   *layers.IPv4   `mapstructure:"ipv4"`
	ICMPv4 *layers.ICMPv4 `mapstructure:"icmpv4"`
}

type TransportConfig struct {
	TCP *layers.TCP `mapstructure:"tcp"`
	UDP *layers.UDP `mapstructure:"udp"`
}

type ApplicationConfig struct {
	Regex  []string `mapstructure:"regex"`
	Prefix []string `mapstructure:"prefix"`
}
