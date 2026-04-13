package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config mirrors the JSON config file. Fields use SCREAMING_SNAKE tags to stay
// compatible with the original Python project's config.json shape.
type Config struct {
	ListenHost         string `json:"LISTEN_HOST"`
	ListenPort         int    `json:"LISTEN_PORT"`
	ConnectIP          string `json:"CONNECT_IP"`
	ConnectPort        int    `json:"CONNECT_PORT"`
	FakeSNI            string `json:"FAKE_SNI"`
	InterfaceIP        string `json:"INTERFACE_IP"`
	QueueNum           uint16 `json:"QUEUE_NUM"`
	HandshakeTimeoutMs int    `json:"HANDSHAKE_TIMEOUT_MS"`
	NoIptablesSetup    bool   `json:"NO_IPTABLES_SETUP"`
	NoConntrackTweak   bool   `json:"NO_CONNTRACK_TWEAK"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, err
	}
	if c.ListenHost == "" || c.ListenPort == 0 || c.ConnectIP == "" || c.ConnectPort == 0 || c.FakeSNI == "" {
		return nil, fmt.Errorf("config missing required fields")
	}
	if c.QueueNum == 0 {
		c.QueueNum = 100
	}
	if c.HandshakeTimeoutMs == 0 {
		c.HandshakeTimeoutMs = 2000
	}
	return c, nil
}
