package main

import (
	"crypto/tls"
	"fmt"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"net/http"
	"os"
	"time"
)

type Config struct {
	Checks          []Check       `mapstructure:"checks"`
	IntervalSeconds time.Duration `mapstructure:"interval_seconds"`
	HttpPort        int           `mapstructure:"http_port"`
	HttpBindAddress string        `mapstructure:"http_bind_address"`
	LogLevel        string        `mapstructure:"log_level"`
}

type Check struct {
	Servers   []string `mapstructure:"servers"`
	Domain    string   `mapstructure:"domain"`
	Type      string   `mapstructure:"type"`
	Protocols []string `mapstructure:"protocols"`
}

var dnsRequestDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "dns_requests_duration_ms",
		Help:    "Duration of DNS requests in milliseconds",
		Buckets: prometheus.LinearBuckets(10, 10, 10),
	},
	[]string{"server", "protocol", "domain", "type"},
)

var log = logrus.New()

func init() {
	prometheus.MustRegister(dnsRequestDuration)
}

func doDnsQuery(server, domain string, resourceType string, netType string) time.Duration {
	resourceTypeInt, err := getDnsType(resourceType)
	if err != nil {
		fmt.Printf("Unknown DNS Resource Record Type: %s\n", resourceType)
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), resourceTypeInt)

	c := new(dns.Client)
	c.Net = netType

	start := time.Now()
	r, _, err := c.Exchange(m, server+":53")
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("Failed to run DNS query (%s): %v\n", netType, err)
		return duration
	}

	if r.Rcode != dns.RcodeSuccess {
		fmt.Printf("Invalid DNS response received (%s): %v\n", netType, r.Rcode)
		return duration
	}

	dnsRequestDuration.With(prometheus.Labels{
		"server":   server,
		"protocol": netType,
		"domain":   domain,
		"type":     resourceType,
	}).Observe(float64(duration.Milliseconds()))
	return duration
}

func doDotQuery(server, domain string, resourceType string) time.Duration {
	resourceTypeInt, err := getDnsType(resourceType)
	if err != nil {
		fmt.Printf("Unknown DNS Resource Record Type: %s\n", resourceType)
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), resourceTypeInt)

	c := new(dns.Client)
	c.Net = "tcp-tls"
	c.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	start := time.Now()
	r, _, err := c.Exchange(m, server+":853")
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("Failed to run DNS query (DoT): %v\n", err)
		return duration
	}

	if r.Rcode != dns.RcodeSuccess {
		fmt.Printf("Invalid DNS response received (DoT): %v\n", r.Rcode)
		return duration
	}

	dnsRequestDuration.With(prometheus.Labels{
		"server":   server,
		"protocol": "dot",
		"domain":   domain,
		"type":     resourceType,
	}).Observe(float64(duration.Milliseconds()))

	return duration
}

func getDnsType(typeName string) (uint16, error) {
	if dnsType, ok := dns.StringToType[typeName]; ok {
		return dnsType, nil
	}
	return 0, fmt.Errorf("unknown DNS Resource Type: %s", typeName)
}

func periodicDNSCheck(config Config) {
	log.Info("Starting DNS requests thread")
	for {
		log.Debug("Executing DNS requests")
		for i, check := range config.Checks {
			for _, server := range check.Servers {
				for _, protocol := range check.Protocols {
					var duration time.Duration
					switch protocol {
					case "udp":
						duration = doDnsQuery(server, check.Domain, check.Type, "udp")
					case "tcp":
						duration = doDnsQuery(server, check.Domain, check.Type, "tcp")
					case "dot":
						duration = doDotQuery(server, check.Domain, check.Type)
					default:
						log.Errorf("Unknown Protocol: %s\n", protocol)
						continue
					}

					log.Debugf("Check %d: Server=%s, Domain=%s, Type=%s, Protocol=%s, Duration=%dms\n", i+1, server, check.Domain, check.Type, protocol, duration.Milliseconds())
				}
			}
		}
		log.Debugf("Sleeping for %d seconds", config.IntervalSeconds)
		time.Sleep(config.IntervalSeconds * time.Second)
	}
}

func setLogLevel(logLevel string) error {
	switch logLevel {
	case "debug":
		log.SetLevel(logrus.DebugLevel)
	case "info":
		log.SetLevel(logrus.InfoLevel)
	case "warn":
		log.SetLevel(logrus.WarnLevel)
	case "error":
		log.SetLevel(logrus.ErrorLevel)
	case "fatal":
		log.SetLevel(logrus.FatalLevel)
	case "panic":
		log.SetLevel(logrus.PanicLevel)
	default:
		return fmt.Errorf("unknown log level: %s", logLevel)
	}
	return nil
}

func readConfiguration() Config {
	viper.SetConfigFile("dns_exporter.yaml")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Failed to read configuration file: %s", err)
	}
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("Configuration syntax error: %v", err)
	}
	return config
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.DebugLevel)
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	log.Info("Reading configuration")
	config := readConfiguration()
	err := setLogLevel(config.LogLevel)
	if err != nil {
		log.Fatalf("Failed to set log level: %v", err)
	}

	log.Debugf("Config Dump: %+v", config)

	go periodicDNSCheck(config)

	http.Handle("/metrics", promhttp.Handler())

	log.Infof("Starting HTTP listener on %s:%d", config.HttpBindAddress, config.HttpPort)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", config.HttpBindAddress, config.HttpPort), nil))
}
