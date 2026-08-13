package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Tempo    TempoConfig    `yaml:"tempo"`
	Mimir    MimirConfig    `yaml:"mimir"`
	Analysis AnalysisConfig `yaml:"analysis"`
	Output   OutputConfig   `yaml:"output"`
}

type TempoConfig struct {
	URL          string        `yaml:"url"`
	PollInterval time.Duration `yaml:"poll_interval"`
	Lookback     time.Duration `yaml:"lookback"`
	SampleLimit  int           `yaml:"sample_limit"`
	TenantID     string        `yaml:"tenant_id"`
}

type MimirConfig struct {
	URL      string `yaml:"url"`
	TenantID string `yaml:"tenant_id"`
}

type AnalysisConfig struct {
	SpanAttributes       []string `yaml:"span_attributes"`
	BaggageHeaderAttr    string   `yaml:"baggage_header_attribute"` // e.g. "ind.baggage.cj"; empty = auto-detect
	RootAnomalyThreshold float64  `yaml:"root_anomaly_threshold"`
	MinCalleeCount       int      `yaml:"min_callee_count"`
}

type OutputConfig struct {
	Format string `yaml:"format"` // json | table | summary
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := defaults()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func defaults() *Config {
	return &Config{
		Tempo: TempoConfig{
			URL:          "http://localhost:3200",
			PollInterval: 5 * time.Minute,
			Lookback:     10 * time.Minute,
			SampleLimit:  200,
		},
		Mimir: MimirConfig{
			URL: "http://localhost:9009",
		},
		Analysis: AnalysisConfig{
			SpanAttributes:       []string{}, // empty = auto-discover from span data
			RootAnomalyThreshold: 0.001,
			MinCalleeCount:       50,
		},
		Output: OutputConfig{
			Format: "summary",
		},
	}
}
