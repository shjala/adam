module github.com/lf-edge/adam

go 1.22

require (
	eve_pcr_prediction v0.0.0-00010101000000-000000000000
	github.com/aohorodnyk/mimeheader v0.0.6
	github.com/golang/protobuf v1.5.0
	github.com/google/go-tpm v0.3.3
	github.com/gorilla/mux v1.7.2
	github.com/lf-edge/eve-api/go v0.0.0-20260116205402-bac92fb1f235
	github.com/satori/go.uuid v1.2.1-0.20181028125025-b2ce2384e17b
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.7.1
	google.golang.org/protobuf v1.36.3
)

replace eve_pcr_prediction => ../

require (
	github.com/envoyproxy/protoc-gen-validate v1.2.1 // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/magiconair/properties v1.8.4 // indirect
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/pelletier/go-toml v1.8.1 // indirect
	github.com/spf13/afero v1.10.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	golang.org/x/sys v0.27.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	gopkg.in/ini.v1 v1.62.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
