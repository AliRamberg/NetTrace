package cmd

import (
	"net"
	"os"

	"github.com/AliRamberg/NetTrace/pkg/bpf"
	"github.com/AliRamberg/NetTrace/pkg/config"
	"github.com/AliRamberg/NetTrace/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	log               = logger.Get()
	networkInterfaces []string
	cfgFile           string
	configMap         config.Config
)

const (
	AnyInterface = "any"
)

var rootCmd = &cobra.Command{
	Use:   "query",
	Short: "Start querying for network events.",
	Long: `Start querying for network events. This command will start querying for network events based on the specified query.
	Only select protocols will be processed by the BPF program, the rest is processed by the userspace program.
	`,
	PreRun: func(cmd *cobra.Command, args []string) {
		if len(networkInterfaces) == 0 {
			cmd.Help()
			os.Exit(1)
		}

		if len(networkInterfaces) == 1 && networkInterfaces[0] == AnyInterface {
			interfaces, err := net.Interfaces()
			if err != nil {
				log.Errorf("failed to get network interfaces: %s", err)
				os.Exit(1)
			}
			if len(interfaces) == 0 {
				log.Error("no network interfaces found")
				os.Exit(1)
			}

			networkInterfaces = make([]string, 0, len(interfaces))
			for _, i := range interfaces {
				networkInterfaces = append(networkInterfaces, i.Name)
			}
		}

		if err := viper.Unmarshal(&configMap); err != nil {
			log.Errorf("failed to unmarshal config: %s", err)
			os.Exit(1)
		}

	},

	Run: func(cmd *cobra.Command, args []string) {
		bpf.Trace(&configMap, networkInterfaces)
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "filters", "filters.yml", "config file with pre-defined filters")

	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.PersistentFlags().StringArrayVarP(&networkInterfaces, "interface", "i", []string{}, "The network interface to listen on.")
}

func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		log.Debugf("Using config file: %s", viper.ConfigFileUsed())
	}

}
