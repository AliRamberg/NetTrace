package bpf

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/AliRamberg/NetTrace/pkg/config"
	"github.com/AliRamberg/NetTrace/pkg/logger"
	"github.com/AliRamberg/NetTrace/pkg/query"
	"github.com/gopacket/gopacket"
)

var log = logger.Get()

//go:generate echo "Generating tc_bpf.go"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf tc tc.c

func Trace(config *config.Config, networkInterfaces []string) error {
	log := logger.Get()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	tc := NewTrafficControlManager(config)
	if tc == nil {
		log.Fatal("failed to create traffic control manager")
	}

	for _, networkInterface := range networkInterfaces {
		if err := tc.Load(networkInterface); err != nil {
			log.Errorf("failed to load tc program: %s", err)
			return err
		}
	}
	defer tc.Close()

	var err error
	var customFilters *map[string][]gopacket.SerializableLayer

	fmt.Println(config.Filters)
	if len(config.Filters) == 0 {
		log.Warn("no filters specified, defaulting to all traffic")
		customFilters = &map[string][]gopacket.SerializableLayer{
			"all": {},
		}
	} else {
		log.Infof("processing %d custom filters", len(config.Filters))
		customFilters, err = query.ProcessCustomFilters(config.Filters)
		if err != nil {
			log.Errorf("failed to process custom filters: %s", err)
			return err
		}
	}

	for _, filterLayers := range *customFilters {
		query := query.NewQuery(filterLayers...)

		if err := tc.AddQuery(query); err != nil {
			log.Errorf("failed to add query: %s", err.Error())
			return err
		}
	}

	go func() {
		tc.ReadLoop()
	}()

	<-stop
	return nil
}
