package query

import (
	"github.com/AliRamberg/NetTrace/pkg/logger"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var log = logger.Get()

const (
	kernelspaceStructSize uint32 = 54
)

type Query struct {
	Layers []gopacket.SerializableLayer
	Size   uint32
}

func NewQuery(queryLayers ...gopacket.SerializableLayer) *Query {
	size := uint32(0)
	for _, layer := range queryLayers {
		switch l := layer.LayerType(); l {
		case layers.LayerTypeEthernet:
			size += 14
		case layers.LayerTypeIPv4:
			size += 20
		case layers.LayerTypeICMPv4:
			size += 8
		case layers.LayerTypeTCP:
			size += 20
		case layers.LayerTypeUDP:
			size += 8
		}
	}

	if size > 0 && size <= kernelspaceStructSize {
		size = kernelspaceStructSize
	} else if size > kernelspaceStructSize {
		log.Errorf("size of query (%d) is too large to unmarshal in kernelspace", size)
		return nil
	}
	return &Query{
		Layers: queryLayers,
		Size:   size,
	}
}
