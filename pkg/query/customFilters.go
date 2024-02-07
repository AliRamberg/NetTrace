package query

import (
	"net"

	"github.com/AliRamberg/NetTrace/pkg/config"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var (
	defaultMACAddress = []byte{0, 0, 0, 0, 0, 0}
	defaultIPAddress  = net.IP{0, 0, 0, 0}
)

func ProcessCustomFilters(filters map[string]config.Filter) (*map[string][]gopacket.SerializableLayer, error) {
	filterMaps := make(map[string][]gopacket.SerializableLayer, len(filters))

	for name, filter := range filters {

		// Construct Data Link layer
		dataLinkLayer := processDataLinkFilter(&filter)
		if dataLinkLayer != nil {
			filterMaps[name] = append(filterMaps[name], dataLinkLayer)
		}

		// Construct Network layer
		networkLayer := processNetworkFilter(&filter)
		if networkLayer != nil {
			filterMaps[name] = append(filterMaps[name], networkLayer)
		}

		// Construct Transport layer
		transportLayer := processTransportFilter(&filter)
		if transportLayer != nil {
			filterMaps[name] = append(filterMaps[name], transportLayer)
		}
	}

	return &filterMaps, nil
}

func processDataLinkFilter(filter *config.Filter) gopacket.SerializableLayer {
	log.Debugf("Processing Ethernet filter")
	if filter.DataLink.Ethernet != nil {
		ethLayer := &layers.Ethernet{
			SrcMAC: defaultMACAddress,
			DstMAC: defaultMACAddress,
		}
		if filter.DataLink.Ethernet.SrcMAC != nil {
			ethLayer.SrcMAC = net.HardwareAddr(filter.DataLink.Ethernet.SrcMAC)
		}
		if filter.DataLink.Ethernet.DstMAC != nil {
			ethLayer.DstMAC = net.HardwareAddr(filter.DataLink.Ethernet.DstMAC)
		}
		if filter.DataLink.Ethernet.EthernetType != 0 {
			ethLayer.EthernetType = layers.EthernetType(filter.DataLink.Ethernet.EthernetType)
		} else {
			log.Warnf("No Ethernet type specified, defaulting to IPv4")
			ethLayer.EthernetType = layers.EthernetTypeIPv4
		}

		return ethLayer
	}
	return nil
}

func processNetworkFilter(filter *config.Filter) gopacket.SerializableLayer {
	log.Debug("Processing IPv4 filter")
	if filter.Network.IPv4 != nil {
		ipLayer := &layers.IPv4{
			Version: 4,
			SrcIP:   defaultIPAddress,
			DstIP:   defaultIPAddress,
		}
		if filter.Network.IPv4.SrcIP != nil {
			ipLayer.SrcIP = net.IP(filter.Network.IPv4.SrcIP)
		}
		if filter.Network.IPv4.DstIP != nil {
			ipLayer.DstIP = net.IP(filter.Network.IPv4.DstIP)
		}
		if filter.Network.IPv4.Protocol != 0 {
			ipLayer.Protocol = layers.IPProtocol(filter.Network.IPv4.Protocol)
		} else {
			log.Warnf("No protocol specified for IPv4 layer, defaulting to TCP")
			ipLayer.Protocol = layers.IPProtocolTCP
		}

		return ipLayer
	}
	return nil
}

func processTransportFilter(filter *config.Filter) gopacket.SerializableLayer {
	log.Debug("Processing Transport layer filter")
	if filter.Transport.TCP != nil {
		tcpLayer := &layers.TCP{
			SrcPort: 0,
			DstPort: 0,
		}
		if filter.Transport.TCP.SrcPort != 0 {
			tcpLayer.SrcPort = layers.TCPPort(filter.Transport.TCP.SrcPort)
		}
		if filter.Transport.TCP.DstPort != 0 {
			tcpLayer.DstPort = layers.TCPPort(filter.Transport.TCP.DstPort)
		}
		return tcpLayer
	}
	if filter.Transport.UDP != nil {
		udpLayer := &layers.UDP{
			SrcPort: 0,
			DstPort: 0,
		}
		if filter.Transport.UDP.SrcPort != 0 {
			udpLayer.SrcPort = layers.UDPPort(filter.Transport.UDP.SrcPort)
		}
		if filter.Transport.UDP.DstPort != 0 {
			udpLayer.DstPort = layers.UDPPort(filter.Transport.UDP.DstPort)
		}
		return udpLayer
	}
	return nil
}
