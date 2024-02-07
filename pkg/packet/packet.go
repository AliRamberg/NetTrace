package packet

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/AliRamberg/NetTrace/pkg/config"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/dns/dnsmessage"
)

type PortType uint16

const (
	PortTypeHTTP  PortType = 80
	PortTypeHTTPS PortType = 443
	PortTypeDNS   PortType = 53
	TimestampSize          = 8
)

var (
	srcIP, dstIP string = "", ""
)

type Packet struct {
	Timestamp    uint64
	parsedPacket gopacket.Packet
	config       *config.Config
}

func (p *Packet) ParsePacket(data []byte, baseLayer gopacket.Decoder, config *config.Config) {
	p.Timestamp = binary.BigEndian.Uint64(data[:TimestampSize])
	p.parsedPacket = gopacket.NewPacket(data[TimestampSize:], baseLayer, gopacket.Default)
	p.config = config
}

func (p *Packet) String() string {
	builder := strings.Builder{}
	for _, layer := range p.parsedPacket.Layers() {
		switch layer.LayerType() {
		case layers.LayerTypeEthernet:
			ethernetLayer := layer.(*layers.Ethernet)
			builder.WriteString(fmt.Sprintf("\nEth: %s --> %s", ethernetLayer.SrcMAC.String(), ethernetLayer.DstMAC.String()))
		case layers.LayerTypeIPv4:
			ipv4Layer := layer.(*layers.IPv4)
			srcIP = ipv4Layer.SrcIP.String()
			dstIP = ipv4Layer.DstIP.String()
		case layers.LayerTypeTCP:
			tcpLayer := layer.(*layers.TCP)
			builder.WriteString(fmt.Sprintf("\nTCP: %s:%d --> %s:%d",
				srcIP, tcpLayer.SrcPort, dstIP, tcpLayer.DstPort))
		case layers.LayerTypeUDP:
			udpLayer := layer.(*layers.UDP)
			builder.WriteString(fmt.Sprintf("\nUDP: %s:%d --> %s:%d",
				srcIP, udpLayer.SrcPort, dstIP, udpLayer.DstPort))
		case layers.LayerTypeICMPv4:
			icmpLayer := layer.(*layers.ICMPv4)
			builder.WriteString(fmt.Sprintf("\nICMP: Type: %s - %s --> %s", icmpLayer.TypeCode, srcIP, dstIP))
		}
	}

	if custom := p.parseCustomPayload(); custom != nil {
		builder.WriteString("\nCustom:\n")
		builder.Write(custom)
	} else if payload := p.parsePayload(); payload != "" {
		builder.WriteString("\nPayload:\n")
		builder.WriteString(payload)
	}

	return builder.String()
}

func (p *Packet) parsePayload() string {
	payload := p.parsedPacket.ApplicationLayer()
	transport := p.parsedPacket.TransportLayer()
	if payload == nil || transport == nil {
		return ""
	}

	switch transport.LayerType() {
	case layers.LayerTypeUDP:
		udp, err := p.handleUDP(payload)
		if err != nil {
			return fmt.Sprintf("Error parsing UDP payload: %s", err)
		}
		return udp
	case layers.LayerTypeTCP:
		tcp, err := p.handleTCP(payload)
		if err != nil {
			return fmt.Sprintf("Error parsing TCP payload: %s", err)
		}
		return tcp
	}
	return string(payload.Payload())
}

func (p *Packet) handleTCP(payload gopacket.ApplicationLayer) (string, error) {
	transportLayer := p.parsedPacket.TransportLayer().(*layers.TCP)

	switch transportLayer.SrcPort {
	case layers.TCPPort(PortTypeHTTPS):
	case layers.TCPPort(PortTypeHTTP):
		res, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(payload.Payload())), nil)
		if err != nil {
			return "", err
		}

		out := fmt.Sprintf("%d, %s", res.StatusCode, res.Proto)
		if res.TLS != nil {
			return fmt.Sprintf("HTTPS Response: %s %d", out, res.TLS.Version), nil
		}
		return fmt.Sprintf("HTTP Response: %s", out), nil
	}

	switch transportLayer.DstPort {
	case layers.TCPPort(PortTypeHTTPS):
	case layers.TCPPort(PortTypeHTTP):
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload.Payload())))
		if err != nil {
			fmt.Printf("'%s'", payload.Payload())
			return "", err
		}
		out := fmt.Sprintf("%s, %s, %+v", req.Proto, req.Method, req.Header)
		if req.TLS != nil {
			return fmt.Sprintf("HTTPS Request: %s %d", out, req.TLS.Version), nil
		}
		return fmt.Sprintf("HTTP Request: %s", out), nil
	}

	return "", nil
}

func (p *Packet) handleUDP(payload gopacket.ApplicationLayer) (string, error) {
	transportLayer := p.parsedPacket.TransportLayer().(*layers.UDP)

	switch transportLayer.SrcPort {
	case layers.UDPPort(PortTypeDNS):
		dns := dnsmessage.Parser{}
		msg, err := dns.Start(payload.Payload())
		if err != nil {
			return "", err
		}

		return fmt.Sprintf("DNS Response: %s", msg.GoString()), nil
	}

	switch transportLayer.DstPort {
	case layers.UDPPort(PortTypeDNS):
		dns := layers.DNS{}
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeDNS, &dns)
		decodedLayers := make([]gopacket.LayerType, 0, 1)
		parser.DecodeLayers(payload.Payload(), &decodedLayers)

		return fmt.Sprintf("DNS Request: %s %+v", dns.OpCode, dns), nil
	}

	return "", nil
}

func (p *Packet) parseCustomPayload() []byte {
	applicationLayer := p.parsedPacket.ApplicationLayer()
	if applicationLayer == nil {
		return nil
	}

	for _, filter := range p.config.Filters {
		if filter.Application.Prefix != nil {
			for _, prefix := range filter.Application.Prefix {

				if strings.HasPrefix(string(applicationLayer.Payload()), prefix) {
					return bytes.TrimSpace(applicationLayer.Payload())
				}
			}
		}

		if filter.Application.Regex != nil {
			for _, regex := range filter.Application.Regex {
				if regexp.MustCompile(regex).Match(applicationLayer.Payload()) {
					return bytes.TrimSpace(applicationLayer.Payload())
				}
			}
		}
	}
	return nil
}
