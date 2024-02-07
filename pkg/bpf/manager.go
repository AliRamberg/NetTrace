package bpf

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/AliRamberg/NetTrace/pkg/config"
	"github.com/AliRamberg/NetTrace/pkg/logger"
	"github.com/AliRamberg/NetTrace/pkg/packet"
	"github.com/AliRamberg/NetTrace/pkg/query"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

type TrafficControlManager struct {
	objs           *tcObjects
	programs       *tcPrograms
	maps           *tcMaps
	ingressFilters []*netlink.BpfFilter
	egressFilters  []*netlink.BpfFilter
	qdiscs         []*netlink.GenericQdisc
	config         *config.Config
	log            *zap.SugaredLogger
}

func NewTrafficControlManager(config *config.Config) *TrafficControlManager {

	objs := tcObjects{}
	if err := loadTcObjects(&objs, nil); err != nil {
		log.Errorf("loading objects: %w", err)
		return nil
	}

	return &TrafficControlManager{
		objs:     &objs,
		programs: &objs.tcPrograms,
		maps:     &objs.tcMaps,
		log:      logger.Get(),
		config:   config,
	}
}

func (b *TrafficControlManager) Close() {
	b.log.Info("Shutting down BPF program")
	b.Unload()
	b.objs.Close()
}

func (b *TrafficControlManager) Load(eth string) error {
	b.log.With("interface", eth).Info("loading tc program")
	networkInterface, err := netlink.LinkByName(eth)
	if err != nil {
		b.log.Errorf("cannot find %s: %s", eth, err)
		return err
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: networkInterface.Attrs().Index,
			Parent:    netlink.HANDLE_CLSACT,
			Handle:    netlink.MakeHandle(0xffff, 0),
		},
		QdiscType: "clsact",
	}
	b.qdiscs = append(b.qdiscs, qdisc)

	if err := netlink.QdiscAdd(qdisc); err != nil {
		b.log.Errorf("cannot add clsact qdisc: %s", err)
		return err
	}

	ingressAttrs := netlink.FilterAttrs{
		LinkIndex: networkInterface.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	egressAttrs := netlink.FilterAttrs{
		LinkIndex: networkInterface.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	fd := b.programs.TrafficTracer.FD()

	ingressFilter := &netlink.BpfFilter{
		FilterAttrs:  ingressAttrs,
		Fd:           fd,
		Name:         "ingress_bpf",
		DirectAction: true,
	}
	b.ingressFilters = append(b.ingressFilters, ingressFilter)

	egressFilter := &netlink.BpfFilter{
		FilterAttrs:  egressAttrs,
		Fd:           fd,
		Name:         "egress_bpf",
		DirectAction: true,
	}
	b.egressFilters = append(b.egressFilters, egressFilter)

	if err := netlink.FilterAdd(ingressFilter); err != nil {
		b.log.Warnf("cannot attach bpf object to filter: %s", err)
		return err
	}
	if err := netlink.FilterAdd(egressFilter); err != nil {
		b.log.Warnf("cannot attach bpf object to filter: %s", err)
		return err
	}

	return nil
}

func (b *TrafficControlManager) Unload() {
	b.log.Infof("unloading tc program %s", b.objs.TrafficTracer.String())
	for _, filter := range b.ingressFilters {
		// `tc filter del dev eth0 ingress`
		if err := netlink.FilterDel(filter); err != nil {
			b.log.Warnf("cannot detach bpf object from filter: %w", err)
		}
	}

	for _, filter := range b.egressFilters {
		// `tc filter del dev eth0 ingress`
		if err := netlink.FilterDel(filter); err != nil {
			b.log.Warnf("cannot detach bpf object from filter: %w", err)
		}
	}

	for _, qdisc := range b.qdiscs {
		// `tc qdisc del dev eth0 clsact`
		if err := netlink.QdiscDel(qdisc); err != nil {
			b.log.Warnf("cannot delete clsact qdisc: %w", err)
		}
	}
}

func (b *TrafficControlManager) AddQuery(query *query.Query) error {
	if query == nil || query.Size == 0 {
		log.Warn("query has no layers")
		return nil
	}

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: false,
	}, query.Layers...)

	var key uint32 = 0

	if err := b.maps.Queries.Update(&key, buf.Bytes()[:query.Size], ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update BPF map: %w", err)
	}

	if err := b.verifyQuery(query, buf); err != nil {
		return fmt.Errorf("failed to verify query: %w", err)
	}

	return nil
}

func (b *TrafficControlManager) ReadLoop() {
	rd, err := ringbuf.NewReader(b.maps.Events)
	if err != nil {
		b.log.Errorf("creating ringbuf reader: %w", err)
		return
	}
	defer rd.Close()

	packet := packet.Packet{}
	record := ringbuf.Record{}

	for {
		if err := rd.ReadInto(&record); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			b.log.Infof("error reading ringbuf record: %w", err)
		}

		packet.ParsePacket(record.RawSample, layers.LayerTypeEthernet, b.config)
		fmt.Println(packet.String())
	}
}

func (b *TrafficControlManager) verifyQuery(q *query.Query, buf gopacket.SerializeBuffer) error {
	b.log.Debug("verifying query")
	b.log.Debugf("Written bytes: %v", buf.Bytes()[:q.Size])

	key := uint32(0)
	value, err := b.maps.Queries.LookupBytes(&key)
	if err != nil {
		return fmt.Errorf("failed to lookup value in BPF map: %w", err)
	}

	b.log.Debugf("Read bytes: %v ", value)

	if !bytes.Equal(buf.Bytes()[:q.Size], value) {
		b.log.Errorf("failed to verify query")
		return fmt.Errorf("failed to verify query")
	}

	return nil
}
