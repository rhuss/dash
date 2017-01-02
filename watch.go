package dash

import (
	"net"
	"time"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
	"bytes"
)

type ButtonEvent struct {
	MacAddress string
}

func WatchButton(iface *net.Interface, macAddress string) *chan ButtonEvent {
	// Start up a goroutine to read in packet data.
	var buttonEventChannel = make(chan ButtonEvent)

	go prepareWatch(iface, macAddress, buttonEventChannel)
	return &buttonEventChannel
}

func prepareWatch(iface *net.Interface, macAddress string, buttonEventChannel chan ButtonEvent) {
	var event = ButtonEvent{
		MacAddress: macAddress,
	}

	for {
		// Open up a pcap handle for packet reads/writes.
		pcapHandle, err := pcap.OpenLive(iface.Name, 65536, true, 200*time.Millisecond)
		if err != nil {
			panic(err)
		}
		watchForButton(pcapHandle, macAddress)
		buttonEventChannel <- event
		pcapHandle.Close()
	}
}

var lastPushed = time.Time{}

// watchForButton watches a handle for incoming ARP responses we might care about, and prints them.
//
// watchForButton loops until 'stop' is closed.
func watchForButton(handle *pcap.Handle, macAddress string) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation == layers.ARPRequest {
				//log.Printf("ARP request")
				//log.Printf("IP %v Dst %v Src %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.DstHwAddress), net.HardwareAddr(arp.SourceHwAddress))
				if addressEquals("00:00:00:00:00:00", arp.DstHwAddress) && addressEquals(macAddress, arp.SourceHwAddress) {
					//log.Print("--> Received ARP request")
					var now = time.Now()
					if now.Sub(lastPushed).Seconds() > 5 {
						lastPushed = now
						return
					}
				}
			}
		}
	}
}

func addressEquals(mac string, addr []byte) bool {
	macParsed, error := net.ParseMAC(mac)
	if error != nil {
		return false
	}
	return bytes.Equal(macParsed, addr)
}
