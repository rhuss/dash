## Go library for tracking Amazon Dash buttons

This simple library sniffs on the network for ARP packets sent by a [Amazon Dash](https://www.amazon.com/dp/B01LBT75HE) button.

Usage:

```golang

import "github.com/rhuss/dash"

iface, err := net.InterfaceByName("eth0")
if err != nil {
  panic(err)
}

eventChannel := dash.WatchButton(iface, "ac:63:11:22:33:44")
  for {
	select {
	case <- *eventChannel:
		log.Print("Button pressed !")
	}
}
```

You should ensure that you add an outbound firewall rule to forbid the button to contact Amazon, otherwise you might end up to eat your dog's food delivered by Amazon yourself ;-)

The single dependency for this package is on [google/gopacket](https://godoc.org/github.com/google/gopacket) which is a wrapper around [pcap](https://en.wikipedia.org/wiki/Pcap). So cross compiling might become difficult, although this library is perfectly suited to be used as part of an home automation system e.g. by running it on a RaspberryPi.
