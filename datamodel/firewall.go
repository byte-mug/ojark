/*
MIT License

Copyright (c) 2017 Simon Schmidt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


package datamodel

import "github.com/google/gopacket"
import "github.com/google/gopacket/layers"
import "github.com/byte-mug/ojark/config"
import "net"

type Action interface{
	Pass() bool
	React(i interface{}) bool
}

type Protoclass []gopacket.LayerType
func (p Protoclass) Contains(lt gopacket.LayerType) bool {
	for _,x := range p { if lt==x { return true } }
	return len(p)==0
}

var protocolType = map[string]Protoclass{
	"": Protoclass{},
	"tcp": Protoclass{layers.LayerTypeTCP},
	"udp": Protoclass{layers.LayerTypeUDP},
	"sctp": Protoclass{layers.LayerTypeSCTP},
	"icmp4": Protoclass{layers.LayerTypeICMPv4},
	"icmp6": Protoclass{layers.LayerTypeICMPv6},
	"icmp": Protoclass{layers.LayerTypeICMPv4,layers.LayerTypeICMPv6},
	"ip": Protoclass{layers.LayerTypeIPv4,layers.LayerTypeIPv6},
	"ip4": Protoclass{layers.LayerTypeIPv4},
	"ip6": Protoclass{layers.LayerTypeIPv6},
	"arp": Protoclass{layers.LayerTypeARP},
}

type Boolcomp uint8

const (
	B_ANY = Boolcomp(iota)
	B_TRUE
	B_FALSE
	b_invalid
)
func (c Boolcomp) String() string {
	switch c{
	case B_ANY: return "*"
	case B_TRUE: return "1"
	case B_FALSE: return "0"
	}
	return "?"
}
func (c Boolcomp) Check(b bool) bool {
	switch c{
	case B_ANY: return true
	case B_TRUE: return b
	case B_FALSE: return !b
	}
	return false
}
func (c *Boolcomp) Parse(s string) {
	*c=b_invalid
	switch s{
	case "0","f","F": *c=B_TRUE
	case "1","t","T": *c=B_FALSE
	case "","*": *c=B_ANY
	}
}

type IP interface{
	MatchIP(ip net.IP) bool
}

type Port interface{
	MatchPort(p int) bool
}

type FilterRule struct {
	SrcIP, DstIP IP
	SrcPort, DstPort Port
	TCP struct{
		FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS Boolcomp
	}
	HasType Protoclass
	Action Action
}

type FilterSet map[string][]*FilterRule

func importFilter(p parser,f config.Filter) (fr *FilterRule) {
	fr = &FilterRule{
		SrcIP: p.ParseIP(f.IP.From),
		DstIP: p.ParseIP(f.IP.To),
		SrcPort: p.ParsePort(f.Port.From),
		DstPort: p.ParsePort(f.Port.To),
	}
	fr.TCP.FIN.Parse(f.Flags.FIN)
	fr.TCP.SYN.Parse(f.Flags.SYN)
	fr.TCP.RST.Parse(f.Flags.RST)
	fr.TCP.PSH.Parse(f.Flags.PSH)
	fr.TCP.ACK.Parse(f.Flags.ACK)
	fr.TCP.URG.Parse(f.Flags.URG)
	fr.TCP.ECE.Parse(f.Flags.ECE)
	fr.TCP.CWR.Parse(f.Flags.CWR)
	fr.TCP.NS.Parse(f.Flags.NS)
	fr.HasType,_ = protocolType[f.Type]
	fr.Action = p.ParseAction(f.Action)
	return
}

type parser interface{
	ParseIP(s string) IP
	ParsePort(s string) Port
	ParseAction(s string) Action
}

