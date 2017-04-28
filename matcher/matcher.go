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


package matcher

import "github.com/google/gopacket"
import "github.com/google/gopacket/layers"
import "github.com/byte-mug/ojark/datamodel"

type Matcher struct {
	eth layers.Ethernet
	arp layers.ARP
	ip4 layers.IPv4
	ip6 layers.IPv6
	es6 layers.IPv6ExtensionSkipper
	tcp layers.TCP
	udp layers.UDP
	sctp layers.SCTP
	parser *gopacket.DecodingLayerParser
	data []gopacket.LayerType
}
func (m *Matcher) Init(){
	m.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &m.eth, &m.arp, &m.ip4, &m.ip6, &m.es6, &m.tcp, &m.udp)
}
func (m *Matcher) match(f *datamodel.FilterRule) bool{
	r := false
	for _,l := range m.data { if f.HasType.Contains(l) { r = true; break } }
	if !r { return false }
	
	for _,l := range m.data {
		switch l {
		case layers.LayerTypeIPv4:
			if !f.SrcIP.MatchIP(m.ip4.SrcIP) { return false }
			if !f.DstIP.MatchIP(m.ip4.DstIP) { return false }
		case layers.LayerTypeIPv6:
			if !f.SrcIP.MatchIP(m.ip6.SrcIP) { return false }
			if !f.DstIP.MatchIP(m.ip6.DstIP) { return false }
		case layers.LayerTypeTCP:
			if !f.SrcPort.MatchPort(int(m.tcp.SrcPort)) { return false }
			if !f.DstPort.MatchPort(int(m.tcp.DstPort)) { return false }
			if !(
				f.TCP.FIN.Check(m.tcp.FIN) &&
				f.TCP.SYN.Check(m.tcp.SYN) &&
				f.TCP.RST.Check(m.tcp.RST) &&
				f.TCP.PSH.Check(m.tcp.PSH) &&
				f.TCP.ACK.Check(m.tcp.ACK) &&
				f.TCP.URG.Check(m.tcp.URG) &&
				f.TCP.ECE.Check(m.tcp.ECE) &&
				f.TCP.CWR.Check(m.tcp.CWR) &&
				f.TCP.NS.Check(m.tcp.NS) ) {
				return false
			}
		case layers.LayerTypeUDP:
			if !f.SrcPort.MatchPort(int(m.udp.SrcPort)) { return false }
			if !f.DstPort.MatchPort(int(m.udp.DstPort)) { return false }
		case layers.LayerTypeSCTP:
			if !f.SrcPort.MatchPort(int(m.sctp.SrcPort)) { return false }
			if !f.DstPort.MatchPort(int(m.sctp.DstPort)) { return false }
		}
	}
	return true
}
func (m *Matcher) Match(f []*datamodel.FilterRule) (a datamodel.Action) {
	for _,e := range f {
		if m.match(e) {
			a = e.Action
		}
	}
	return
}
func (m *Matcher) Parse(data []byte) error{
	m.parser.Truncated = false
	return m.parser.DecodeLayers(data,&m.data)
}


