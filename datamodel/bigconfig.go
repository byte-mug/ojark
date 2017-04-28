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

import "net"
import "encoding/binary"
import "fmt"
import "github.com/byte-mug/ojark/config"

type any struct{}
func (a any) MatchIP(ip net.IP) bool { return true }
func (a any) MatchPort(p int) bool { return true }
func (a any) String() string { return "ANY" }

type config_holder struct{
	ip map[string]*ipSet
	port map[string]*portSet
	action map[string] Action
}
func (c *config_holder) Init() {
	c.ip = make(map[string]*ipSet)
	c.port = make(map[string]*portSet)
	c.action = make(map[string] Action)
}
func (c *config_holder) ParseIP(s string) IP {
	if s=="" { return any{} }
	r,ok := c.ip[s]
	if !ok {
		r = parseIP(s)
		c.ip[s] = r
	}
	return r
}
func (c *config_holder) DefineIP(n string, sl []string) {
	ips := new(ipSet)
	osl := make([]string,0,len(sl))
	for _,s := range sl {
		r,ok := c.ip[s]
		if ok {
			ips.v4 = append(ips.v4,r.v4...)
			ips.v6 = append(ips.v6,r.v6...)
		}else{
			osl = append(osl,s)
		}
	}
	if len(osl)!=0 {
		r := parseIP(osl...)
		ips.v4 = append(ips.v4,r.v4...)
		ips.v6 = append(ips.v6,r.v6...)
	}
	ips.v4 = ips.v4.clean().strip()
	ips.v6 = ips.v6.clean().strip()
	c.ip[n] = ips
}
func (c *config_holder) ParsePort(s string) Port {
	if s=="" { return any{} }
	r,ok := c.port[s]
	if !ok {
		r = parsePort(s)
		c.port[s] = r
	}
	return r
}
func (c *config_holder) DefinePort(n string, sl []string) {
	ps := new(portSet)
	osl := make([]string,0,len(sl))
	for _,s := range sl {
		r,ok := c.port[s]
		if ok {
			ps.ips = append(ps.ips,r.ips...)
		}else{
			osl = append(osl,s)
		}
	}
	if len(osl)!=0 {
		r := parsePort(osl...)
		ps.ips = append(ps.ips,r.ips...)
	}
	ps.ips = ps.ips.clean().strip()
	c.port[n] = ps
}
func (c *config_holder) ParseAction(s string) Action {
	r,ok := c.action[s]
	if !ok {
		r = parseAction(s)
		c.action[s] = r
	}
	return r
}
func (c *config_holder) DefineAction(n string, a Action) {
	c.action[n] = a
}

type Parser struct{
	ch config_holder
}
func (p *Parser) Init() {
	p.ch.Init()
}
func (p *Parser) DefineAction(n string, a Action){ p.ch.DefineAction(n,a) }
func (p *Parser) AddIPs(s config.IPSets) {
	for k,v := range s { p.ch.DefineIP(k,v) }
}
func (p *Parser) AddPorts(s config.PortSets) {
	for k,v := range s { p.ch.DefinePort(k,v) }
}
func (p *Parser) CompileRules(f config.Filters) FilterSet {
	s := make(FilterSet)
	for k,v := range f {
		d := make([]*FilterRule,len(v))
		for i,e := range v { d[i] = importFilter(&p.ch,e) }
		s[k] = d
	}
	return s
}
func (p *Parser) Compile(c config.GeneralConfig) FilterSet {
	p.AddIPs(c.IPSets)
	p.AddPorts(c.PortSets)
	return p.CompileRules(c.Filters)
}

type actionPass uint8

const (
	a_pass = actionPass(iota)
	a_block
)
func (a actionPass) Pass() bool{ return a==a_pass }
func (a actionPass) React(i interface{}) bool { return false }
func (a actionPass) String() string {
	switch a{
	case a_pass: return "pass"
	case a_block: return "block"
	}
	return ""
}

func parseAction(s string) Action {
	switch s{
	case "pass": return a_pass
	case "block": return a_block
	}
	panic("unknown action "+s)
}

type ipSet struct{
	v4 i32set
	v6 i128set
}
func (i *ipSet) MatchIP(ip net.IP) bool {
	if i4 := ip.To4(); len(i4)!=0 {
		v := binary.BigEndian.Uint32([]byte(i4))
		return i.v4.find(v)
	}else if i6 := ip.To16(); len(i6)!=0 {
		vh := binary.BigEndian.Uint64([]byte(i6))
		vl := binary.BigEndian.Uint64([]byte(i6)[8:])
		return i.v6.find(vh,vl)
	}
	return false
}

func parseIP(s ...string) *ipSet {
	ips := new(ipSet)
	for _,se := range s {
		_,ran,e := net.ParseCIDR(se)
		ip := net.ParseIP(se)
		if e==nil {
			if i4 := ran.IP.To4(); len(i4)!=0 {
				ips.v4 = append(ips.v4,loadNet4(i4,ran.Mask))
			}else{
				i6 := ran.IP.To16()
				ips.v6 = append(ips.v6,loadNet16(i6,ran.Mask))
			}
		}else if i4 := ip.To4(); len(i4)!=0 {
			v := binary.BigEndian.Uint32([]byte(i4))
			ips.v4 = append(ips.v4,i32pair{v,v})
		}else if i6 := ip.To16(); len(i6)!=0 {
			vh := binary.BigEndian.Uint64([]byte(i6))
			vl := binary.BigEndian.Uint64([]byte(i6)[8:])
			ips.v6 = append(ips.v6,i128pair{vh,vl,vh,vl})
		}else { panic("Invalid IP address: '"+se+"'") }
	}
	ips.v4 = ips.v4.clean()
	ips.v6 = ips.v6.clean()
	return ips
}

func loadNet4(i4 net.IP,m net.IPMask) (r i32pair){
	if len(m)==16 {
		m = m[12:]
	}
	mask := binary.BigEndian.Uint32([]byte(m))
	r.b = binary.BigEndian.Uint32([]byte(i4))&mask
	r.e = r.b|^mask
	return
}

func loadNet16(i6 net.IP,m net.IPMask) (r i128pair){
	mh := binary.BigEndian.Uint64([]byte(m))
	ml := binary.BigEndian.Uint64([]byte(m)[8:])
	r.bh = binary.BigEndian.Uint64([]byte(i6))&mh
	r.bl = binary.BigEndian.Uint64([]byte(i6)[8:])&ml
	r.eh = r.bh|^mh
	r.el = r.bl|^ml
	return
}

type portSet struct {
	ips i32set
}
func (ps *portSet) MatchPort(p int) bool {
	return ps.ips.find(uint32(p))
}

func parsePort(s ...string) *portSet {
	var b,e uint32
	var svc,tp string
	ps := new(portSet)
	for _,se := range s {
		i,_ := fmt.Sscanf(se,"%d-%d",&b,&e)
		switch i {
		case 0:
			j,_ := fmt.Sscanf(se,"%s/%s",&svc,&tp)
			if j<2 { tp = "tcp" }
			pn,err := net.LookupPort(tp, svc)
			if err!=nil { panic("Invalid port: "+se) }
			b = uint32(pn)
			fallthrough
		case 1:
			e = b
			fallthrough
		case 2:
			ps.ips = append(ps.ips,i32pair{b,e})
		}
	}
	ps.ips = ps.ips.clean()
	return ps
}

