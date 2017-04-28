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

/* firewall config parser */
package config

import "github.com/lytics/confl"

type Flags struct {
	/* TCP flags */
	FIN string `json:"fin"`
	SYN string `json:"syn"`
	RST string `json:"rst"`
	PSH string `json:"psh"`
	ACK string `json:"ack"`
	URG string `json:"urg"`
	ECE string `json:"ece"`
	CWR string `json:"cwr"`
	NS string `json:"ns"`
}
type Pair struct {
	From string `json:"from"`
	To string   `json:"to"`
}
type Filter struct {
	IP Pair `json:"ip"`
	Port Pair `json:"port"`
	Type string `json:"type"`
	Action string `json:"action"`
	Flags Flags `json:"flags"`
}

type Filters map[string][]Filter

type IPSets map[string][]string
type PortSets map[string][]string

type GeneralConfig struct{
	IPSets   IPSets   `json:"ipset"`
	PortSets PortSets `json:"portset"`
	Filters  Filters  `json:"filter"`
}

func LoadFilters(data []byte) (f Filters,e error) {
	e = confl.Unmarshal(data,&f)
	return
}
func Load(data []byte) (f GeneralConfig,e error) {
	e = confl.Unmarshal(data,&f)
	return
}


