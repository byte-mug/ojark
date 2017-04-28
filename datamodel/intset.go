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

import "sort"

type i32pair struct{
	b,e uint32
}
func (p *i32pair) join(o i32pair) bool {
	e := p.e
	e++
	if e==0 { return true } /* Overflow: No one behind! */
	
	if e < o.b { return false }
	if p.e < o.e { p.e = o.e }
	return true
}

type i32set []i32pair
func (a i32set) Len() int { return len(a) }
func (a i32set) Less(i, j int) bool { return a[i].b < a[j].b }
func (a i32set) Swap(i, j int) { a[i],a[j] = a[j],a[i] }
func (a i32set) find(p uint32) bool {
	i := sort.Search(
		len(a),
	func(i int) bool {
		return a[i].b > p
	})
	if i<0 || i>=len(a) { return false }
	return (a[i].b >= p) && (a[i].e <= p)
}
func (a i32set) clean() i32set {
	if len(a)==0 { return a }
	var p i32pair
	b := make(i32set,0,len(a))
	sort.Sort(a)
	p = a[0]
	for _,e := range a[1:] {
		/* If the p and e overlap, join them! */
		if p.join(e) { continue }
		b = append(b,p)
		p = e
	}
	b = append(b,p)
	return b
}
func (a i32set) merge(i i32set) i32set {
	return append(append(make(i32set,0,len(a)+len(i)),a...),i...).clean()
}
func (a i32set) strip() i32set {
	b := make(i32set,len(a))
	copy(b,a)
	return b
}


type i128pair struct {
	bh,bl,eh,el uint64
}
func (p *i128pair) join(o i128pair) bool {
	eh := p.eh
	el := p.el
	el++
	if el==0 { eh++ }
	if eh==0 { return true } /* Overflow: No one behind! */
	
	if (eh < o.bh) || ( (eh == o.bh) && (el < o.bl) ) { return false }
	if p.eh < o.eh {
		p.eh = o.eh
		p.el = o.el
	} else if (p.eh == o.eh) && (p.el < o.el) {
		p.el = o.el
	}
	return true
}

type i128set []i128pair
func (a i128set) Len() int { return len(a) }
func (a i128set) Less(i, j int) bool {
	if a[i].bh == a[j].bh {
		return a[i].bl < a[j].bl
	}
	return a[i].bh < a[j].bh
}
func (a i128set) Swap(i, j int) { a[i],a[j] = a[j],a[i] }
func (a i128set) find(ph, pl uint64) bool {
	i := sort.Search(
		len(a),
	func(i int) bool {
		if a[i].bh == ph { return a[i].bl > pl }
		return a[i].bh > ph
	})-1
	if i<0 || i>=len(a) { return false }
	if a[i].bh==ph {
		return (a[i].bl >= pl) && (a[i].el <= pl)
	}
	return (a[i].bh >= ph) && (a[i].eh <= ph)
}
func (a i128set) clean() i128set {
	if len(a)==0 { return a }
	var p i128pair
	b := make(i128set,0,len(a))
	sort.Sort(a)
	p = a[0]
	for _,e := range a[1:] {
		/* If the p and e overlap, join them! */
		if p.join(e) { continue }
		b = append(b,p)
		p = e
	}
	b = append(b,p)
	return b
}
func (a i128set) merge(i i128set) i128set {
	return append(append(make(i128set,0,len(a)+len(i)),a...),i...).clean()
}
func (a i128set) strip() i128set {
	b := make(i128set,len(a))
	copy(b,a)
	return b
}

