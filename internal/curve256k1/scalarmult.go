package curve256k1

func (p *PointJacobian) ScalarMult(q *PointJacobian, k []byte) *PointJacobian {
	var table lookupTable
	table.Init(q)

	var tmp PointJacobian
	var v, zero PointJacobian
	zero.Zero()
	v.Zero()

	for _, b := range k {
		v.Double(&v)
		v.Double(&v)
		v.Double(&v)
		v.Double(&v)
		table.SelectInto(&tmp, b>>4)
		v.Add(&v, &tmp)

		v.Double(&v)
		v.Double(&v)
		v.Double(&v)
		v.Double(&v)
		table.SelectInto(&tmp, b&0xf)
		v.Add(&v, &tmp)
	}
	p.Set(&v)
	return p
}

func (p *PointJacobian) ScalarBaseMult(k []byte) *PointJacobian {
	var q PointJacobian
	q.FromAffine(new(Point).NewGenerator())

	var zero, v PointJacobian
	zero.Zero()
	v.Zero()
	for i := 0; i < len(k); i++ {
		b := int(k[i])
		for j := 7; j >= 0; j-- {
			var tmp PointJacobian
			v.Double(&v)
			tmp.Select(&q, &zero, (b>>j)&1)
			v.Add(&v, &tmp)
		}
	}
	p.Set(&v)
	return p

}
