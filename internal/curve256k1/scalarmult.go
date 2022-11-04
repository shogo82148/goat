package curve256k1

func (p *PointJacobian) ScalarMult(q *PointJacobian, k []byte) *PointJacobian {
	var zero PointJacobian
	zero.Zero()
	p.Zero()
	for i := 0; i < len(k); i++ {
		b := int(k[i])
		for j := 7; j >= 0; j-- {
			var tmp PointJacobian
			p.Double(p)
			tmp.Select(q, &zero, (b>>j)&1)
			p.Add(p, &tmp)
		}
	}
	return p
}
