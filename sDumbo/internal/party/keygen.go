package party

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
)

//SigKeyGen return pk and sks, n is the number of parties, t is the threshold of combining signature
func SigKeyGen(n uint32, t uint32) ([]*share.PriShare, *share.PubPoly) {
	suit := pairing.NewSuiteBn256()
	random := suit.RandomStream()

	x := suit.G1().Scalar().Pick(random)

	// pripoly
	pripoly := share.NewPriPoly(suit.G2(), int(t), x, suit.RandomStream())
	// n points in poly
	npoints := pripoly.Shares(int(n))
	//pub poly
	pubpoly := pripoly.Commit(suit.G2().Point().Base())
	return npoints, pubpoly
}

//EncKeyGen return tpkes
func EncKeyGen(n uint32, t uint32) (kyber.Point, []*share.PubShare, []*share.PriShare) {
	suite := pairing.NewSuiteBn256()
	random := suite.RandomStream()

	x := suite.G2().Scalar().Pick(random)

	pripoly := share.NewPriPoly(suite.G2(), int(t), x, suite.RandomStream())
	sks := pripoly.Shares(int(n))

	pubpoly := pripoly.Commit(suite.G2().Point().Base())
	vk := pubpoly.Shares(int(n))

	pk := suite.G2().Point().Mul(x, suite.G2().Point().Base())

	return pk, vk, sks
}
