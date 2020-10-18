package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/hima398/pairing-based-crypto/pairing/paillier"
)

type Candidate struct {
	Index *big.Int
	Name  string
}

var vArg = flag.Int("voters", 10, "Number of Voters.")

var cArg = flag.String("candidates", "Alice,Bob", "Candidates(Comma separated).")

func BuildCandidates(r int, names []string) []Candidate {
	var candidates []Candidate
	for i, name := range names {
		c := Candidate{}
		c.Index = new(big.Int).Exp(big.NewInt(int64(r)), big.NewInt(int64(i)), nil)
		c.Name = name
		candidates = append(candidates, c)
	}
	return candidates
}

func Select(c []Candidate, pub *paillier.PublicKey) *big.Int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(c))))
	if err != nil {
		panic(err)
	}
	return paillier.Encrypt(c[n.Int64()].Index, pub)
}

func Count(votes []big.Int, priv *paillier.PrivateKey) {
	n2 := new(big.Int).Mul(priv.PublicKey.N, priv.PublicKey.N)

	t := big.NewInt(1)
	for _, v := range votes {
		t = new(big.Int).Mod(new(big.Int).Mul(t, &v), n2)
	}
	result := priv.Decrypt(t)

	fmt.Println(result)
}

func main() {
	flag.Parse()
	fmt.Printf("%d, %s\n", *vArg, *cArg)
	// 基数
	voters := *vArg
	names := strings.Split(*cArg, ",")

	// 基数は投票者+1
	candidates := BuildCandidates(voters+1, names)
	priv, err := paillier.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	var votes []big.Int
	for i := 0; i < voters; i++ {
		c := Select(candidates, &priv.PublicKey)
		votes = append(votes, *c)
	}

	Count(votes, priv)
}
