package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/hashicorp/vault/shamir"
	"math/big"
	"strconv"
	"time"
	"zk_eq_blockchain/pkg"
)

func main() {
	Test1()
}

// 一个区块10笔交易，打印区块算法信息
// 一个区块20笔交易，打印区块算法信息
// 一个区块30笔交易，打印区块算法信息
func Test1() {
	beginTime := time.Now()
	// secrets为三个秘密的整数表示。
	rand.Reader = pkg.MyPolyReader{}
	//a_secret := "abcde"
	//b_secret := "2222"
	//c_secret := "3333"
	//
	//secrets := []string{a_secret, b_secret, c_secret}

	var secrets []string
	//随机生成秘密
	peersCount := 10
	for i := 0; i < peersCount; i++ {
		secrets = append(secrets, "secret"+strconv.Itoa(i))
	}

	secretShares := make([][][]byte, len(secrets))

	// 将每个秘密分割成shares
	for i, secret := range secrets {
		secmid := hex.EncodeToString([]byte(secret))
		n := new(big.Int)
		secretInt, _ := n.SetString(secmid, 16)
		secret = secretInt.String()

		secretNumber, ok := new(big.Int).SetString(secret, 10)
		if !ok {
			panic("无法将秘密转换为数字")
		}
		// 分散秘钥：3个shares，2个就可以恢复
		shares, err := shamir.Split(secretNumber.Bytes(), len(secrets), len(secrets)-1)
		if err != nil {
			panic(err)
		}
		secretShares[i] = shares
	}

	// 假定现在我们拥有所有的shares
	sum := big.NewInt(0)

	totalSecret := make([]*big.Int, len(secrets))

	for i := 0; i < len(secrets); i++ {
		totalSecret[i] = big.NewInt(0)
		for _, shares := range secretShares {
			a := big.NewInt(0)
			a = a.SetBytes(shares[i])
			totalSecret[i] = totalSecret[i].Add(totalSecret[i], a)
		}
	}

	var totalSecretBytes [][]byte
	bLen := len(totalSecret[0].Bytes())
	sameTest := make(map[byte]struct{}, 0)
	for i := 0; i < (len(secrets) - 1); i++ {
		b := totalSecret[i].Bytes()
		_, ok := sameTest[b[bLen-1]]
		if ok {
			continue
		}
		totalSecretBytes = append(totalSecretBytes, totalSecret[i].Bytes())
		sameTest[b[bLen-1]] = struct{}{}
	}

	secret, err := shamir.Combine(totalSecretBytes)
	if err != nil {
		panic(err)
	}
	sum = sum.SetBytes(secret)

	//减去系数
	for i := 0; i < len(secrets); i++ {
		sum = sum.Sub(sum, big.NewInt(int64(1+i)))
	}

	keyTime := time.Now().Sub(beginTime).Microseconds()

	fmt.Printf("生成随机数的时间为：%d(us)", keyTime)

	// 测试区块内笔数
	//txsCount := []uint{1000, 1200, 1400, 1600, 1800, 2000, 2200, 2400, 2600, 2800, 3000}
	//txsCount := []uint{10, 12, 14, 16} //每个区块里包含多少交易
	txsCount := []uint{50}
	txSize := []uint{10000000} //报文的大小

	for i := 0; i < len(txSize); i++ {
		size := txSize[i]
		var txBody string
		for i := 0; i < int(size); i++ {
			txBody += "1"
		}

		for i := 0; i < len(txsCount); i++ {
			var proofs [][]byte
			var vks [][]byte

			beginTime := time.Now()
			txs := txsCount[i]
			for j := 0; j < int(txs); j++ {
				proof, vk := pkg.GenerateProve(txBody, sum.Bytes())
				proofs = append(proofs, proof)
				vks = append(vks, vk)
			}
			//获取占用的毫秒数
			proofTime := time.Now().Sub(beginTime).Milliseconds()

			bt1 := time.Now()
			proofLen := 0

			for j := 0; j < int(txs); j++ {
				h := sha256.New()
				h.Write([]byte(txBody))
				r := h.Sum(nil)
				source := hex.EncodeToString(r)
				n := new(big.Int)
				n, ok := n.SetString(source, 16)
				if !ok {
					panic("xxx")
				}
				source = n.String()

				_, err := pkg.VerifyProof(pkg.HashCalc(source), vks[j], proofs[j])
				if err != nil {
					panic(err)
				}
				proofLen += len(proofs[j])
			}

			verifyTime := time.Now().Sub(bt1).Milliseconds()
			fmt.Printf("一个区块内的交易数：%d(笔), 交易大小：%d(Byte),证明总大小：%d (Byte), 生成证明的时间为: %d ms, 验证时间为：%d\n",
				txs, size, proofLen, proofTime, verifyTime)
		}
	}
}
