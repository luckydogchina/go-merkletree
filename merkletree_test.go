package chain

import (
	"testing"
	"math/rand"
	"bytes"
	"encoding/binary"
	"crypto/sha256"
	"github.com/cloudflare/cfssl/log"
)

//获取随机的left
func randmomByte() []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	for i := 0; i != 4;i++{
		binary.Write(bytesBuffer, binary.BigEndian, rand.Uint64());
	}
	return bytesBuffer.Bytes()
}

//sha256的hash函数
func sh256test(input ...[]byte) []byte {
	sh256 := sha256.New();
	for _, data := range input{
		sh256.Write(data);
	}
	return sh256.Sum(nil);
}

func testUnit(element int, branchPos uint32)  error{
	var leftlist [][]byte;

	//构造随机的left队列
	for i := 0;i< element; i++{
		r := randmomByte();
		log.Debugf("left %d  %x\n", i, r)
		leftlist = append(leftlist, r);
	}

	var branch[][]byte;

	//生成root hash， 获取存在性证明
	rootHash, err := MerkleTreeRootHash(leftlist, branchPos, &branch, sh256test);
	if err == nil{
		log.Infof("the merkle tree root hash : %x\n", rootHash);
	}else {
		log.Errorf("make the  merkle tree root Hash error: %s\n",err.Error());
		return  err;
	}

	//left节点校验
	isOk, err := CheckLeftWithPOE(rootHash, &ProofOfExistence{branch,branchPos}, leftlist[branchPos], sh256test);
	if(!isOk){
		log.Errorf("result of Checking the left : %s\n", err.Error());
		return  err;
	}

	log.Infof("Check POE SUCCESS!!!")
	return  nil;
}

func TestMerkleRootHash(t *testing.T) {
	//构造一个包含11元素的merkletree,获取9号元素的poe并校验;
	testUnit(11, uint32(9));
}

