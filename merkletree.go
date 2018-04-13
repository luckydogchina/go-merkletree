/*
	@author: wangzhipeng@whty.com.cn
	@date: 2018/01/30
	@function：实现Merkle tree的相关运算和生成 proof of existence;
*/

package chain

import (
	"fmt"
	)

//存在性证明
type ProofOfExistence struct {
	ReverseHash [][]byte;
	BranchPos 	uint32;
}


type MerkleHash func(input ...[]byte) []byte

/*
	根据叶子节点队列生成Merkle Tree Root Hash,实现方式参考了Bitcoin中的MerkleComputation函数,Merkle Tree的高度< 32,也就是说最多能容纳2^31个叶子节点;
参数：
	@leftlist : 叶子节点队列，里面包含的是hash值;
	@branchpos : 叶子节点的序号，如果想获取PoE需要传入，否则置为0;
	@pBranch ： 逆向hash队列，如果想获得PoE需传入，否则置为nil;
	@Hash ： 生成MerkleRootHash的hash算法;
返回值：
	merkle-tree roo thash 和 错误信息
*/
func MerkleTreeRootHash(leftlist [][]byte, branchpos uint32, pBranch *[][]byte, Hash MerkleHash)([]byte,error) {
	var h,root []byte;
	var inner [32][]byte;

	isMatched := false;
	count  := uint32(0);
	level  := uint32(0);
	matchlevel := uint32(0xFFFFFFFF);


	if(len(leftlist) == 0){
		return root, fmt.Errorf("the lable list cannot be empty!!!");
	}

	if(branchpos >= uint32(len(leftlist))){
		return root, fmt.Errorf("the pos is out of range");
	}

	for _, left := range leftlist{
		h = left[:];
		isMatched = (count==branchpos);
		count++;

		level =0;
		for ;(count & (1<<level)) == 0;{
			if(pBranch != nil){
				if(isMatched){
					*pBranch = append(*pBranch, inner[level]);
				}else if(matchlevel == level){
					*pBranch = append(*pBranch, h);
					isMatched = true;
				}
			}

			h = Hash(inner[level], h);
			level++;
		}

		inner[level] = h;
		if(isMatched){
			matchlevel = level;
		}
	}

	level  = 0;
	for ; (count&(1<<level)) == 0;{
		level++
	}


	h = inner[level][:];
	isMatched = (matchlevel == level);
	for ;count != (1 << level);{
		if(pBranch != nil && isMatched){
			*pBranch = append(*pBranch, h);
		}

		h = Hash(h, h);
		count += (1<<level);
		level++;

		for ;(count & (1<<level)) == 0;{
			if(pBranch != nil){
				if(isMatched){
					*pBranch = append(*pBranch, inner[level]);
				}else if(matchlevel == level) {
					*pBranch = append(*pBranch, h);
					isMatched = true;
				}
			}

			h = Hash(inner[level], h);
			level++;
		}
	}

	root = h[:];
	return root, nil
}

/*
验证存在性证明中的Reversehash是否合法
参数：
	@rootHash: merkle Tree的根hash值;
	@pfExistence： left存在性证明;
	@left: 叶子节点;
	@branchPos: 叶子节点序号;
	@Hash： 自定义hash函数，一定要与生成POE的hash函数一致
返回值：
	正确/失败 和 错误信息
*/
func CheckLeftWithPOE(rootHash []byte,  existence *ProofOfExistence, left []byte, Hash MerkleHash) (bool, error){
	if(existence == nil){
		return false, fmt.Errorf("the proof of Existence is nil");
	}

	if(len(existence.ReverseHash)==0 ){
		return false, fmt.Errorf("the proof of Existenc is empty");
	}

	if(len(existence.ReverseHash) >= 32){
		return false, fmt.Errorf("the tree heigth is over range");
	}

	if(existence.BranchPos > uint32(2<< uint8(len(existence.ReverseHash)))){
		return false, fmt.Errorf("the Branpos %d is over range !!!", existence.BranchPos)
	}

	h := left;
	branchPos := existence.BranchPos;

	for _, reverseHash := range (existence.ReverseHash){
		if(branchPos%2 == 1 ){
			h = Hash(reverseHash, h);
		}else {
			h = Hash(h, reverseHash);
		}

		branchPos/=2;
	}

	for i :=0; i < 32 ; i++ {
		if(h[i] != rootHash[i]){
			return false, fmt.Errorf("the proof of Existence is wrong!");
		}
	}

	return true, nil;
}