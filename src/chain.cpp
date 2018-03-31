// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"
#include "chainparams.h"
#include "validation.h"

/* Moved here from the header, because we need auxpow and the logic becomes more involved.  */
CBlockHeader CBlockIndex::GetBlockHeader(const Consensus::Params& consensusParams) const
{
    CBlockHeader block;
    block.nVersion       = nVersion;

    /* The CBlockIndex object's block header is missing the auxpow.
       So if this is an auxpow block, read it from disk instead.  We only have to read the actual *header*, not the full block.  */
    if (block.IsAuxpow())
    {
        ReadBlockHeaderFromDisk(block, this, consensusParams);
        return block;
    }

    if (pprev)
        block.hashPrevBlock = pprev->GetBlockHash();
    block.hashMerkleRoot = hashMerkleRoot;
    block.nTime          = nTime;
    block.nBits          = nBits;
    block.nNonce         = nNonce;
    return block;
}

/**
 * CChain implementation
 */
void CChain::SetTip(CBlockIndex *pindex) {
    if (pindex == nullptr) {
        vChain.clear();
        return;
    }
    vChain.resize(pindex->nHeight + 1);
    while (pindex && vChain[pindex->nHeight] != pindex) {
        vChain[pindex->nHeight] = pindex;
        pindex = pindex->pprev;
    }
}

CBlockLocator CChain::GetLocator(const CBlockIndex *pindex) const {
    int nStep = 1;
    std::vector<uint256> vHave;
    vHave.reserve(32);

    if (!pindex) pindex = Tip();
    while (pindex) {
        vHave.push_back(pindex->GetBlockHash());
        // Stop when we have added the genesis block.
        if (pindex->nHeight == 0) break;
        // Exponentially larger steps back, plus the genesis block.
        int nHeight = std::max(pindex->nHeight - nStep, 0);
        if (Contains(pindex)) {
            // Use O(1) CChain index if possible.
            pindex = (*this)[nHeight];
        } else {
            // Otherwise, use O(log n) skiplist.
            pindex = pindex->GetAncestor(nHeight);
        }
        if (vHave.size() > 10) nStep *= 2;
    }

    return CBlockLocator(vHave);
}

const CBlockIndex *CChain::FindFork(const CBlockIndex *pindex) const {
    if (pindex == nullptr) {
        return nullptr;
    }
    if (pindex->nHeight > Height()) pindex = pindex->GetAncestor(Height());
    while (pindex && !Contains(pindex))
        pindex = pindex->pprev;
    return pindex;
}

CBlockIndex *CChain::FindEarliestAtLeast(int64_t nTime) const {
    std::vector<CBlockIndex *>::const_iterator lower =
        std::lower_bound(vChain.begin(), vChain.end(), nTime,
                         [](CBlockIndex *pBlock, const int64_t &time) -> bool {
                             return pBlock->GetBlockTimeMax() < time;
                         });
    return (lower == vChain.end() ? nullptr : *lower);
}

/** Turn the lowest '1' bit in the binary representation of a number into a '0'.
 */
static inline int InvertLowestOne(int n) {
    return n & (n - 1);
}

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
static inline int GetSkipHeight(int height) {
    if (height < 2) return 0;

    // Determine which height to jump back to. Any number strictly lower than
    // height is acceptable, but the following expression seems to perform well
    // in simulations (max 110 steps to go back up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1
                        : InvertLowestOne(height);
}

CBlockIndex *CBlockIndex::GetAncestor(int height) {
    if (height > nHeight || height < 0) return nullptr;

    CBlockIndex *pindexWalk = this;
    int heightWalk = nHeight;
    while (heightWalk > height) {
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);
        if (pindexWalk->pskip != nullptr &&
            (heightSkip == height || (heightSkip > height &&
                                      !(heightSkipPrev < heightSkip - 2 &&
                                        heightSkipPrev >= height)))) {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        } else {
            assert(pindexWalk->pprev);
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }
    return pindexWalk;
}

const CBlockIndex *CBlockIndex::GetAncestor(int height) const {
    return const_cast<CBlockIndex *>(this)->GetAncestor(height);
}

void CBlockIndex::BuildSkip() {
    if (pprev) pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
}

arith_uint256 GetBlockProofBase(const CBlockIndex& block)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0) return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for a arith_uint256. However, as 2**256 is at least as
    // large as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) /
    // (bnTarget+1)) + 1, or ~bnTarget / (nTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

arith_uint256 GetPrevWorkForAlgo(const CBlockIndex& block, int algo)
{
    const CBlockIndex* pindex = &block;
    while (pindex != NULL)
    {
        if (pindex->GetAlgo() == algo)
        {
            return GetBlockProofBase(*pindex);
        }
        pindex = pindex->pprev;
    }
    return UintToArith256(Params().GetConsensus().powLimit[algo]);
}

arith_uint256 GetPrevWorkForAlgoWithDecayV1(const CBlockIndex& block, int algo)
{
    int nDistance = 0;
    const CBlockIndex* pindex = &block;
    pindex = pindex->pprev;
    arith_uint256 ret = UintToArith256(Params().GetConsensus().powLimit[algo]);
    while (pindex != NULL)
    {
        if (nDistance > 32)
        {
            return ret;
        }
        if (pindex->GetAlgo() == algo)
        {
            arith_uint256 nWork = GetBlockProofBase(*pindex);
            nWork *= (32 - nDistance);
            nWork /= 32;
            if (nWork < ret) nWork = ret;
            return nWork;
        }
        pindex = pindex->pprev;
        nDistance++;
    }
    return ret;
}
// same as V1 but default is 0
arith_uint256 GetPrevWorkForAlgoWithDecayV2(const CBlockIndex& block, int algo)
{
    int nDistance = 0;
    const CBlockIndex* pindex = &block;
    pindex = pindex->pprev;
    while (pindex != NULL)
    {
        if (nDistance > 32)
        {
            return arith_uint256(0);
        }
        if (pindex->GetAlgo() == algo)
        {
            arith_uint256 nWork = GetBlockProofBase(*pindex);
            nWork *= (32 - nDistance);
            nWork /= 32;
            return nWork;
        }
        pindex = pindex->pprev;
        nDistance++;
    }
    return arith_uint256(0);
}
// similar to V2 but using '100' instead of '32'
arith_uint256 GetPrevWorkForAlgoWithDecayV3(const CBlockIndex& block, int algo)
{
    int nDistance = 0;
    const CBlockIndex* pindex = &block;
    pindex = pindex->pprev;
    while (pindex != NULL)
    {
        if (nDistance > 100)
        {
            return arith_uint256(0);
        }
        if (pindex->GetAlgo() == algo)
        {
            arith_uint256 nWork = GetBlockProofBase(*pindex);
            nWork *= (100 - nDistance);
            nWork /= 100;
            return nWork;
        }
        pindex = pindex->pprev;
        nDistance++;
    }
    return arith_uint256(0);
}

arith_uint256 GetGeometricMeanPrevWork(const CBlockIndex& block)
{
    //arith_uint256 bnRes;
    arith_uint256 nBlockWork = GetBlockProofBase(block);
    uint256 bnBlockWork = ArithToUint256(nBlockWork);
    int nAlgo = block.GetAlgo();
    
    for (int algo = 0; algo < NUM_ALGOS; algo++)
    {
        if (algo != nAlgo)
        {
            arith_uint256 nBlockWorkAlt = GetPrevWorkForAlgoWithDecayV3(block, algo);
            uint256 bnBlockWorkAlt = ArithToUint256(nBlockWorkAlt);
            if (nBlockWorkAlt != 0)
                nBlockWork *= nBlockWorkAlt;
        }
    }
    // Compute the geometric mean
    /* XWARNING
    CBigNum bnRes = bnBlockWork.nthRoot(NUM_ALGOS);
    
    // Scale to roughly match the old work calculation
    bnRes <<= 8;
    
    //return bnRes;
    return UintToArith256(bnRes.getuint256());
     */
    return nBlockWork;
}

arith_uint256 GetBlockProof(const CBlockIndex& block)
{
    Consensus::Params params = Params().GetConsensus();

    arith_uint256 bnTarget;
    int nHeight = block.nHeight;
    int nAlgo = block.GetAlgo();

    if (nHeight > params.nGeometricAverageWork_Start)
    {
        bnTarget = GetGeometricMeanPrevWork(block);
    }
    else
    {
        arith_uint256 nBlockWork = GetBlockProofBase(block);
        for (int algo = 0; algo < NUM_ALGOS; algo++)
        {
            if (algo != nAlgo)
            {
                if(nHeight >= params.nBlockAlgoNormalisedWorkDecayV2Start)
                {
                    nBlockWork += GetPrevWorkForAlgoWithDecayV2(block, algo);
                }
                else
                {
                    nBlockWork += GetPrevWorkForAlgoWithDecayV1(block, algo);
                }
            }
        }
        bnTarget = nBlockWork / NUM_ALGOS;
    }
    
    return bnTarget;
}



int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip, const Consensus::Params& params)
{
    arith_uint256 r;
    int sign = 1;
    if (to.nChainWork > from.nChainWork) {
        r = to.nChainWork - from.nChainWork;
    } else {
        r = from.nChainWork - to.nChainWork;
        sign = -1;
    }
    r = r * arith_uint256(params.nPowTargetSpacing) / GetBlockProof(tip);
    if (r.bits() > 63) {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * r.GetLow64();
}

const CBlockIndex* GetLastBlockIndexForAlgo(const CBlockIndex* pindex, int algo)
{
    for (;;)
    {
        if (!pindex)
            return NULL;
        if (pindex->GetAlgo() == algo)
            return pindex;
        pindex = pindex->pprev;
    }
}

std::string GetAlgoName(int Algo, uint32_t time, const Consensus::Params& consensusParams)
{
    switch (Algo)
    {
        case ALGO_SLOT1:  return std::string("Lyra2RE2");
        case ALGO_SLOT2:  return std::string("Skein");
        case ALGO_SLOT3:  return std::string("Argon2d");
        case ALGO_SHA256:  return std::string("SHA256");

    }
    return std::string("Unknown");
}
