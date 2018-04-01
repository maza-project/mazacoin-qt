// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"

unsigned int GetNextWorkRequired_V1(const CBlockIndex* pindexLast, const CBlockHeader *pblock,
                                    const Consensus::Params &params)
{
    const uint32_t nProofOfWorkLimit = UintToArith256(params.powLimit[ALGO_SHA256]).GetCompact();
    static const int64_t nAveragingInterval = params.DifficultyAdjustmentInterval() * 20;
    static const int64_t nAveragingTargetTimespan = nAveragingInterval * params.nPowTargetSpacing; // 40 minutes
    static const int64_t nMaxAdjustDown = 20; // 20% adjustment down
    static const int64_t nMaxAdjustUp = 15; // 15% adjustment up
    static const int64_t nMinActualTimespan = nAveragingTargetTimespan * (100 - nMaxAdjustUp) / 100;
    static const int64_t nMaxActualTimespan = nAveragingTargetTimespan * (100 + nMaxAdjustDown) / 100;
    
    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;
    
    // Start at difficulty of 1
    if (pindexLast->nHeight+1 < nAveragingInterval)
        return UintToArith256(params.startingDifficulty).GetCompact();
    // Only change once per interval
    if ((pindexLast->nHeight+1) % params.nRuleChangeActivationThreshold != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.nRuleChangeActivationThreshold != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }
    
    // Go back by what we want to be nAveragingInterval blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < nAveragingInterval-1; i++)
        pindexFirst = pindexFirst->pprev;
    assert(pindexFirst);
    
    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    //LogPrintf("  nActualTimespan = %d  before bounds\n", nActualTimespan);
    if (nActualTimespan < nMinActualTimespan)
        nActualTimespan = nMinActualTimespan;
    if (nActualTimespan > nMaxActualTimespan)
        nActualTimespan = nMaxActualTimespan;
    
    // Retarget
    arith_uint256 bnNew;
    arith_uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    bnNew *= nActualTimespan;
    bnNew /= nAveragingTargetTimespan;
    
    if (bnNew > UintToArith256(params.powLimit[ALGO_SHA256]))
        bnNew = UintToArith256(params.powLimit[ALGO_SHA256]);
    
    /// debug print
    /*
     LogPrintf("GetNextWorkRequired RETARGET\n");
     LogPrintf("Params().TargetTimespan() = %d    nActualTimespan = %d\n", nAveragingTargetTimespan, nActualTimespan);
     LogPrintf("Before: %08x  %s\n", pindexLast->nBits, bnOld.ToString());
     LogPrintf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.ToString());
     */
    return bnNew.GetCompact();
}


unsigned int DarkGravityWave3(const CBlockIndex* pindexLast, const CBlockHeader *pblock,
                              const Consensus::Params &params) {
    /* current difficulty formula, darkcoin - DarkGravity v3, written by Evan Duffield - evan@darkcoin.io */
    const CBlockIndex *BlockLastSolved = pindexLast;
    const CBlockIndex *BlockReading = pindexLast;
    int64_t nActualTimespan = 0;
    int64_t LastBlockTime = 0;
    int64_t PastBlocksMin = 24;
    int64_t PastBlocksMax = 24;
    int64_t CountBlocks = 0;
    arith_uint256 PastDifficultyAverage;
    arith_uint256 PastDifficultyAveragePrev;
    arith_uint256 bnNum;
    
    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || BlockLastSolved->nHeight < PastBlocksMin) {
        arith_uint256 temp = UintToArith256(params.powLimit[ALGO_SHA256]);
        return temp.GetCompact();
    }
    
    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (PastBlocksMax > 0 && i > PastBlocksMax) break;
        CountBlocks++;
        
        if (CountBlocks <= PastBlocksMin) {
            if (CountBlocks == 1)
                PastDifficultyAverage.SetCompact(BlockReading->nBits);
            else
                PastDifficultyAverage = ((PastDifficultyAveragePrev * CountBlocks)+(bnNum.SetCompact(BlockReading->nBits))) / (CountBlocks+1);
            PastDifficultyAveragePrev = PastDifficultyAverage;
        }
        
        if (LastBlockTime > 0){
            int64_t Diff = (LastBlockTime - BlockReading->GetBlockTime());
            nActualTimespan += Diff;
        }
        LastBlockTime = BlockReading->GetBlockTime();
        
        if (BlockReading->pprev == NULL) {
            assert(BlockReading);
            break;
        }
        BlockReading = BlockReading->pprev;
    }
    
    arith_uint256 bnNew(PastDifficultyAverage);
    
    int64_t nTargetTimespan = CountBlocks*params.nPowTargetSpacing;
    
    if (nActualTimespan < nTargetTimespan/3)
        nActualTimespan = nTargetTimespan/3;
    if (nActualTimespan > nTargetTimespan*3)
        nActualTimespan = nTargetTimespan*3;
    
    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;
    
    if (bnNew > UintToArith256(params.powLimit[ALGO_SHA256]))
        bnNew = UintToArith256(params.powLimit[ALGO_SHA256]);
    
    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequiredMaza(const CBlockIndex* pindexLast, const CBlockHeader *pblock,
                                 const Consensus::Params &params) {
    
    int DiffMode = 1;
    if (params.fPowAllowMinDifficultyBlocks) {
        if (pindexLast->nHeight+1 >= 10)
            DiffMode = 2;
    } else {
        if (pindexLast->nHeight+1 >= 100000)
            DiffMode = 2;
    }
    
    if (DiffMode == 1)
        return GetNextWorkRequired_V1(pindexLast, pblock, params);
    else
        return DarkGravityWave3(pindexLast, pblock, params);
}


unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    
    if (pindexLast->nHeight < params.nTimeArgon2dStart)
        return GetNextWorkRequiredMaza(pindexLast, pblock, params);
    
    int algo = pblock->GetAlgo();
    const arith_uint256 nProofOfWorkLimit = UintToArith256(params.powLimit[algo]);

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit.GetCompact();

    // find previous block with same algo
    const CBlockIndex* pindexPrev = GetLastBlockIndexForAlgo(pindexLast, algo);
    if (pindexPrev == NULL)
        return nProofOfWorkLimit.GetCompact();
    
    const CBlockIndex* pindexFirst = pindexPrev;
   
    // Go back by what we want to be nAveragingInterval blocks
    for (int i = 0; pindexFirst && i < params.nPoWAveragingInterval - 1; i++)
    {
        pindexFirst = pindexFirst->pprev;
        pindexFirst = GetLastBlockIndexForAlgo(pindexFirst, algo);
        if (pindexFirst == NULL)
            return nProofOfWorkLimit.GetCompact();
    }

    const CBlockIndex* pindexFirstPrev;
    for ( ;; )
    {
        // check blocks before first block for time warp
        pindexFirstPrev = pindexFirst->pprev;
        if (pindexFirstPrev == NULL)
            return nProofOfWorkLimit.GetCompact();
        pindexFirstPrev = GetLastBlockIndexForAlgo(pindexFirstPrev, algo);
        if (pindexFirstPrev == NULL)
            return nProofOfWorkLimit.GetCompact();
        // take previous block if block times are out of order
        if (pindexFirstPrev->GetBlockTime() > pindexFirst->GetBlockTime())
        {
            if (fDebug)
            {
                LogPrintf("GetNextWorkRequired(Algo=%d): First blocks out of order times, swapping:   %d   %d\n", algo, pindexFirstPrev->GetBlockTime(), pindexFirst->GetBlockTime());
            }
            pindexFirst = pindexFirstPrev;
        }
        else
            break;
    }
    
    //??
    int64_t nMinActualTimespan = params.nPoWAveragingTargetTimespan() * (100 - params.nMaxAdjustUp) / 100;
    int64_t nMaxActualTimespan = params.nPoWAveragingTargetTimespan() * (100 + params.nMaxAdjustDown) / 100;
    
    // Limit adjustment step
    int64_t nActualTimespan = pindexPrev->GetBlockTime() - pindexFirst->GetBlockTime();
    
    if (fDebug)
        LogPrintf("GetNextWorkRequired(Algo=%d): nActualTimespan = %d before bounds   %d   %d\n", algo, nActualTimespan, pindexLast->GetBlockTime(), pindexFirst->GetBlockTime());
    
    if (nActualTimespan < nMinActualTimespan)
        nActualTimespan = nMinActualTimespan;
    if (nActualTimespan > nMaxActualTimespan)
        nActualTimespan = nMaxActualTimespan;
    
    if (fDebug)
        LogPrintf("GetNextWorkRequired(Algo=%d): nActualTimespan = %d after bounds   %d   %d\n", algo, nActualTimespan, nMinActualTimespan, nMaxActualTimespan);
    
    // Retarget
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    arith_uint256 bnOld;
    bnOld = bnNew;
    
    bnNew *= nActualTimespan;
    bnNew /= params.nPoWAveragingTargetTimespan();
    if(bnNew > nProofOfWorkLimit)
        bnNew = nProofOfWorkLimit;
    
    if (fDebug)
    {
        LogPrintf("GetNextWorkRequired(Algo=%d) RETARGET\n", algo);
        LogPrintf("GetNextWorkRequired(Algo=%d): nTargetTimespan = %d    nActualTimespan = %d\n", algo, params.nPoWAveragingTargetTimespan(), nActualTimespan);
        LogPrintf("GetNextWorkRequired(Algo=%d): Before: %08x  %s\n", algo, pindexLast->nBits, bnOld.ToString());
        LogPrintf("GetNextWorkRequired(Algo=%d): After:  %08x  %s\n", algo, bnNew.GetCompact(), bnNew.ToString());
    }
    
    return bnNew.GetCompact();
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, int algo, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit[algo]);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit) bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, int algo, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit[algo]))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
