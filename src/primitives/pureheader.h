// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_PUREHEADER_H
#define BITCOIN_PRIMITIVES_PUREHEADER_H

#include "serialize.h"
#include "uint256.h"
#include "consensus/params.h"

/** Multi-Algo definitions used to encode algorithm in nVersion */

enum {
    ALGO_SHA256 = 0,  // currently SHA256
    ALGO_SLOT1 = 1,  // currently Lyra2RE2
    ALGO_SLOT2 = 2,  // currently Skein
    ALGO_SLOT3 = 3,  // currently Argon2d
    NUM_ALGOS
};

enum
{
    // primary version
    BLOCK_VERSION_DEFAULT        = 4,

    // algo
    BLOCK_VERSION_ALGO      = (7 << 9),
    BLOCK_VERSION_SLOT1     = (1 << 9),
    BLOCK_VERSION_SLOT2     = (2 << 9),
    BLOCK_VERSION_SLOT3     = (3 << 9),
};

/** extract algo from nVersion */
int GetAlgo(int nVersion);

class CPureBlockHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    CPureBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    uint256 GetSHAHash() const;
    
    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
   
    /** Extract algo from blockheader */
    inline int GetAlgo() const
    {
        return ::GetAlgo(nVersion);
    }
    
    /** Encode the algorithm into nVersion */
    inline void SetAlgo(int algo)
    {
        switch(algo)
        {
            case ALGO_SHA256:
                break;
            case ALGO_SLOT1:
                nVersion |= BLOCK_VERSION_SLOT1;
                break;
            case ALGO_SLOT2:
                nVersion |= BLOCK_VERSION_SLOT2;
                break;
            case ALGO_SLOT3:
                nVersion |= BLOCK_VERSION_SLOT3;
                break;
            default:
                break;
        }
    }
};

#endif // BITCOIN_PRIMITIVES_PUREHEADER_H
