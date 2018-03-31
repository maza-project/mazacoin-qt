// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/pureheader.h"

#include "hash.h"
#include "crypto/hashskein.h"
#include "crypto/lyra2/lyra2RE.h"
#include "crypto/hashargon2d.h"
#include "utilstrencodings.h"

uint256 CPureBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CPureBlockHeader::GetPoWHash(int algo, const Consensus::Params& consensusParams) const
{
    switch (algo)
    {
        case ALGO_SLOT1:
            {
            uint256 thash;
            lyra2re2_hash(BEGIN(nVersion), BEGIN(thash));
            return thash;
            }
            
        case ALGO_SLOT2:
            return HashSkein(BEGIN(nVersion), END(nNonce));
            
        case ALGO_SLOT3:
            return HashArgon2d(BEGIN(nVersion), END(nNonce));
            
        case ALGO_SHA256:
            return GetHash();
            
    }
    // catch-all if above doesn't match anything to algo
    return GetHash();
}

void CPureBlockHeader::SetBaseVersion(int32_t nBaseVersion, int32_t nChainId)
{
    assert(nBaseVersion >= 1 && nBaseVersion < VERSION_AUXPOW);
    assert(!IsAuxpow());
    nVersion = nBaseVersion | (nChainId * VERSION_CHAIN_START);
}

int GetAlgo(int nVersion)
{
    switch (nVersion & BLOCK_VERSION_ALGO)
    {
        case 0:
            return ALGO_SHA256;
        case BLOCK_VERSION_SLOT1:
            return ALGO_SLOT1;
        case BLOCK_VERSION_SLOT2:
            return ALGO_SLOT2;
        case BLOCK_VERSION_SLOT3:
            return ALGO_SLOT3;
    }
    return ALGO_SLOT1;
}
