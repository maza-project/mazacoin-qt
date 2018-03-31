// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once
/*
#include "amount.h"
#include "script/ismine.h"
#include "script/sign.h"
#include "streams.h"
#include "tinyformat.h"
#include "ui_interface.h"
#include "utilstrencodings.h"
#include "validationinterface.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
*/
class CBlock;
class CBlockIndex;
class Config;

/** A transaction with a merkle branch linking it to the block chain. */
class CMerkleTx {
private:
    /** Constant used in hashBlock to indicate tx has been abandoned */
    static const uint256 ABANDON_HASH;

public:
    CTransactionRef tx;
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;

    /**
     * An nIndex == -1 means that hashBlock (in nonzero) refers to the earliest
     * block in the chain we know this or any in-wallet dependency conflicts
     * with. Older clients interpret nIndex == -1 as unconfirmed for backward
     * compatibility.
     */
    int nIndex;

    CMerkleTx() {
        SetTx(MakeTransactionRef());
        Init();
    }

    CMerkleTx(CTransactionRef arg) {
        SetTx(std::move(arg));
        Init();
    }

    /**
     * Helper conversion operator to allow passing CMerkleTx where CTransaction
     * is expected.
     * TODO: adapt callers and remove this operator.
     */
    operator const CTransaction &() const { return *tx; }

    void Init() {
        hashBlock = uint256();
        nIndex = -1;
    }

    void SetTx(CTransactionRef arg) { tx = std::move(arg); }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        // For compatibility with older versions.
        std::vector<uint256> vMerkleBranch;
        READWRITE(tx);
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    }

    void SetMerkleBranch(const CBlockIndex *pIndex, int posInBlock);

    /**
     * Actually compute the Merkle branch.  This is used for unit tests when
     * constructing an auxpow.  It is not needed for actual production, since
     * we do not care in the Namecoin client how the auxpow is constructed
     * by a miner.
     */
    void InitMerkleBranch(const CBlock& block, int posInBlock);

    /**
     * Return depth of transaction in blockchain:
     * <0  : conflicts with a transaction this deep in the blockchain
     *  0  : in memory pool, waiting to be included in a block
     * >=1 : this many blocks deep in the main chain
     */
    int GetDepthInMainChain(const CBlockIndex *&pindexRet) const;
    int GetDepthInMainChain() const {
        const CBlockIndex *pindexRet;
        return GetDepthInMainChain(pindexRet);
    }
    bool IsInMainChain() const {
        const CBlockIndex *pindexRet;
        return GetDepthInMainChain(pindexRet) > 0;
    }
    int GetBlocksToMaturity() const;
    /**
     * Pass this transaction to the mempool. Fails if absolute fee exceeds
     * absurd fee.
     */
    bool AcceptToMemoryPool(const CAmount& nAbsurdFee, CValidationState& state);
    bool hashUnset() const {
        return (hashBlock.IsNull() || hashBlock == ABANDON_HASH);
    }
    bool isAbandoned() const { return (hashBlock == ABANDON_HASH); }
    void setAbandoned() { hashBlock = ABANDON_HASH; }

    const uint256 &GetId() const { return tx->GetId(); }
    bool IsCoinBase() const { return tx->IsCoinBase(); }
};
