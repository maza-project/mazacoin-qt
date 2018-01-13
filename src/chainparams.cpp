// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <cassert>

#include "chainparamsseeds.h"

// Far into the future.
static const std::string ANTI_REPLAY_COMMITMENT =
    "Bitcoin: A Peer-to-Peer Electronic Cash System";

static std::vector<uint8_t> GetAntiReplayCommitment() {
    return std::vector<uint8_t>(std::begin(ANTI_REPLAY_COMMITMENT),
                                std::end(ANTI_REPLAY_COMMITMENT));
}

static CBlock CreateGenesisBlock(const char *pszTimestamp,
                                 const CScript &genesisOutputScript,
                                 uint32_t nTime, uint32_t nNonce,
                                 uint32_t nBits, int32_t nVersion,
                                 const Amount genesisReward) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig =
        CScript() << 486604799 << CScriptNum(4)
                  << std::vector<uint8_t>((const uint8_t *)pszTimestamp,
                                          (const uint8_t *)pszTimestamp +
                                              strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation transaction
 * cannot be spent since it did not originally exist in the database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000,
 * hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893,
 * vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase
 * 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce,
                                 uint32_t nBits, int32_t nVersion,
                                 const Amount genesisReward) {
    const char *pszTimestamp =
        "February 5, 2014: The Black Hills are not for sale - 1868 Is The LAW!";
    const CScript genesisOutputScript =
        CScript() << 
        ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
        
                  << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce,
                              nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 950000;
        consensus.BIP34Height = 999999;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb4"
                                       "4ab7bd1b19115dd6a759c0808b8");
        // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP65Height = 999999;
        // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.BIP66Height = 999999;
        consensus.antiReplayOpReturnSunsetHeight = 999999;
        consensus.antiReplayOpReturnCommitment = GetAntiReplayCommitment();
        consensus.powLimit = uint256S(
            "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.startingDifficulty = uint256S(
            "00000003ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 8 * 60; // ???14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        // 95% of 2016
        consensus.nRuleChangeActivationThreshold = consensus.nPowTargetTimespan / consensus.nPowTargetSpacing;
        consensus.nMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime =
            1199145601;
        // December 31, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout =
            1230767999;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime =
            1462060800;
        // May 1st, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork =
            uint256S("0x0000000000000000000000000000000000000000003f94d1ad39168"
                     "2fe038bf5");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid =
            uint256S("0x000000000000000000ff3a41f208c932d5f91fe8d0739fca36152f6"
                     "073b2ef5e");

        // Aug, 1 hard fork
        //consensus.uahfStartTime = 9999999999;


        /**
         * The message start string is designed to be unlikely to occur in
         * normal data. The characters are rarely used upper ASCII, not valid as
         * UTF-8, and produce a large 32-bit integer with any alignment.
         */
        diskMagic[0] = 0xf8;
        diskMagic[1] = 0xb5;
        diskMagic[2] = 0x03;
        diskMagic[3] = 0xdf;
        netMagic[0] = 0xe3;
        netMagic[1] = 0xe1;
        netMagic[2] = 0xf3;
        netMagic[3] = 0xe8;
        nDefaultPort = 12835;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1390747675, 2091390249, 0x1e0ffff0, 1,
                                     5000 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("0x00000c7c73d8ce604178dae13f0fc6ec0be3275614366d44b1b4b5c6e238c60c"));
        
        assert(genesis.hashMerkleRoot ==
               uint256S("0x62d496378e5834989dd9594cfc168dbb76f84a39bbda18286cddc7d1d1589f4f"));

        // Note that of those with the service bits flag, most only support a
        // subset of possible options.
        // Bitcoin ABC seeder
        vSeeds.push_back(
            CDNSSeedData("mazacoin.org", "node.mazacoin.org", true));
        // bitcoinforks seeders
        // BU backed seeder
        // Bitprim
        // Amaury SÉCHET
        // criptolayer.net

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 50);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 9);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 224);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
        cashaddrPrefix = "bitcoincash";

        vFixedSeeds = std::vector<SeedSpec6>(
            pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            .mapCheckpoints = {
                {0,uint256S("0x00000c7c73d8ce604178dae13f0fc6ec0be3275614366d44b1b4b5c6e238c60c")},
                {91800,uint256S("0x00000000000000f35417a67ff0bb5cec6a1c64d13bb1359ae4a03d2c9d44d900")},
                {183600,uint256S("0x0000000000000787f10fa4a547822f8170f1f182ca0de60ecd2de189471da885")}}};

        // Data as of block
        // 00000000000000000166d612d5595e2b1cd88d71d695fc580af64d8da8658c23
        // (height 446482).
        chainTxData = ChainTxData{
            // UNIX timestamp of last known number of transactions.
            1483472411,
            // Total number of transactions between genesis and that timestamp
            // (the tx=... number in the SetBestChain debug.log lines)
            184495391,
            // Estimated number of transactions per second after that timestamp.
            3.2};
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 950000;
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d4"
                                       "1500f8e2a5c3f0dd01299cd8ef8");
        // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP65Height = 581885;
        // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.BIP66Height = 330776;
        consensus.antiReplayOpReturnSunsetHeight = 1250000;
        consensus.antiReplayOpReturnCommitment = GetAntiReplayCommitment();
        consensus.powLimit = uint256S(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        // 75% for testchains
        consensus.nRuleChangeActivationThreshold = 1512;
        // nPowTargetTimespan / nPowTargetSpacing
        consensus.nMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime =
            1199145601;
        // December 31, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout =
            1230767999;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime =
            1456790400;
        // May 1st, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork =
            uint256S("0x00000000000000000000000000000000000000000000001f057509e"
                     "ba81aed91");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid =
            uint256S("0x00000000000128796ee387cf110ccb9d2f36cffaf7f73079c995377"
                     "c65ac0dcc");

        diskMagic[0] = 0x0b;
        diskMagic[1] = 0x11;
        diskMagic[2] = 0x09;
        diskMagic[3] = 0x07;
        netMagic[0] = 0xf4;
        netMagic[1] = 0xe5;
        netMagic[2] = 0xf3;
        netMagic[3] = 0xf4;
        nDefaultPort = 18333;
        nPruneAfterHeight = 1000;

        genesis =
            CreateGenesisBlock(1296688602, 414098458, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        /*
        assert(consensus.hashGenesisBlock ==
               uint256S("0x000000000933ea01ad0ee984209779baaec3ced90fa3f4087195"
                        "26f8d77f4943"));
        assert(genesis.hashMerkleRoot ==
               uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab212"
                        "7b7afdeda33b"));
*/
        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        // Bitcoin ABC seeder
        vSeeds.push_back(CDNSSeedData("bitcoinabc.org",
                                      "testnet-seed.bitcoinabc.org", true));
        // bitcoinforks seeders
        vSeeds.push_back(CDNSSeedData(
            "bitcoinforks.org", "testnet-seed-abc.bitcoinforks.org", true));
        // Bitprim
        vSeeds.push_back(
            CDNSSeedData("bitprim.org", "testnet-seed.bitprim.org", true));
        // Amaury SÉCHET
        vSeeds.push_back(
            CDNSSeedData("deadalnix.me", "testnet-seed.deadalnix.me", true));
        // criptolayer.net
        vSeeds.push_back(CDNSSeedData("criptolayer.net",
                                      "testnet-seeder.criptolayer.net", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = "bchtest";
        vFixedSeeds = std::vector<SeedSpec6>(
            pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = {
            .mapCheckpoints = {
                {546, uint256S("000000002a936ca763904c3c35fce2f3556c559c0214345"
                               "d31b1bcebf76acb70")},
                // UAHF fork block.
                {1155876, uint256S("00000000000e38fef93ed9582a7df43815d5c2ba9fd"
                                   "37ef70c9a0ea4a285b8f5")},
                // Nov, 13. DAA activation block.
                {1188697, uint256S("0000000000170ed0918077bde7b4d36cc4c91be69fa"
                                   "09211f748240dabe047fb")},
            }};

        // Data as of block
        // 00000000c2872f8f8a8935c8e3c5862be9038c97d4de2cf37ed496991166928a
        // (height 1063660)
        chainTxData = ChainTxData{1483546230, 12834668, 0.15};
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        // BIP34 has not activated on regtest (far in the future so block v1 are
        // not rejected in tests)
        consensus.BIP34Height = 100000000;
        consensus.BIP34Hash = uint256();
        // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP65Height = 1351;
        // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251;
        consensus.antiReplayOpReturnSunsetHeight = 530000;
        consensus.antiReplayOpReturnCommitment = GetAntiReplayCommitment();
        consensus.powLimit = uint256S(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        // 75% for testchains
        consensus.nRuleChangeActivationThreshold = 108;
        // Faster than normal for regtest (144 instead of 2016)
        consensus.nMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout =
            999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout =
            999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        // Hard fork is always enabled on regtest.
        consensus.uahfHeight = 0;

        // Nov, 13 hard fork is always on on regtest.
        consensus.daaHeight = 0;

        diskMagic[0] = 0xfa;
        diskMagic[1] = 0xbf;
        diskMagic[2] = 0xb5;
        diskMagic[3] = 0xda;
        netMagic[0] = 0xda;
        netMagic[1] = 0xb5;
        netMagic[2] = 0xbf;
        netMagic[3] = 0xfa;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        /*
        assert(consensus.hashGenesisBlock ==
               uint256S("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b"
                        "1a11466e2206"));
        assert(genesis.hashMerkleRoot ==
               uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab212"
                        "7b7afdeda33b"));
*/
        //!< Regtest mode doesn't have any fixed seeds.
        vFixedSeeds.clear();
        //!< Regtest mode doesn't have any DNS seeds.
        vSeeds.clear();

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {.mapCheckpoints = {
                              {0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5"
                                           "beb436012afca590b1a11466e2206")},
                          }};

        chainTxData = ChainTxData{0, 0, 0};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = "bchreg";
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime,
                              int64_t nTimeout) {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};

static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(const std::string &chain) {
    if (chain == CBaseChainParams::MAIN) {
        return mainParams;
    }

    if (chain == CBaseChainParams::TESTNET) {
        return testNetParams;
    }

    if (chain == CBaseChainParams::REGTEST) {
        return regTestParams;
    }

    throw std::runtime_error(
        strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string &network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime,
                                 int64_t nTimeout) {
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
