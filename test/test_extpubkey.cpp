#include "gtest/gtest.h"
#include <iostream>
#include <string>

#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_elements_address.h"

using cfd::core::CfdException;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::Extkey;
using cfd::core::ExtPubkey;
using cfd::core::KeyData;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::NetType;
using cfd::core::AddressType;

static const uint32_t extpubkey_kVersionMainnetPubkey = ExtPubkey::kVersionMainnetPubkey;
static const uint32_t extpubkey_kVersionTestnetPubkey = ExtPubkey::kVersionTestnetPubkey;

TEST(ExtPubkey, DefaultConstructorTest) {
  ExtPubkey extkey = ExtPubkey();

  EXPECT_STREQ("", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ("00000000", extkey.GetVersionData().GetHex().c_str());
  EXPECT_FALSE(extkey.IsValid());
}

TEST(ExtPubkey, SerializeConstructorTest) {
  std::string ext_serial = "043587cf02f4a831a200000000bdc76da475a6fbdc4f3758939ab2096d4ab53b7d66c0eed66fc0f4be242835fc030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0";
  ExtPubkey extkey = ExtPubkey(ByteData(ext_serial));

  EXPECT_STREQ(ext_serial.c_str(), extkey.GetData().GetHex().c_str());
  EXPECT_STREQ("043587cf", extkey.GetVersionData().GetHex().c_str());
  EXPECT_TRUE(extkey.IsValid());
  EXPECT_STREQ("tpubDBwZbsX7C1m4tfHxHSFBvvuasqMxzMvSNM5yuAWz6kAfCATAgegvrtGdnxkqfr8wwRZi5d9fJHXqE8EFTSogTXd3xVx3GUFy9Xcg8dufREz", extkey.ToString().c_str());
  EXPECT_EQ(2, extkey.GetDepth());
  EXPECT_STREQ("030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0", extkey.GetPubkey().GetHex().c_str());
}

TEST(ExtPubkey, Base58ConstructorTest) {
  std::string ext_base58 = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy";
  ExtPubkey extkey = ExtPubkey(ext_base58);

  EXPECT_STREQ("0488b21e000000000000000000a3fa8c983223306de0f0f65e74ebb1e98aba751633bf91d5fb56529aa5c132c102f632717d78bf73e74aa8461e2e782532abae4eed5110241025afb59ebfd3d2fd", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ("0488b21e", extkey.GetVersionData().GetHex().c_str());
  EXPECT_EQ(extpubkey_kVersionMainnetPubkey, extkey.GetVersion());
  EXPECT_EQ(0, extkey.GetFingerprint());
  EXPECT_TRUE(extkey.IsValid());
  EXPECT_STREQ(ext_base58.c_str(), extkey.ToString().c_str());
  EXPECT_EQ(0, extkey.GetDepth());
  EXPECT_EQ(0, extkey.GetChildNum());
  EXPECT_STREQ("a3fa8c983223306de0f0f65e74ebb1e98aba751633bf91d5fb56529aa5c132c1", extkey.GetChainCode().GetHex().c_str());
  EXPECT_STREQ("02f632717d78bf73e74aa8461e2e782532abae4eed5110241025afb59ebfd3d2fd", extkey.GetPubkey().GetHex().c_str());

  ext_base58 = "tpubDBwZbsX7C1m4tfHxHSFBvvuasqMxzMvSNM5yuAWz6kAfCATAgegvrtGdnxkqfr8wwRZi5d9fJHXqE8EFTSogTXd3xVx3GUFy9Xcg8dufREz";
  extkey = ExtPubkey(ext_base58);
  EXPECT_STREQ("043587cf02f4a831a200000000bdc76da475a6fbdc4f3758939ab2096d4ab53b7d66c0eed66fc0f4be242835fc030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ("043587cf", extkey.GetVersionData().GetHex().c_str());
  EXPECT_EQ(extpubkey_kVersionTestnetPubkey, extkey.GetVersion());
  EXPECT_EQ(0xF4A831A2, extkey.GetFingerprint());
  EXPECT_TRUE(extkey.IsValid());
  EXPECT_STREQ(ext_base58.c_str(), extkey.ToString().c_str());
  EXPECT_EQ(2, extkey.GetDepth());
  EXPECT_EQ(0, extkey.GetChildNum());
  EXPECT_STREQ("bdc76da475a6fbdc4f3758939ab2096d4ab53b7d66c0eed66fc0f4be242835fc", extkey.GetChainCode().GetHex().c_str());
  EXPECT_STREQ("030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0", extkey.GetPubkey().GetHex().c_str());
  EXPECT_EQ(NetType::kTestnet, extkey.GetNetworkType());

  std::string privkey_xpriv = "tprv8ZgxMBicQKsPeWHBt7a68nPnvgTnuDhUgDWC8wZCgA8GahrQ3f3uWpq7wE7Uc1dLBnCe1hhCZ886K6ND37memRDWqsA9HgSKDXtwh2Qxo6J";
  EXPECT_THROW((extkey = ExtPubkey(privkey_xpriv)), CfdException);
}

TEST(ExtPubkey, FromKeyDataTest) {
  // tpubDDNapBCUaChXpE91grWNGp8xWg84GcS1iRSR7iynAFTv6JAGnKTEUB3vkHtsV4NbkZf6SfjYM6PvW3kZ77KLUZ2GTYNBN4PJRWCKN1ERjJe
  // 44
  std::string ext_base58 = "tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua";
  ExtPubkey extkey = ExtPubkey(NetType::kTestnet,
      Pubkey("02ca30dbb25a2cf96344a04ae2144fb28a17f006c34cfb973b9f21623db27c5cd3"),
      Pubkey("03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3"),
      ByteData256("839fb0d66f1887db167cdc530ab98e871d8b017ebcb198568874b6c98516364e"),
      uint8_t{4}, uint32_t{44});

  EXPECT_STREQ("043587cf04a53a8ff30000002c839fb0d66f1887db167cdc530ab98e871d8b017ebcb198568874b6c98516364e03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ("043587cf", extkey.GetVersionData().GetHex().c_str());
  EXPECT_EQ(extpubkey_kVersionTestnetPubkey, extkey.GetVersion());
  EXPECT_EQ(0xA53A8FF3, extkey.GetFingerprint());
  EXPECT_STREQ("a53a8ff3", extkey.GetFingerprintData().GetHex().c_str());
  EXPECT_TRUE(extkey.IsValid());
  EXPECT_STREQ(ext_base58.c_str(), extkey.ToString().c_str());
  EXPECT_EQ(4, extkey.GetDepth());
  EXPECT_EQ(44, extkey.GetChildNum());
  EXPECT_STREQ("839fb0d66f1887db167cdc530ab98e871d8b017ebcb198568874b6c98516364e", extkey.GetChainCode().GetHex().c_str());
  EXPECT_STREQ("03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3", extkey.GetPubkey().GetHex().c_str());
}

TEST(ExtPubkey, DerivePubkeyTest) {
  std::string ext_serial = "043587cf02f4a831a200000000bdc76da475a6fbdc4f3758939ab2096d4ab53b7d66c0eed66fc0f4be242835fc030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0";
  ExtPubkey extkey = ExtPubkey(ByteData(ext_serial));
  ExtPubkey child;
  ExtPubkey child1;
  ExtPubkey child2;
  std::vector<uint32_t> path = {0, 44};

  EXPECT_NO_THROW((child = extkey.DerivePubkey(path)));
  EXPECT_STREQ("043587cf04a53a8ff30000002c839fb0d66f1887db167cdc530ab98e871d8b017ebcb198568874b6c98516364e03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3", child.GetData().GetHex().c_str());
  EXPECT_STREQ("tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua", child.ToString().c_str());
  EXPECT_STREQ("043587cf", child.GetVersionData().GetHex().c_str());
  EXPECT_EQ(extpubkey_kVersionTestnetPubkey, child.GetVersion());
  EXPECT_TRUE(child.IsValid());
  EXPECT_EQ(4, child.GetDepth());
  EXPECT_STREQ("03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3", child.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("839fb0d66f1887db167cdc530ab98e871d8b017ebcb198568874b6c98516364e", child.GetChainCode().GetHex().c_str());
  EXPECT_STREQ("a53a8ff3", child.GetFingerprintData().GetHex().c_str());
#ifndef CFD_DISABLE_ELEMENTS
  EXPECT_STREQ("68a454a64c91bd4086e5008e843dbe1c583d193afd9bdbbcdd8afcb1bdd3cafe", child.GetPubTweakSum().GetHex().c_str());
#endif  // CFD_DISABLE_ELEMENTS

  EXPECT_NO_THROW((child1 = extkey.DerivePubkey(0)));
  EXPECT_STREQ("043587cf", child1.GetVersionData().GetHex().c_str());
  EXPECT_EQ(extpubkey_kVersionTestnetPubkey, child1.GetVersion());
  EXPECT_TRUE(child1.IsValid());
  EXPECT_EQ(3, child1.GetDepth());
  EXPECT_STREQ("02ca30dbb25a2cf96344a04ae2144fb28a17f006c34cfb973b9f21623db27c5cd3", child1.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("87ced156b5641d416892046bbd1257c492c030967868aa8dc7a7067490fa08d5", child1.GetChainCode().GetHex().c_str());
  EXPECT_STREQ("b7665978", child1.GetFingerprintData().GetHex().c_str());
#ifndef CFD_DISABLE_ELEMENTS
  EXPECT_STREQ("6a5e09c61652134b024da66a8517fe2e280c6faaa7c3a99314f60b1081410f0c", child1.GetPubTweakSum().GetHex().c_str());
#endif  // CFD_DISABLE_ELEMENTS

  EXPECT_NO_THROW((child2 = child1.DerivePubkey(44)));
  EXPECT_STREQ("043587cf", child2.GetVersionData().GetHex().c_str());
  EXPECT_EQ(extpubkey_kVersionTestnetPubkey, child2.GetVersion());
  EXPECT_TRUE(child2.IsValid());
  EXPECT_EQ(4, child2.GetDepth());
  EXPECT_STREQ("03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3", child2.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("839fb0d66f1887db167cdc530ab98e871d8b017ebcb198568874b6c98516364e", child2.GetChainCode().GetHex().c_str());
  EXPECT_STREQ("a53a8ff3", child2.GetFingerprintData().GetHex().c_str());
#ifndef CFD_DISABLE_ELEMENTS
  EXPECT_STREQ("68a454a64c91bd4086e5008e843dbe1c583d193afd9bdbbcdd8afcb1bdd3cafe", child2.GetPubTweakSum().GetHex().c_str());
#endif  // CFD_DISABLE_ELEMENTS

  EXPECT_STREQ(child2.GetData().GetHex().c_str(), child.GetData().GetHex().c_str());
  EXPECT_STREQ(child2.GetVersionData().GetHex().c_str(), child.GetVersionData().GetHex().c_str());
  EXPECT_EQ(child2.GetVersion(), child.GetVersion());
  EXPECT_TRUE(child2.IsValid());
  EXPECT_STREQ(child2.ToString().c_str(), child.ToString().c_str());
  EXPECT_EQ(child2.GetDepth(), child.GetDepth());
  EXPECT_STREQ(child2.GetPubkey().GetHex().c_str(), child.GetPubkey().GetHex().c_str());
#ifndef CFD_DISABLE_ELEMENTS
  EXPECT_STREQ(child2.GetPubTweakSum().GetHex().c_str(), child.GetPubTweakSum().GetHex().c_str());
#endif  // CFD_DISABLE_ELEMENTS

  EXPECT_NO_THROW((child2 = extkey.DerivePubkey("0x000000000/0x2c")));  // 0/44
  EXPECT_STREQ(child2.GetData().GetHex().c_str(), child.GetData().GetHex().c_str());
  EXPECT_STREQ(child2.GetVersionData().GetHex().c_str(), child.GetVersionData().GetHex().c_str());
  EXPECT_EQ(child2.GetVersion(), child.GetVersion());
  EXPECT_TRUE(child2.IsValid());
  EXPECT_STREQ(child2.ToString().c_str(), child.ToString().c_str());
  EXPECT_EQ(child2.GetDepth(), child.GetDepth());
  EXPECT_STREQ(child2.GetPubkey().GetHex().c_str(), child.GetPubkey().GetHex().c_str());

  EXPECT_THROW((child2 = extkey.DerivePubkey("m/1/1")), CfdException);  // master 

  EXPECT_NO_THROW((child2 = extkey.DerivePubkey("/1/1")));  // start slash

  EXPECT_THROW((child2 = extkey.DerivePubkey("1/2//3")), CfdException);  // empty number

  // KeyData
  KeyData data1 = extkey.DerivePubkeyData("0/44");
  EXPECT_STREQ("[b7665978/0/44]tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua", data1.ToString(false).c_str());
  EXPECT_STREQ("tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua", data1.GetExtPubkey().ToString().c_str());

  KeyData data2 = extkey.DerivePubkeyData(path);
  EXPECT_STREQ("[b7665978/0/44]tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua", data2.ToString(false).c_str());
  EXPECT_STREQ("tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua", data2.GetExtPubkey().ToString().c_str());
}

TEST(ExtPubkey, DerivePubTweakTest) {
  std::string ext_serial = "043587cf02f4a831a200000000bdc76da475a6fbdc4f3758939ab2096d4ab53b7d66c0eed66fc0f4be242835fc030061b08c4c80dc04aaa0b44018d2c4bcdb0d9c0992fb4fddf9d2fb096a5164c0";
  ExtPubkey extkey = ExtPubkey(ByteData(ext_serial));

  std::vector<uint32_t> key_paths = {0, 5};
  ByteData256 tweak_sum;
  EXPECT_NO_THROW((tweak_sum = extkey.DerivePubTweak(key_paths)));
#ifndef CFD_DISABLE_ELEMENTS
  EXPECT_STREQ("2f0b491d070c810a9779a8398063ba6e20302604dc36cf6bf6f935e34c68fa22", tweak_sum.GetHex().c_str());
#endif  // CFD_DISABLE_ELEMENTS
}

TEST(ExtPubkey, CreateExtPubkeyFromPubkey) {
  ExtPubkey extkey;

  EXPECT_NO_THROW((extkey = ExtPubkey(NetType::kTestnet,
      Pubkey("02ca30dbb25a2cf96344a04ae2144fb28a17f006c34cfb973b9f21623db27c5cd3"),
      ByteData256("87ced156b5641d416892046bbd1257c492c030967868aa8dc7a7067490fa08d5"),
      3, 44)));
  EXPECT_STREQ("043587cf04a53a8ff30000002c839fb0d66f1887db167cdc530ab98e871d8b017ebcb198568874b6c98516364e03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3", extkey.GetData().GetHex().c_str());
  EXPECT_STREQ("tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua", extkey.ToString().c_str());
  EXPECT_STREQ("043587cf", extkey.GetVersionData().GetHex().c_str());
  EXPECT_EQ(extpubkey_kVersionTestnetPubkey, extkey.GetVersion());
  EXPECT_TRUE(extkey.IsValid());
  EXPECT_EQ(4, extkey.GetDepth());
  EXPECT_STREQ("03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3", extkey.GetPubkey().GetHex().c_str());
  EXPECT_STREQ("839fb0d66f1887db167cdc530ab98e871d8b017ebcb198568874b6c98516364e", extkey.GetChainCode().GetHex().c_str());
  EXPECT_STREQ("a53a8ff3", extkey.GetFingerprintData().GetHex().c_str());
}

TEST(ExtPubkey, GetPubkeyAddress) {
  std::string ext_base58 = "tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua";

  ExtPubkey pubkey(ext_base58);
  auto addr1 = pubkey.GetPubkeyAddress();
  EXPECT_EQ("tb1qgrys9hdcsunfh5qklzj85e6qev9v5gmsyl4tfv",
    addr1.GetAddress());
  auto addrs1 = pubkey.GetPubkeyAddresses();
  EXPECT_EQ(4, addrs1.size());
  if (addrs1.size() == 4) {
    EXPECT_EQ("tb1qgrys9hdcsunfh5qklzj85e6qev9v5gmsyl4tfv",
      addrs1[0].GetAddress());
    EXPECT_EQ("tb1p78nk0sz4tnspqke2wmg03vvmd5e6z3lc9a66qhzvp9vqcwtfflfs5wcm3n",
      addrs1[1].GetAddress());
    EXPECT_EQ("2N9E4zD7TeFFuHTvzuVVvVSpmKq2DwGevP6",
      addrs1[2].GetAddress());
    EXPECT_EQ("mmRWLqKULV2s5o1j42FhB6ZhdscGmqSRH2",
      addrs1[3].GetAddress());
  }

  auto addr2 = pubkey.GetPubkeyAddress(
      AddressType::kWitnessUnknown, nullptr, NetType::kRegtest);
  EXPECT_EQ("bcrt1qgrys9hdcsunfh5qklzj85e6qev9v5gmsxkvx79",
    addr2.GetAddress());
  auto addrs2 = pubkey.GetPubkeyAddresses(nullptr, NetType::kRegtest);
  EXPECT_EQ(4, addrs1.size());
  if (addrs2.size() == 4) {
    EXPECT_EQ("bcrt1qgrys9hdcsunfh5qklzj85e6qev9v5gmsxkvx79",
      addrs2[0].GetAddress());
    EXPECT_EQ("bcrt1p78nk0sz4tnspqke2wmg03vvmd5e6z3lc9a66qhzvp9vqcwtfflfsehjayf",
      addrs2[1].GetAddress());
    EXPECT_EQ("2N9E4zD7TeFFuHTvzuVVvVSpmKq2DwGevP6",
      addrs2[2].GetAddress());
    EXPECT_EQ("mmRWLqKULV2s5o1j42FhB6ZhdscGmqSRH2",
      addrs2[3].GetAddress());
  }

#ifndef CFD_DISABLE_ELEMENTS
  auto el_list = cfd::core::GetElementsAddressFormatList();
  auto addr3 = pubkey.GetPubkeyAddress(AddressType::kP2pkhAddress,
      &el_list, NetType::kElementsRegtest);
  EXPECT_EQ("2dfLJSJHCNrVWVYJU63ZDJeKFgRZEuxc1JQ",
    addr3.GetAddress());

  auto addrs3 = pubkey.GetPubkeyAddresses(
      &el_list, NetType::kElementsRegtest);
  EXPECT_EQ(4, addrs3.size());
  if (addrs3.size() == 4) {
    EXPECT_EQ("ert1qgrys9hdcsunfh5qklzj85e6qev9v5gms7zecq9",
      addrs3[0].GetAddress());
    EXPECT_EQ("ert1p78nk0sz4tnspqke2wmg03vvmd5e6z3lc9a66qhzvp9vqcwtfflfsgy6rdd",
      addrs3[1].GetAddress());
    EXPECT_EQ("XTL5r53bjRBtL24WwjCMpGtaAnr5wmHkXL",
      addrs3[2].GetAddress());
    EXPECT_EQ("2dfLJSJHCNrVWVYJU63ZDJeKFgRZEuxc1JQ",
      addrs3[3].GetAddress());
  }
#endif  // CFD_DISABLE_ELEMENTS
}

TEST(Extkey, Constructor) {
  
  std::string ext_base58 = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy";
  Extkey extkey_base58(ext_base58);
  ByteData ext_serial(
    "0488b21e000000000000000000a3fa8c983223306de0f0f65e74ebb1e98aba751633bf91d5fb56529aa5c132c102f632717d78bf73e74aa8461e2e782532abae4eed5110241025afb59ebfd3d2fd");
  Extkey extkey(ext_serial);

  EXPECT_EQ(extkey_base58.GetData().GetHex(), extkey.GetData().GetHex());
}