#include "cfdcore/cfdcore_ecdsa_adaptor.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_util.h"
#include "gtest/gtest.h"

using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CryptoUtil;
using cfd::core::Privkey;
using cfd::core::Pubkey;

using cfd::core::AdaptorSignature;

const ByteData256 msg(
    "8131e6f4b45754f2c90bd06688ceeabc0c45055460729928b4eecf11026a9e2d");
const Privkey sk(
    "90ac0d5dc0a1a9ab352afb02005a5cc6c4df0da61d8149d729ff50db9b5a5215");
const std::string adaptor_sig_str =
    "0287b498de89db75bf68e15836be75e42619cfe85a6bcea503ea23444597deae8c025ed1a6f5d7ce4a4d8132c824ed374353629d672fea7c5c459348f3b279463d5a8d6d61a6589bb4b99bbccc3c0cd288ec5826e42821326aa29d1ab0af3f344ff3a1c4e25ad6fe22e55786685f6266a2f57a771c33404829fbac39b5810fb52e3534070c08dcdb7be744cbde3cde979f9d79ecb9f155ecf3c4975bbc5935486f14";  // NOLINT

const AdaptorSignature adaptor_sig2(
    "032c637cd797dd8c2ce261907ed43e82d6d1a48cbabbbece801133dd8d70a01b1403eb615a3e59b1cbbf4f87acaf645be1eda32a066611f35dd5557802802b14b19c81c04c3fefac5783b2077bd43fa0a39ab8a64d4d78332a5d621ea23eca46bc011011ab82dda6deb85699f508744d70d4134bea03f784d285b5c6c15a56e4e1fab4bc356abbdebb3b8fe1e55e6dd6d2a9ea457e91b2e6642fae69f9dbb5258854");  // NOLINT
// unnormalize signature
const ByteData compact_sig("2c637cd797dd8c2ce261907ed43e82d6d1a48cbabbbece801133dd8d70a01b14b5f24321f550b7b9dd06ee4fcfd82bdad8b142ff93a790cc4d9f7962b38c6a3b");  // NOLINT
const Privkey secret(
    "324719b51ff2474c9438eb76494b0dc0bcceeb529f0a5428fd198ad8f886e99c");
const Pubkey adaptor(
    "02042537e913ad74c4bbd8da9607ad3b9cb297d08e014afc51133083f1bd687a62");

TEST(AdaptorSignature, Encrypt) {
  auto adaptor_sig = AdaptorSignature::Encrypt(msg, sk, adaptor);

  EXPECT_EQ(adaptor_sig_str, adaptor_sig.GetData().GetHex());
  EXPECT_TRUE(adaptor_sig.Verify(msg, sk.GetPubkey(), adaptor));
}

TEST(AdaptorSignature, Verify) {
  AdaptorSignature adaptor_sig("03424d14a5471c048ab87b3b83f6085d125d5864249ae4297a57c84e74710bb6730223f325042fce535d040fee52ec13231bf709ccd84233c6944b90317e62528b2527dff9d659a96db4c99f9750168308633c1867b70f3a18fb0f4539a1aecedcd1fc0148fc22f36b6303083ece3f872b18e35d368b3958efe5fb081f7716736ccb598d269aa3084d57e1855e1ea9a45efc10463bbf32ae378029f5763ceb40173f");  // NOLINT

  EXPECT_TRUE(
      adaptor_sig.Verify(
          ByteData256("8131e6f4b45754f2c90bd06688ceeabc0c45055460729928b4eecf11026a9e2d"),  // NOLINT
          Pubkey("035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c"),  // NOLINT
          Pubkey("02c2662c97488b07b6e819124b8989849206334a4c2fbdf691f7b34d2b16e9c293")));  // NOLINT
}

TEST(AdaptorSignature, Decrypt) {
  auto sig = adaptor_sig2.Decrypt(secret);

  auto normalized_compact_sig = CryptoUtil::NormalizeSignature(compact_sig);
  EXPECT_EQ(normalized_compact_sig.GetHex(), sig.GetHex());
}

TEST(AdaptorSignature, Recover) {
  auto sec = adaptor_sig2.Recover(compact_sig, adaptor);

  EXPECT_EQ(secret.GetHex(), sec.GetHex());
}

TEST(AdaptorSignature, Copy) {
  AdaptorSignature sig(adaptor_sig2);
  AdaptorSignature sig2;
  sig2 = adaptor_sig2;

  EXPECT_EQ(adaptor_sig2.GetData().GetHex(), sig.GetData().GetHex());
  EXPECT_EQ(adaptor_sig2.GetData().GetHex(), sig2.GetData().GetHex());
}
