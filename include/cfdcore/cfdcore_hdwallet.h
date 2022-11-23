// Copyright 2020 CryptoGarage
/**
 * @file cfdcore_hdwallet.h
 *
 * @brief definition for BIP32/BIP39/BIP44 class.
 */
#ifndef CFD_CORE_INCLUDE_CFDCORE_CFDCORE_HDWALLET_H_
#define CFD_CORE_INCLUDE_CFDCORE_CFDCORE_HDWALLET_H_

#include <string>
#include <vector>

#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_key.h"

namespace cfd {
namespace core {

class Extkey;
class ExtPrivkey;
class ExtPubkey;
class KeyData;

/**
 * @brief A data class that represents an HD Wallet.
 */
class CFD_CORE_EXPORT HDWallet {
 public:
  /**
   * @brief seed byte size (128bit)
   */
  static constexpr uint32_t kSeed128Size = 16;
  /**
   * @brief seed byte size (256bit)
   */
  static constexpr uint32_t kSeed256Size = 32;
  /**
   * @brief seed byte size (512bit)
   */
  static constexpr uint32_t kSeed512Size = 64;

  /**
   * @brief constructor.
   */
  HDWallet();

  /**
   * @brief constructor.
   * @param[in] seed  seed
   */
  explicit HDWallet(const ByteData& seed);

  /**
   * @brief constructor.
   * @param[in] mnemonic                mnemonic
   * @param[in] passphrase              passphrase
   * @param[in] use_ideographic_space   ideographic space use flag. (default: false)
   */
  HDWallet(
      std::vector<std::string> mnemonic, std::string passphrase,
      bool use_ideographic_space = false);

  /**
   * @brief Get seed value.
   * @return seed
   */
  ByteData GetSeed() const;

  /**
   * @brief Generate an extended privkey.
   * @param[in] network_type      network type
   * @param[in] format_type       format type
   * @return extended privkey
   * @throws CfdException If invalid seed.
   */
  ExtPrivkey GeneratePrivkey(
      NetType network_type,
      Bip32FormatType format_type = Bip32FormatType::kNormal) const;
  /**
   * @brief Generate an extended privkey.
   * @param[in] network_type      network type
   * @param[in] child_num         child number
   * @param[in] format_type       format type
   * @return extended privkey
   * @throws CfdException If invalid seed.
   */
  ExtPrivkey GeneratePrivkey(
      NetType network_type, uint32_t child_num,
      Bip32FormatType format_type = Bip32FormatType::kNormal) const;
  /**
   * @brief Generate an extended privkey.
   * @param[in] network_type      network type
   * @param[in] path              child number path
   * @param[in] format_type       format type
   * @return extended privkey
   * @throws CfdException If invalid seed.
   */
  ExtPrivkey GeneratePrivkey(
      NetType network_type, const std::vector<uint32_t>& path,
      Bip32FormatType format_type = Bip32FormatType::kNormal) const;
  /**
   * @brief Generate an extended privkey.
   * @param[in] network_type      network type
   * @param[in] string_path       child number string path
   * @param[in] format_type       format type
   * @return extended privkey
   * @throws CfdException If invalid seed.
   */
  ExtPrivkey GeneratePrivkey(
      NetType network_type, const std::string& string_path,
      Bip32FormatType format_type = Bip32FormatType::kNormal) const;

  /**
   * @brief Generate an extended privkey data.
   * @param[in] network_type      network type
   * @param[in] path              child number path
   * @param[in] format_type       format type
   * @return extended privkey
   * @throws CfdException If invalid seed.
   */
  KeyData GeneratePrivkeyData(
      NetType network_type, const std::vector<uint32_t>& path,
      Bip32FormatType format_type = Bip32FormatType::kNormal) const;
  /**
   * @brief Generate an extended privkey data.
   * @param[in] network_type      network type
   * @param[in] string_path       child number string path
   * @param[in] format_type       format type
   * @return extended privkey
   * @throws CfdException If invalid seed.
   */
  KeyData GeneratePrivkeyData(
      NetType network_type, const std::string& string_path,
      Bip32FormatType format_type = Bip32FormatType::kNormal) const;

  /**
   * @brief Generate an extended pubkey.
   * @param[in] network_type      network type
   * @param[in] format_type       format type
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey GeneratePubkey(
      NetType network_type,
      Bip32FormatType format_type = Bip32FormatType::kNormal) const;
  /**
   * @brief Generate an extended pubkey.
   * @param[in] network_type      network type
   * @param[in] child_num         child number
   * @param[in] format_type       format type
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey GeneratePubkey(
      NetType network_type, uint32_t child_num,
      Bip32FormatType format_type = Bip32FormatType::kNormal) const;
  /**
   * @brief Generate an extended pubkey.
   * @param[in] network_type      network type
   * @param[in] path              child number path
   * @param[in] format_type       format type
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey GeneratePubkey(
      NetType network_type, const std::vector<uint32_t>& path,
      Bip32FormatType format_type = Bip32FormatType::kNormal) const;
  /**
   * @brief Generate an extended pubkey.
   * @param[in] network_type      network type
   * @param[in] string_path       child number string path
   * @param[in] format_type       format type
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey GeneratePubkey(
      NetType network_type, const std::string& string_path,
      Bip32FormatType format_type = Bip32FormatType::kNormal) const;

  /**
   * @brief Generate an extended pubkey data.
   * @param[in] network_type      network type
   * @param[in] path              child number path
   * @param[in] format_type       format type
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  KeyData GeneratePubkeyData(
      NetType network_type, const std::vector<uint32_t>& path,
      Bip32FormatType format_type = Bip32FormatType::kNormal) const;
  /**
   * @brief Generate an extended pubkey data.
   * @param[in] network_type      network type
   * @param[in] string_path       child number string path
   * @param[in] format_type       format type
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  KeyData GeneratePubkeyData(
      NetType network_type, const std::string& string_path,
      Bip32FormatType format_type = Bip32FormatType::kNormal) const;

  /**
   * @brief Get the Wordlist available in Mnemonic.
   * @param[in] language  language to Wordlist
   * @return Wordlist vector
   * @throws CfdException If invalid language passed.
   */
  static std::vector<std::string> GetMnemonicWordlist(
      const std::string& language);

  /**
   * @brief Get the Wordlist available in Mnemonic.
   * @param[in] entropy     Entropy value for Mnemonic generation
   * @param[in] language    language to mnemonic
   * @return mnemonic vector
   * @throws CfdException If invalid language passed.
   */
  static std::vector<std::string> ConvertEntropyToMnemonic(
      const ByteData& entropy, const std::string& language);

  /**
   * @brief Convert from Mnemonic to Entropy.
   * @param[in] mnemonic  mnemonic vector
   * @param[in] language  language to mnemonic
   * @return entropy data
   * @throws CfdException If invalid language passed.
   */
  static ByteData ConvertMnemonicToEntropy(
      const std::vector<std::string>& mnemonic, const std::string& language);

  /**
   * @brief Verify mnemonic is valid
   * @param[in] mnemonic                mnemonic vector to check valid
   * @param[in] language                language to verify
   * @retval true   mnemonic checksum is valid
   * @retval false  mnemonic checksum is invalid
   */
  static bool CheckValidMnemonic(
      const std::vector<std::string>& mnemonic, const std::string& language);

 private:
  ByteData seed_;  //!< seed

  /**
   * @brief Determine if the language is supported by Mnemonic.
   * @param[in] language  language used by mnemonic.
   * @retval true   If language is supported.
   * @retval false  If language is not supported.
   */
  static bool CheckSupportedLanguages(const std::string& language);

  /**
   * @brief Generate seed from mnemonic and passphrase.
   * @param[in] mnemonic                mnemonic vector
   * @param[in] passphrase              passphrase
   * @param[in] use_ideographic_space   Flag to separate with double-byte space
   * @return seed
   */
  static ByteData ConvertMnemonicToSeed(
      const std::vector<std::string>& mnemonic, const std::string& passphrase,
      bool use_ideographic_space = false);
};

/**
 * @brief extended key base class.
 */
class CFD_CORE_EXPORT Extkey {
 public:
  /**
   * @brief bip32 serialize size
   */
  static constexpr uint32_t kSerializeSize = 78;
  /**
   * @brief hardened key definition
   */
  static constexpr uint32_t kHardenedKey = 0x80000000;

  /**
   * @brief create from privkey.
   * @param[in] version             extkey version
   * @param[in] parent_fingerprint  parent fingerprint(4byte)
   * @param[in] privkey             privkey
   * @param[in] chain_code          chain code
   * @param[in] depth               depth
   * @param[in] child_num           child num
   * @param[in] tweak_sum           tweak sum
   * @return Extkey object.
   */
  static Extkey FromPrivkey(
      uint32_t version, const ByteData& parent_fingerprint,
      const Privkey& privkey, const ByteData256& chain_code, uint8_t depth,
      uint32_t child_num, ByteData256 tweak_sum = ByteData256());
  /**
   * @brief create from pubkey.
   * @param[in] version             extkey version
   * @param[in] parent_fingerprint  parent fingerprint(4byte)
   * @param[in] pubkey              pubkey
   * @param[in] chain_code          chain code
   * @param[in] depth               depth
   * @param[in] child_num           child num
   * @param[in] tweak_sum           tweak sum
   * @return Extkey object.
   */
  static Extkey FromPubkey(
      uint32_t version, const ByteData& parent_fingerprint,
      const Pubkey& pubkey, const ByteData256& chain_code, uint8_t depth,
      uint32_t child_num, ByteData256 tweak_sum = ByteData256());

  /**
   * @brief constructor.
   */
  Extkey();
  /**
   * @brief constructor.
   * @param[in] seed          seed byte
   * @param[in] network_type  network type
   * @param[in] format_type   format type
   */
  explicit Extkey(
      const ByteData& seed, NetType network_type,
      Bip32FormatType format_type = Bip32FormatType::kNormal);
  /**
   * @brief constructor.
   * @param[in] seed            seed byte
   * @param[in] version         extkey version
   */
  explicit Extkey(const ByteData& seed, uint32_t version);
  /**
   * @brief constructor.
   * @param[in] serialize_data  serialize data
   */
  explicit Extkey(const ByteData& serialize_data);
  /**
   * @brief constructor.
   * @param[in] serialize_data  serialize data
   * @param[in] tweak_sum       tweak sum
   */
  explicit Extkey(
      const ByteData& serialize_data, const ByteData256& tweak_sum);
  /**
   * @brief constructor.
   * @param[in] base58_data  base58 data
   */
  explicit Extkey(const std::string& base58_data);
  /**
   * @brief constructor.
   * @param[in] base58_data  base58 data
   * @param[in] tweak_sum    tweak sum
   */
  explicit Extkey(
      const std::string& base58_data, const ByteData256& tweak_sum);

  /**
   * @brief Get Serialize information of extension key.
   * @return serialize data
   */
  ByteData GetData() const;
  /**
   * @brief Get the Base58 string of the extended key.
   * @return base58 string
   */
  std::string ToString() const;

  /**
   * @brief Derive the extended key.
   * @param[in] child_num       child number.
   * @return derived extended key.
   */
  Extkey Derive(uint32_t child_num) const;
  /**
   * @brief Derive the extended key.
   * @param[in] path    child number list.
   * @return derived extended key.
   */
  Extkey Derive(const std::vector<uint32_t>& path) const;
  /**
   * @brief Derive the extended key.
   * @param[in] string_path    child number path.
   * @return derived extended key.
   */
  Extkey Derive(const std::string& string_path) const;
  /**
   * @brief Convert to the extended public key.
   * @return extended key.
   */
  Extkey ToPubkey() const;

  /**
   * @brief Get the related pubkey address.
   * @details This function is returns the Bip32FormatType or P2WPKH address.
   * @param[in] address_type        address type (auto is witnessUnknown)
   * @param[in] network_parameters  network parameter. (nullptr is bitcoin)
   * @param[in] net_type            network type (auto is kCustomChain)
   * @return address.
   */
  Address GetPubkeyAddress(
      AddressType address_type = AddressType::kWitnessUnknown,
      const std::vector<AddressFormatData>* network_parameters = nullptr,
      NetType net_type = NetType::kCustomChain);
  /**
   * @brief Get related pubkey address list.
   * @details If the Bip32FormatType isn't Normal, return the target type only.
   * @param[in] network_parameters  network parameter. (nullptr is bitcoin)
   * @param[in] net_type            network type (auto is kCustomChain)
   * @return address list.
   */
  std::vector<Address> GetPubkeyAddresses(
      const std::vector<AddressFormatData>* network_parameters = nullptr,
      NetType net_type = NetType::kCustomChain);

  /**
   * @brief Check if the data format is correct.
   * @retval true  valid
   * @retval false invalid
   */
  bool IsValid() const;

  /**
   * @brief Check if the data format is extended private key.
   * @retval true   private key
   * @retval false  public key
   */
  bool HasPrivkey() const;

  /**
   * @brief Get depth.
   * @return depth value
   */
  uint8_t GetDepth() const;
  /**
   * @brief Get veresion.
   * @return version data (4byte)
   */
  uint32_t GetVersion() const;
  /**
   * @brief Get veresion.
   * @return version data (4byte)
   */
  ByteData GetVersionData() const;
  /**
   * @brief Get child number.
   * @return child number (4byte)
   */
  uint32_t GetChildNum() const;
  /**
   * @brief Get chain code.
   * @return chain code (32byte)
   */
  ByteData256 GetChainCode() const;
  /**
   * @brief Get fingerprint.
   * @return fingerprint data (4byte)
   */
  uint32_t GetFingerprint() const;
  /**
   * @brief Get fingerprint.
   * @return fingerprint data (4byte)
   */
  ByteData GetFingerprintData() const;

  /**
   * @brief Get pubkey.
   * @return Pubkey
   */
  Pubkey GetPubkey() const;
  /**
   * @brief Get privkey.
   * @return Privkey
   */
  Privkey GetPrivkey() const;
  /**
   * @brief Get the composite value of the tweak value generated in the process of generating the derived Pubkey.
   * @return tweak sum
   */
  ByteData256 GetPubTweakSum() const;
  /**
   * @brief Get network type.
   * @return network type.
   */
  NetType GetNetworkType() const;
  /**
   * @brief Has mainnet key.
   * @retval true   mainnet
   * @retval flse   testnet
   */
  bool HasMainnetKey() const;
  /**
   * @brief Get bip32 format type.
   * @return bip32 format type.
   */
  Bip32FormatType GetFormatType() const;

 protected:
  uint32_t version_ = 0;    //!< version
  ByteData fingerprint_;    //!< finger print
  uint8_t depth_ = 0;       //!< depth
  uint32_t child_num_ = 0;  //!< child number
  ByteData256 chaincode_;   //!< chain code
  Privkey privkey_;         //!< private key
  Pubkey pubkey_;           //!< public key
  ByteData256 tweak_sum_;   //!< tweak sum
};

/**
 * @brief A data class that represents an extended private key.
 */
class CFD_CORE_EXPORT ExtPrivkey : public Extkey {
 public:
  /**
   * @brief mainnet privkey version
   */
  static constexpr uint32_t kVersionMainnetPrivkey = 0x0488ade4;
  /**
   * @brief testnet privkey version
   */
  static constexpr uint32_t kVersionTestnetPrivkey = 0x04358394;

  /**
   * @brief constructor.
   */
  ExtPrivkey();
  /**
   * @brief constructor.
   * @param[in] seed          seed byte
   * @param[in] network_type  network type
   * @param[in] format_type   format type
   */
  explicit ExtPrivkey(
      const ByteData& seed, NetType network_type,
      Bip32FormatType format_type = Bip32FormatType::kNormal);
  /**
   * @brief constructor.
   * @param[in] serialize_data  serialize data
   */
  explicit ExtPrivkey(const ByteData& serialize_data);
  /**
   * @brief constructor.
   * @param[in] serialize_data  serialize data
   * @param[in] tweak_sum       tweak sum
   */
  explicit ExtPrivkey(
      const ByteData& serialize_data, const ByteData256& tweak_sum);
  /**
   * @brief constructor.
   * @param[in] base58_data  base58 data
   */
  explicit ExtPrivkey(const std::string& base58_data);
  /**
   * @brief constructor.
   * @param[in] base58_data  base58 data
   * @param[in] tweak_sum    tweak sum
   */
  explicit ExtPrivkey(
      const std::string& base58_data, const ByteData256& tweak_sum);
  /**
   * @brief constructor.
   * @param[in] network_type       network type
   * @param[in] parent_key         parent privkey
   * @param[in] parent_chain_code  parent chain code
   * @param[in] parent_depth       parent depth
   * @param[in] child_num          child num
   * @param[in] format_type        format type
   */
  explicit ExtPrivkey(
      NetType network_type, const Privkey& parent_key,
      const ByteData256& parent_chain_code, uint8_t parent_depth,
      uint32_t child_num,
      Bip32FormatType format_type = Bip32FormatType::kNormal);
  /**
   * @brief constructor.
   * @param[in] network_type  network type
   * @param[in] parent_key    parent privkey
   * @param[in] privkey       privkey
   * @param[in] chain_code    chain code
   * @param[in] depth         depth
   * @param[in] child_num     child num
   * @param[in] format_type   format type
   */
  explicit ExtPrivkey(
      NetType network_type, const Privkey& parent_key, const Privkey& privkey,
      const ByteData256& chain_code, uint8_t depth, uint32_t child_num,
      Bip32FormatType format_type = Bip32FormatType::kNormal);
  /**
   * @brief constructor.
   * @param[in] network_type        network type
   * @param[in] parent_fingerprint  parent fingerprint(4byte)
   * @param[in] privkey             privkey
   * @param[in] chain_code          chain code
   * @param[in] depth               depth
   * @param[in] child_num           child num
   * @param[in] format_type         format type
   */
  explicit ExtPrivkey(
      NetType network_type, const ByteData& parent_fingerprint,
      const Privkey& privkey, const ByteData256& chain_code, uint8_t depth,
      uint32_t child_num,
      Bip32FormatType format_type = Bip32FormatType::kNormal);

  /**
   * @brief copy constructor.
   * @param[in] key_data    extkey data
   */
  explicit ExtPrivkey(const Extkey& key_data);

  /**
   * @brief Get a privkey.
   * @return Privkey
   */
  using Extkey::GetPrivkey;

  /**
   * @brief Check if the data format is correct.
   * @retval true  valid
   * @retval false invalid
   */
  bool IsValid() const;

  /**
   * @brief Acquires the extended private key of the specified hierarchy.
   * @param[in] child_num         child number
   * @return extended pubprivkeykey
   * @throws CfdException If invalid seed.
   */
  ExtPrivkey DerivePrivkey(uint32_t child_num) const;
  /**
   * @brief Acquires the extended private key of the specified hierarchy.
   * @param[in] path              child number path
   * @return extended privkey
   * @throws CfdException If invalid seed.
   */
  ExtPrivkey DerivePrivkey(const std::vector<uint32_t>& path) const;
  /**
   * @brief Acquires the extended private key of the specified hierarchy.
   * @param[in] string_path     child number string path
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPrivkey DerivePrivkey(const std::string& string_path) const;

  /**
   * @brief Derive extended privkey.
   * @param[in] path              child number path
   * @return extended privkey
   * @throws CfdException If invalid seed.
   */
  KeyData DerivePrivkeyData(const std::vector<uint32_t>& path) const;
  /**
   * @brief Derive ext-privkey.
   * @param[in] string_path       child number string path
   * @return extended privkey
   * @throws CfdException If invalid seed.
   */
  KeyData DerivePrivkeyData(const std::string& string_path) const;

  /**
   * @brief Obtain the extended public key of the same layer.
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey GetExtPubkey() const;
  /**
   * @brief Obtain the extended public key of the specified hierarchy.
   * @param[in] child_num         child number
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey DerivePubkey(uint32_t child_num) const;
  /**
   * @brief Obtain the extended public key of the specified hierarchy.
   * @param[in] path              child number path
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey DerivePubkey(const std::vector<uint32_t>& path) const;
  /**
   * @brief Obtain the extended public key of the specified hierarchy.
   * @param[in] string_path     child number string path
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey DerivePubkey(const std::string& string_path) const;

  /**
   * @brief Derive ext-pubkey.
   * @param[in] path              child number path
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  KeyData DerivePubkeyData(const std::vector<uint32_t>& path) const;
  /**
   * @brief Derive extended pubkey.
   * @param[in] string_path       child number string path
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  KeyData DerivePubkeyData(const std::string& string_path) const;
};

/**
 * @brief A data class that represents an extended public key.
 */
class CFD_CORE_EXPORT ExtPubkey : public Extkey {
 public:
  /**
   * @brief mainnet pubkey version
   */
  static constexpr uint32_t kVersionMainnetPubkey = 0x0488b21e;
  /**
   * @brief testnet pubkey version
   */
  static constexpr uint32_t kVersionTestnetPubkey = 0x043587cf;

  /**
   * @brief constructor.
   */
  ExtPubkey();
  /**
   * @brief constructor.
   * @param[in] serialize_data  serialize data
   */
  explicit ExtPubkey(const ByteData& serialize_data);
  /**
   * @brief constructor.
   * @param[in] serialize_data  serialize data
   * @param[in] tweak_sum       tweak sum
   */
  explicit ExtPubkey(
      const ByteData& serialize_data, const ByteData256& tweak_sum);
  /**
   * @brief constructor.
   * @param[in] base58_data  base58 data
   */
  explicit ExtPubkey(const std::string& base58_data);
  /**
   * @brief constructor.
   * @param[in] base58_data  base58 data
   * @param[in] tweak_sum    tweak sum
   */
  explicit ExtPubkey(
      const std::string& base58_data, const ByteData256& tweak_sum);
  /**
   * @brief constructor.
   * @param[in] network_type       network type
   * @param[in] parent_key         parent pubkey
   * @param[in] parent_chain_code  parent chain code
   * @param[in] parent_depth       parent depth
   * @param[in] child_num          child num
   * @param[in] format_type        format type
   */
  explicit ExtPubkey(
      NetType network_type, const Pubkey& parent_key,
      const ByteData256& parent_chain_code, uint8_t parent_depth,
      uint32_t child_num,
      Bip32FormatType format_type = Bip32FormatType::kNormal);
  /**
   * @brief constructor.
   * @param[in] network_type  network type
   * @param[in] parent_key    parent pubkey
   * @param[in] pubkey        pubkey
   * @param[in] chain_code    chain code
   * @param[in] depth         depth
   * @param[in] child_num     child num
   * @param[in] format_type   format type
   */
  explicit ExtPubkey(
      NetType network_type, const Pubkey& parent_key, const Pubkey& pubkey,
      const ByteData256& chain_code, uint8_t depth, uint32_t child_num,
      Bip32FormatType format_type = Bip32FormatType::kNormal);
  /**
   * @brief constructor.
   * @param[in] network_type        network type
   * @param[in] parent_fingerprint  parent fingerprint(4byte)
   * @param[in] pubkey              pubkey
   * @param[in] chain_code          chain code
   * @param[in] depth               depth
   * @param[in] child_num           child num
   * @param[in] format_type         format type
   */
  explicit ExtPubkey(
      NetType network_type, const ByteData& parent_fingerprint,
      const Pubkey& pubkey, const ByteData256& chain_code, uint8_t depth,
      uint32_t child_num,
      Bip32FormatType format_type = Bip32FormatType::kNormal);

  /**
   * @brief copy constructor.
   * @param[in] key_data    extkey data
   */
  explicit ExtPubkey(const Extkey& key_data);

  /**
   * @brief Get pubkey.
   * @return Pubkey
   */
  using Extkey::GetPubkey;
  /**
   * @brief Obtain the extended public key of the specified hierarchy.
   * @param[in] child_num         child number
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey DerivePubkey(uint32_t child_num) const;
  /**
   * @brief Obtain the extended public key of the specified hierarchy.
   * @param[in] path              child number path
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey DerivePubkey(const std::vector<uint32_t>& path) const;
  /**
   * @brief Obtain the extended public key of the specified hierarchy.
   * @param[in] string_path     child number string path
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  ExtPubkey DerivePubkey(const std::string& string_path) const;

  /**
   * @brief Derive extended pubkey.
   * @param[in] path              child number path
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  KeyData DerivePubkeyData(const std::vector<uint32_t>& path) const;
  /**
   * @brief Derive extended pubkey.
   * @param[in] string_path       child number string path
   * @return extended pubkey
   * @throws CfdException If invalid seed.
   */
  KeyData DerivePubkeyData(const std::string& string_path) const;

  /**
   * @brief Get the tweak value generated in the process of generating the derived Pubkey.
   * @param[in] path    child number path
   * @return tweak sum
   */
  ByteData256 DerivePubTweak(const std::vector<uint32_t>& path) const;
  /**
   * @brief Get the composite value of the tweak value generated in the process of generating the derived Pubkey.
   * @return tweak sum
   */
  using Extkey::GetPubTweakSum;
};

/**
 * @brief hardened string type.
 */
enum HardenedType {
  kApostrophe = 0,  //!< apostrophe
  kLargeH = 1,      //!< 'H'
  kSmallH = 2,      //!< 'h'
  kNumber = 3,      //!< number only (0x80000000)
};

/**
 * @brief key and bip32 path information class.
 */
class CFD_CORE_EXPORT KeyData {
 public:
  /**
   * @brief constructor.
   */
  KeyData();
  /**
   * @brief Get key text information from ext-privkey.
   * @param[in] ext_privkey  privkey
   * @param[in] child_path   bip32 path for child.
   * @param[in] finterprint     master-pubkey fingerprint
   */
  explicit KeyData(
      const ExtPrivkey& ext_privkey, const std::string& child_path,
      const ByteData& finterprint);
  /**
   * @brief Get key text information from ext-pubkey.
   * @param[in] ext_pubkey   pubkey
   * @param[in] child_path   bip32 path for child.
   * @param[in] finterprint     master-pubkey fingerprint
   */
  explicit KeyData(
      const ExtPubkey& ext_pubkey, const std::string& child_path,
      const ByteData& finterprint);
  /**
   * @brief Get key text information from privkey.
   * @param[in] privkey   privkey
   * @param[in] child_path   bip32 path for child.
   * @param[in] finterprint     master-pubkey fingerprint
   */
  explicit KeyData(
      const Privkey& privkey, const std::string& child_path,
      const ByteData& finterprint);
  /**
   * @brief Get key text information from pubkey.
   * @param[in] pubkey   pubkey
   * @param[in] child_path   bip32 path for child.
   * @param[in] finterprint     master-pubkey fingerprint
   */
  explicit KeyData(
      const Pubkey& pubkey, const std::string& child_path,
      const ByteData& finterprint);
  /**
   * @brief Get key text information from ext-privkey.
   * @param[in] ext_privkey  privkey
   * @param[in] child_num_list   bip32 path for child.
   * @param[in] finterprint     master-pubkey fingerprint
   */
  explicit KeyData(
      const ExtPrivkey& ext_privkey,
      const std::vector<uint32_t>& child_num_list,
      const ByteData& finterprint);
  /**
   * @brief Get key text information from ext-pubkey.
   * @param[in] ext_pubkey   pubkey
   * @param[in] child_num_list   bip32 path for child.
   * @param[in] finterprint     master-pubkey fingerprint
   */
  explicit KeyData(
      const ExtPubkey& ext_pubkey, const std::vector<uint32_t>& child_num_list,
      const ByteData& finterprint);
  /**
   * @brief Get key text information from privkey.
   * @param[in] privkey   privkey
   * @param[in] child_num_list   bip32 path for child.
   * @param[in] finterprint     master-pubkey fingerprint
   */
  explicit KeyData(
      const Privkey& privkey, const std::vector<uint32_t>& child_num_list,
      const ByteData& finterprint);
  /**
   * @brief Get key text information from pubkey.
   * @param[in] pubkey   pubkey
   * @param[in] child_num_list   bip32 path for child.
   * @param[in] finterprint     master-pubkey fingerprint
   */
  explicit KeyData(
      const Pubkey& pubkey, const std::vector<uint32_t>& child_num_list,
      const ByteData& finterprint);
  /**
   * @brief Get key text information from string.
   * @param[in] path_info   key-path info.
   * @param[in] child_num   child number to use if an asterisk is used.
   * @param[in] has_schnorr_pubkey   schnorr(xonly) pubkey used.
   */
  explicit KeyData(
      const std::string& path_info, int32_t child_num = -1,
      bool has_schnorr_pubkey = false);

  /**
   * @brief exist ext-privkey.
   * @retval true  exist
   * @retval false not exist
   */
  bool HasExtPrivkey() const;
  /**
   * @brief exist ext-pubkey.
   * @retval true  exist
   * @retval false not exist
   */
  bool HasExtPubkey() const;
  /**
   * @brief exist privkey.
   * @retval true  exist
   * @retval false not exist
   */
  bool HasPrivkey() const;
  /**
   * @brief getting pubkey.
   * @return pubkey
   */
  Pubkey GetPubkey() const;
  /**
   * @brief getting privkey.
   * @return privkey
   */
  Privkey GetPrivkey() const;
  /**
   * @brief getting ext-privkey.
   * @details need ext-privkey exists.
   * @return ext-privkey
   */
  ExtPrivkey GetExtPrivkey() const;
  /**
   * @brief getting ext-pubkey.
   * @details need ext-pubkey exists.
   * @return ext-pubkey
   */
  ExtPubkey GetExtPubkey() const;

  /**
   * @brief Derive ext-privkey.
   * @param[in] path  path
   * @param[in] has_rebase_path  rebase path/fingerprint base
   * @return path info with ext-privkey.
   */
  KeyData DerivePrivkey(
      std::vector<uint32_t> path, bool has_rebase_path) const;
  /**
   * @brief Derive ext-privkey.
   * @param[in] path  path
   * @param[in] has_rebase_path  rebase path/fingerprint base
   * @return path info with ext-privkey.
   */
  KeyData DerivePrivkey(std::string path, bool has_rebase_path) const;
  /**
   * @brief Derive ext-pubkey.
   * @param[in] path  path
   * @param[in] has_rebase_path  rebase path/fingerprint base
   * @return path info with ext-pubkey.
   */
  KeyData DerivePubkey(std::vector<uint32_t> path, bool has_rebase_path) const;
  /**
   * @brief Derive ext-pubkey.
   * @param[in] path  path
   * @param[in] has_rebase_path  rebase path/fingerprint base
   * @return path info with ext-pubkey.
   */
  KeyData DerivePubkey(std::string path, bool has_rebase_path) const;

  /**
   * @brief getting bip32 path.
   * @param[in] hardened_type  hardened string type
   * @param[in] has_hex  using hex string
   * @return bip32 path
   */
  std::string GetBip32Path(
      HardenedType hardened_type = HardenedType::kApostrophe,
      bool has_hex = false) const;
  /**
   * @brief get message string.
   * @param[in] has_pubkey  displays the pubkey string.
   * @param[in] hardened_type  hardened string type
   * @param[in] has_hex  using hex string
   * @return message string.
   */
  std::string ToString(
      bool has_pubkey = true,
      HardenedType hardened_type = HardenedType::kApostrophe,
      bool has_hex = false) const;
  /**
   * @brief get fingerprint.
   * @return fingerprint.
   */
  ByteData GetFingerprint() const;
  /**
   * @brief get child number array.
   * @return child number array.
   */
  std::vector<uint32_t> GetChildNumArray() const;
  /**
   * @brief check valid.
   * @retval true   valid
   * @retval false  invalid
   */
  bool IsValid() const;

 private:
  Pubkey pubkey_;               //!< pubkey
  Privkey privkey_;             //!< privkey
  ExtPrivkey extprivkey_;       //!< ext privkey
  ExtPubkey extpubkey_;         //!< ext pubkey
  std::vector<uint32_t> path_;  //!< bip32 path
  ByteData fingerprint_;        //!< fingerprint by key string
};

}  // namespace core
}  // namespace cfd

#endif  // CFD_CORE_INCLUDE_CFDCORE_CFDCORE_HDWALLET_H_
