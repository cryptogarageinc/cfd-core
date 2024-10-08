// Copyright 2019 CryptoGarage
/**
 * @file cfdcore_descriptor.cpp
 *
 * @brief implemations of related to Output Descriptor
 */
#include "cfdcore/cfdcore_descriptor.h"

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_elements_address.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_util.h"
#include "cfdcore_wally_util.h"  // NOLINT

namespace cfd {
namespace core {

using logger::info;
using logger::warn;

/**
 * @brief Struct for DescriptorNode Script type management table.
 */
struct DescriptorNodeScriptData {
  std::string name;           //!< Name
  DescriptorScriptType type;  //!< Script type
  bool top_only;              //!< exist top only
  bool has_child;             //!< can exist child
  bool multisig;              //!< use multisig
};

/**
 * @brief Struct for DescriptorNode Script type management table.
 */
static const DescriptorNodeScriptData kDescriptorNodeScriptTable[] = {
    {"sh", DescriptorScriptType::kDescriptorScriptSh, true, true, false},
    {"combo", DescriptorScriptType::kDescriptorScriptCombo, true, true, false},
    {"wsh", DescriptorScriptType::kDescriptorScriptWsh, false, true, false},
    {"pk", DescriptorScriptType::kDescriptorScriptPk, false, true, false},
    {"pkh", DescriptorScriptType::kDescriptorScriptPkh, false, true, false},
    {"wpkh", DescriptorScriptType::kDescriptorScriptWpkh, false, true, false},
    {"multi", DescriptorScriptType::kDescriptorScriptMulti, false, true, true},
    {"sortedmulti", DescriptorScriptType::kDescriptorScriptSortedMulti, false,
     true, true},
    {"addr", DescriptorScriptType::kDescriptorScriptAddr, true, false, false},
    {"raw", DescriptorScriptType::kDescriptorScriptRaw, true, false, false},
    {"tr", DescriptorScriptType::kDescriptorScriptTaproot, true, true, false},
};

// -----------------------------------------------------------------------------
// DescriptorKeyInfo
// -----------------------------------------------------------------------------
std::string DescriptorKeyInfo::GetExtPrivkeyInformation(
    const ExtPrivkey& ext_privkey, const std::string& child_path) {
  std::string result;
  if (ext_privkey.IsValid()) {
    result = "[" + ext_privkey.GetFingerprintData().GetHex();
    if (!child_path.empty()) {
      std::string::size_type index = 0;
      if ((child_path[0] == 'm') || (child_path[0] == 'M')) ++index;
      if (child_path[index] != '/') {
        result += "/";
      }
      result += child_path.substr(index);
    }
    result += "]";
  }
  return result;
}

std::string DescriptorKeyInfo::GetExtPubkeyInformation(
    const ExtPubkey& ext_pubkey, const std::string& child_path) {
  std::string result;
  if (ext_pubkey.IsValid()) {
    result = "[" + ext_pubkey.GetFingerprintData().GetHex();
    if (!child_path.empty()) {
      std::string::size_type index = 0;
      if ((child_path[0] == 'm') || (child_path[0] == 'M')) ++index;
      if (child_path[index] != '/') {
        result += "/";
      }
      result += child_path.substr(index);
    }
    result += "]";
  }
  return result;
}

DescriptorKeyInfo::DescriptorKeyInfo()
    : key_type_(DescriptorKeyType::kDescriptorKeyNull) {
  // do nothing
}

DescriptorKeyInfo::DescriptorKeyInfo(
    const std::string& key, const std::string parent_key_information) {
  if (key.size() < 4) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "DescriptorKeyInfo illegal key.");
  }
  // analyze format
  std::string hdkey_top = key.substr(1, 3);
  if ((hdkey_top == "pub") || (hdkey_top == "prv")) {
    std::vector<std::string> list = StringUtil::Split(key, "/");
    for (size_t index = 1; index < list.size(); ++index) {
      path_ += "/" + list[index];
    }
    if (hdkey_top == "prv") {
      key_type_ = DescriptorKeyType::kDescriptorKeyBip32Priv;
      extprivkey_ = ExtPrivkey(list[0]);
    } else {
      key_type_ = DescriptorKeyType::kDescriptorKeyBip32;
      extpubkey_ = ExtPubkey(list[0]);
    }
  } else {
    key_type_ = DescriptorKeyType::kDescriptorKeyPublic;
    bool is_wif = false;
    try {
      // pubkey format check
      ByteData bytes(key);
      if (Pubkey::IsValid(bytes)) {
        // pubkey
        pubkey_ = Pubkey(bytes);
      } else {
        // schnorr pubkey
        SchnorrPubkey schnorr(bytes);
        schnorr_pubkey_ = schnorr;
        key_string_ = schnorr_pubkey_.GetHex();
        key_type_ = DescriptorKeyType::kDescriptorKeySchnorr;
      }
    } catch (const CfdException& except) {
      std::string errmsg(except.what());
      if (Privkey::HasWif(key)) {
        is_wif = true;
      } else {
        throw except;
      }
    }
    if (is_wif) {
      Privkey privkey;
      // privkey WIF check
      try {
        privkey_ = Privkey::FromWif(key, NetType::kMainnet);
      } catch (const CfdException& except) {
        std::string errmsg(except.what());
        if (errmsg.find("Error WIF to Private key.") == std::string::npos) {
          throw except;
        }
      }
      if (!privkey_.IsValid()) {
        privkey_ = Privkey::FromWif(key, NetType::kTestnet);
      }
      key_string_ = privkey_.GetWif();
    }
  }

  if (!parent_key_information.empty()) {
    parent_info_ = parent_key_information;
  }
}

DescriptorKeyInfo::DescriptorKeyInfo(
    const Pubkey& pubkey, const std::string parent_key_information)
    : key_type_(DescriptorKeyType::kDescriptorKeyPublic), pubkey_(pubkey) {
  if (!parent_key_information.empty()) {
    parent_info_ = parent_key_information;
  }
}

DescriptorKeyInfo::DescriptorKeyInfo(
    const SchnorrPubkey& schnorr_pubkey,
    const std::string parent_key_information)
    : key_type_(DescriptorKeyType::kDescriptorKeySchnorr),
      schnorr_pubkey_(schnorr_pubkey) {
  if (!parent_key_information.empty()) {
    parent_info_ = parent_key_information;
  }
}

DescriptorKeyInfo::DescriptorKeyInfo(
    const Privkey& privkey, bool use_wif_parameter, NetType net_type,
    bool is_compressed, const std::string parent_key_information)
    : key_type_(DescriptorKeyType::kDescriptorKeyPublic), privkey_(privkey) {
  if (use_wif_parameter) {
    key_string_ = privkey.ConvertWif(net_type, is_compressed);
  } else {
    key_string_ = privkey.GetWif();
  }
  if (!parent_key_information.empty()) {
    parent_info_ = parent_key_information;
  }
}

DescriptorKeyInfo::DescriptorKeyInfo(
    const ExtPrivkey& ext_privkey, const std::string parent_key_information,
    const std::string path)
    : key_type_(DescriptorKeyType::kDescriptorKeyBip32Priv),
      extprivkey_(ext_privkey) {
  if (!parent_key_information.empty()) {
    parent_info_ = parent_key_information;
  }
  if (!path.empty()) {
    if (path[0] != '/') {
      path_ = "/" + path;
    } else {
      path_ = path;
    }
  }
}

DescriptorKeyInfo::DescriptorKeyInfo(
    const ExtPubkey& ext_pubkey, const std::string parent_key_information,
    const std::string path)
    : key_type_(DescriptorKeyType::kDescriptorKeyBip32),
      extpubkey_(ext_pubkey) {
  if (!parent_key_information.empty()) {
    parent_info_ = parent_key_information;
  }
  if (!path.empty()) {
    if (path[0] != '/') {
      path_ = "/" + path;
    } else {
      path_ = path;
    }
  }
}

DescriptorKeyInfo::DescriptorKeyInfo(const DescriptorKeyInfo& object) {
  key_type_ = object.key_type_;
  pubkey_ = object.pubkey_;
  schnorr_pubkey_ = object.schnorr_pubkey_;
  privkey_ = object.privkey_;
  extprivkey_ = object.extprivkey_;
  extpubkey_ = object.extpubkey_;
  parent_info_ = object.parent_info_;
  path_ = object.path_;
  key_string_ = object.key_string_;
}

DescriptorKeyInfo& DescriptorKeyInfo::operator=(
    const DescriptorKeyInfo& object) {
  if (this != &object) {
    key_type_ = object.key_type_;
    pubkey_ = object.pubkey_;
    schnorr_pubkey_ = object.schnorr_pubkey_;
    privkey_ = object.privkey_;
    extprivkey_ = object.extprivkey_;
    extpubkey_ = object.extpubkey_;
    parent_info_ = object.parent_info_;
    path_ = object.path_;
    key_string_ = object.key_string_;
  }
  return *this;
}

Pubkey DescriptorKeyInfo::GetPubkey() const { return pubkey_; }

SchnorrPubkey DescriptorKeyInfo::GetSchnorrPubkey() const {
  return schnorr_pubkey_;
}

Privkey DescriptorKeyInfo::GetPrivkey() const { return privkey_; }

std::string DescriptorKeyInfo::GetBip32Path() const { return path_; }

ExtPrivkey DescriptorKeyInfo::GetExtPrivkey() const { return extprivkey_; }

ExtPubkey DescriptorKeyInfo::GetExtPubkey() const { return extpubkey_; }

DescriptorKeyType DescriptorKeyInfo::GetKeyType() const { return key_type_; }

bool DescriptorKeyInfo::HasExtPrivkey() const { return extprivkey_.IsValid(); }

bool DescriptorKeyInfo::HasExtPubkey() const { return extpubkey_.IsValid(); }

bool DescriptorKeyInfo::HasPrivkey() const { return privkey_.IsValid(); }

bool DescriptorKeyInfo::HasSchnorrPubkey() const {
  return schnorr_pubkey_.IsValid();
}

std::string DescriptorKeyInfo::ToString() const {
  if (key_type_ == DescriptorKeyType::kDescriptorKeyPublic) {
    if (privkey_.IsValid()) {
      return parent_info_ + key_string_;
    } else {
      return parent_info_ + pubkey_.GetHex();
    }
  } else if (key_type_ == DescriptorKeyType::kDescriptorKeyBip32) {
    return parent_info_ + extpubkey_.ToString() + path_;
  } else if (key_type_ == DescriptorKeyType::kDescriptorKeyBip32Priv) {
    return parent_info_ + extprivkey_.ToString() + path_;
  } else if (key_type_ == DescriptorKeyType::kDescriptorKeySchnorr) {
    return parent_info_ + schnorr_pubkey_.GetHex() + path_;
  } else {
    return "";
  }
}

// -----------------------------------------------------------------------------
// DescriptorKeyReference
// -----------------------------------------------------------------------------
DescriptorKeyReference::DescriptorKeyReference()
    : key_type_(DescriptorKeyType::kDescriptorKeyNull) {}

DescriptorKeyReference::DescriptorKeyReference(const Pubkey& pubkey)
    : key_type_(DescriptorKeyType::kDescriptorKeyPublic), pubkey_(pubkey) {
  schnorr_pubkey_ = SchnorrPubkey::FromPubkey(pubkey_);
}

DescriptorKeyReference::DescriptorKeyReference(
    const SchnorrPubkey& schnorr_pubkey)
    : key_type_(DescriptorKeyType::kDescriptorKeySchnorr),
      schnorr_pubkey_(schnorr_pubkey) {
  pubkey_ = schnorr_pubkey.CreatePubkey();
}

DescriptorKeyReference::DescriptorKeyReference(
    const ExtPrivkey& ext_privkey, const std::string* arg)
    : key_type_(DescriptorKeyType::kDescriptorKeyBip32Priv),
      pubkey_(ext_privkey.GetExtPubkey().GetPubkey()),
      extprivkey_(ext_privkey),
      argument_((arg) ? *arg : "") {
  schnorr_pubkey_ = SchnorrPubkey::FromPubkey(pubkey_);
}

DescriptorKeyReference::DescriptorKeyReference(
    const ExtPubkey& ext_pubkey, const std::string* arg)
    : key_type_(DescriptorKeyType::kDescriptorKeyBip32),
      pubkey_(ext_pubkey.GetPubkey()),
      extpubkey_(ext_pubkey),
      argument_((arg) ? *arg : "") {
  schnorr_pubkey_ = SchnorrPubkey::FromPubkey(pubkey_);
}

DescriptorKeyReference::DescriptorKeyReference(
    const KeyData& key, const std::string* arg)
    : key_type_(DescriptorKeyType::kDescriptorKeyPublic),
      pubkey_(key.GetPubkey()),
      key_data_(key),
      argument_((arg) ? *arg : "") {
  if (key_data_.HasExtPrivkey()) {
    extprivkey_ = key_data_.GetExtPrivkey();
    key_type_ = DescriptorKeyType::kDescriptorKeyBip32Priv;
  } else if (key_data_.HasExtPubkey()) {
    extpubkey_ = key_data_.GetExtPubkey();
    key_type_ = DescriptorKeyType::kDescriptorKeyBip32;
  }
  schnorr_pubkey_ = SchnorrPubkey::FromPubkey(pubkey_);
}

DescriptorKeyReference::DescriptorKeyReference(
    const DescriptorKeyReference& object) {
  key_type_ = object.key_type_;
  pubkey_ = object.pubkey_;
  schnorr_pubkey_ = object.schnorr_pubkey_;
  extprivkey_ = object.extprivkey_;
  extpubkey_ = object.extpubkey_;
  key_data_ = object.key_data_;
  argument_ = object.argument_;
}

DescriptorKeyReference& DescriptorKeyReference::operator=(
    const DescriptorKeyReference& object) {
  if (this != &object) {
    key_type_ = object.key_type_;
    pubkey_ = object.pubkey_;
    schnorr_pubkey_ = object.schnorr_pubkey_;
    extprivkey_ = object.extprivkey_;
    extpubkey_ = object.extpubkey_;
    key_data_ = object.key_data_;
    argument_ = object.argument_;
  }
  return *this;
}

Pubkey DescriptorKeyReference::GetPubkey() const { return pubkey_; }

SchnorrPubkey DescriptorKeyReference::GetSchnorrPubkey() const {
  return schnorr_pubkey_;
}

bool DescriptorKeyReference::HasSchnorrPubkey() const {
  return key_type_ == DescriptorKeyType::kDescriptorKeySchnorr;
}

std::string DescriptorKeyReference::GetArgument() const { return argument_; }

bool DescriptorKeyReference::HasExtPubkey() const {
  if ((key_type_ == DescriptorKeyType::kDescriptorKeyBip32) ||
      (key_type_ == DescriptorKeyType::kDescriptorKeyBip32Priv)) {
    return true;
  }
  return false;
}

bool DescriptorKeyReference::HasExtPrivkey() const {
  if (key_type_ == DescriptorKeyType::kDescriptorKeyBip32Priv) {
    return true;
  }
  return false;
}

ExtPrivkey DescriptorKeyReference::GetExtPrivkey() const {
  if (key_type_ == DescriptorKeyType::kDescriptorKeyBip32Priv) {
    return extprivkey_;
  }
  warn(CFD_LOG_SOURCE, "Failed to GetExtPrivkey. unsupported key type.");
  throw CfdException(
      CfdError::kCfdIllegalArgumentError,
      "GetExtPrivkey unsupported key type.");
}

ExtPubkey DescriptorKeyReference::GetExtPubkey() const {
  if (key_type_ == DescriptorKeyType::kDescriptorKeyBip32) {
    return extpubkey_;
  }
  if (key_type_ == DescriptorKeyType::kDescriptorKeyBip32Priv) {
    return extprivkey_.GetExtPubkey();
  }
  warn(CFD_LOG_SOURCE, "Failed to GetExtPubkey. unsupported key type.");
  throw CfdException(
      CfdError::kCfdIllegalArgumentError,
      "GetExtPubkey unsupported key type.");
}

KeyData DescriptorKeyReference::GetKeyData() const { return key_data_; }

DescriptorKeyType DescriptorKeyReference::GetKeyType() const {
  return key_type_;
}

// -----------------------------------------------------------------------------
// DescriptorScriptReference
// -----------------------------------------------------------------------------
DescriptorScriptReference::DescriptorScriptReference()
    : script_type_(DescriptorScriptType::kDescriptorScriptNull),
      is_script_(false),
      req_num_(0),
      is_tapbranch_(false) {
  // do nothing
}

DescriptorScriptReference::DescriptorScriptReference(
    const Script& locking_script, DescriptorScriptType script_type,
    const std::vector<AddressFormatData>& address_prefixes)
    : script_type_(script_type),
      locking_script_(locking_script),
      is_script_(false),
      req_num_(0),
      is_tapbranch_(false),
      addr_prefixes_(address_prefixes) {
  if ((script_type != DescriptorScriptType::kDescriptorScriptRaw) &&
      (script_type != DescriptorScriptType::kDescriptorScriptMiniscript)) {
    warn(
        CFD_LOG_SOURCE, "If it is not a raw type, key or script is required.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "If it is not a raw type, key or script is required.");
  }
}

DescriptorScriptReference::DescriptorScriptReference(
    const Script& locking_script, DescriptorScriptType script_type,
    const DescriptorScriptReference& child_script,
    const std::vector<AddressFormatData>& address_prefixes)
    : script_type_(script_type),
      locking_script_(locking_script),
      is_script_(true),
      req_num_(0),
      is_tapbranch_(false),
      addr_prefixes_(address_prefixes) {
  redeem_script_ = child_script.locking_script_;
  child_script_ = std::make_shared<DescriptorScriptReference>(child_script);
}

DescriptorScriptReference::DescriptorScriptReference(
    const Script& locking_script, DescriptorScriptType script_type,
    const std::vector<DescriptorKeyReference>& key_list,
    const std::vector<AddressFormatData>& address_prefixes,
    const uint32_t req_sig_num)
    : script_type_(script_type),
      locking_script_(locking_script),
      is_script_(false),
      req_num_(req_sig_num),
      is_tapbranch_(false),
      keys_(key_list),
      addr_prefixes_(address_prefixes) {
  // do nothing
}

DescriptorScriptReference::DescriptorScriptReference(
    const Address& address_script,
    const std::vector<AddressFormatData>& address_prefixes)
    : script_type_(DescriptorScriptType::kDescriptorScriptAddr),
      locking_script_(address_script.GetLockingScript()),
      is_script_(false),
      address_script_(address_script),
      req_num_(0),
      is_tapbranch_(false),
      addr_prefixes_(address_prefixes) {
  // do nothing
}

DescriptorScriptReference::DescriptorScriptReference(
    const Script& locking_script, DescriptorScriptType script_type,
    const std::vector<DescriptorKeyReference>& key_list,
    const TapBranch& tapbranch,
    const std::vector<AddressFormatData>& address_prefixes)
    : script_type_(script_type),
      locking_script_(locking_script),
      is_script_(false),
      req_num_(0),
      tapbranch_(tapbranch),
      is_tapbranch_(true),
      keys_(key_list),
      addr_prefixes_(address_prefixes) {
  // do nothing
}

DescriptorScriptReference::DescriptorScriptReference(
    const Script& locking_script, DescriptorScriptType script_type,
    const std::vector<DescriptorKeyReference>& key_list,
    const TaprootScriptTree& script_tree,
    const std::vector<AddressFormatData>& address_prefixes)
    : script_type_(script_type),
      locking_script_(locking_script),
      is_script_(false),
      req_num_(0),
      is_tapbranch_(false),
      script_tree_(script_tree),
      keys_(key_list),
      addr_prefixes_(address_prefixes) {
  // do nothing
}

DescriptorScriptReference::DescriptorScriptReference(
    const DescriptorScriptReference& object) {
  locking_script_ = object.locking_script_;
  script_type_ = object.script_type_;
  address_script_ = object.address_script_;
  is_script_ = object.is_script_;
  redeem_script_ = object.redeem_script_;
  child_script_ = object.child_script_;
  keys_ = object.keys_;
  req_num_ = object.req_num_;
  tapbranch_ = object.tapbranch_;
  is_tapbranch_ = object.is_tapbranch_;
  script_tree_ = object.script_tree_;
  addr_prefixes_ = object.addr_prefixes_;
}

DescriptorScriptReference& DescriptorScriptReference::operator=(
    const DescriptorScriptReference& object) {
  if (this != &object) {
    locking_script_ = object.locking_script_;
    script_type_ = object.script_type_;
    address_script_ = object.address_script_;
    is_script_ = object.is_script_;
    redeem_script_ = object.redeem_script_;
    child_script_ = object.child_script_;
    keys_ = object.keys_;
    req_num_ = object.req_num_;
    tapbranch_ = object.tapbranch_;
    is_tapbranch_ = object.is_tapbranch_;
    script_tree_ = object.script_tree_;
    addr_prefixes_ = object.addr_prefixes_;
  }
  return *this;
}

Script DescriptorScriptReference::GetLockingScript() const {
  return locking_script_;
}

bool DescriptorScriptReference::HasAddress() const {
  if (script_type_ == DescriptorScriptType::kDescriptorScriptRaw) {
    if (locking_script_.IsP2wpkhScript() || locking_script_.IsP2wshScript() ||
        locking_script_.IsTaprootScript() || locking_script_.IsP2shScript() ||
        locking_script_.IsP2pkhScript()) {
      return true;
    }
    return false;
  }
  return true;
}

Address DescriptorScriptReference::GenerateAddress(NetType net_type) const {
  bool is_key = false;
  bool is_witness = false;
  switch (script_type_) {
    case DescriptorScriptType::kDescriptorScriptRaw:
      if (locking_script_.IsP2wpkhScript() ||
          locking_script_.IsTaprootScript() ||
          locking_script_.IsP2wshScript()) {
        auto hash = locking_script_.GetElementList()[1].GetBinaryData();
        return Address(
            net_type, locking_script_.GetWitnessVersion(), hash,
            addr_prefixes_);
      } else if (locking_script_.IsP2shScript()) {
        auto hash = locking_script_.GetElementList()[1].GetBinaryData();
        return Address(
            net_type, AddressType::kP2shAddress, ByteData160(hash),
            addr_prefixes_);
      } else if (locking_script_.IsP2pkhScript()) {
        auto hash = locking_script_.GetElementList()[2].GetBinaryData();
        return Address(
            net_type, AddressType::kP2pkhAddress, ByteData160(hash),
            addr_prefixes_);
      }
      warn(CFD_LOG_SOURCE, "raw type descriptor is not support.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "raw type descriptor is not support.");
    case DescriptorScriptType::kDescriptorScriptAddr:
      if (net_type != address_script_.GetNetType()) {
        warn(CFD_LOG_SOURCE, "Failed to nettype. unmatch address nettype.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError, "unmatch address nettype.");
      }
      return address_script_;
    case DescriptorScriptType::kDescriptorScriptWpkh:
      is_witness = true;
      // fall-through
    case DescriptorScriptType::kDescriptorScriptPk:
    case DescriptorScriptType::kDescriptorScriptPkh:
    case DescriptorScriptType::kDescriptorScriptMulti:
    case DescriptorScriptType::kDescriptorScriptSortedMulti:
      is_key = true;
      break;
    case DescriptorScriptType::kDescriptorScriptCombo:
      if (!locking_script_.IsP2shScript()) {
        is_key = true;
        is_witness = locking_script_.IsP2wpkhScript();
      }
      break;
    case DescriptorScriptType::kDescriptorScriptWsh:
      is_witness = true;
      break;
    case DescriptorScriptType::kDescriptorScriptTaproot:
      return Address(
          net_type, locking_script_.GetWitnessVersion(),
          locking_script_.GetElementList()[1].GetBinaryData(), addr_prefixes_);
    default:
      // case DescriptorScriptType::kDescriptorScriptSh:
      break;
  }
  if (is_key) {
    Pubkey pubkey = keys_[0].GetPubkey();
    if (is_witness) {
      return Address(
          net_type, WitnessVersion::kVersion0, pubkey, addr_prefixes_);
    } else {
      return Address(net_type, pubkey, addr_prefixes_);
    }
  }

  if (script_type_ == DescriptorScriptType::kDescriptorScriptWsh) {
    return Address(
        net_type, WitnessVersion::kVersion0, redeem_script_, addr_prefixes_);
  }
  if (script_type_ == DescriptorScriptType::kDescriptorScriptWsh) {
    return Address(
        net_type, WitnessVersion::kVersion0, redeem_script_, addr_prefixes_);
  }
  return Address(net_type, redeem_script_, addr_prefixes_);
}

std::vector<Address> DescriptorScriptReference::GenerateAddresses(
    NetType net_type) const {
  std::vector<Address> result;
  if ((script_type_ == DescriptorScriptType::kDescriptorScriptMulti) ||
      (script_type_ == DescriptorScriptType::kDescriptorScriptSortedMulti)) {
    for (const auto& key : keys_) {
      result.emplace_back(net_type, key.GetPubkey(), addr_prefixes_);
    }
  } else {
    result.push_back(GenerateAddress(net_type));
  }
  return result;
}

AddressType DescriptorScriptReference::GetAddressType() const {
  switch (script_type_) {
    case DescriptorScriptType::kDescriptorScriptRaw:
      if (locking_script_.IsP2wpkhScript()) {
        return AddressType::kP2wpkhAddress;
      } else if (locking_script_.IsP2wshScript()) {
        return AddressType::kP2wshAddress;
      } else if (locking_script_.IsTaprootScript()) {
        return AddressType::kTaprootAddress;
      } else if (locking_script_.IsP2shScript()) {
        return AddressType::kP2shAddress;
      } else if (locking_script_.IsP2pkhScript()) {
        return AddressType::kP2pkhAddress;
      }
      warn(
          CFD_LOG_SOURCE,
          "Failed to GenerateAddress. raw type descriptor is not support.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "raw type descriptor is not support.");
    case DescriptorScriptType::kDescriptorScriptAddr:
      return address_script_.GetAddressType();
    default:
      break;
  }
  if (locking_script_.IsP2shScript()) {
    if (redeem_script_.IsP2wpkhScript()) {
      return AddressType::kP2shP2wpkhAddress;
    } else if (redeem_script_.IsP2wshScript()) {
      return AddressType::kP2shP2wshAddress;
    }
    return AddressType::kP2shAddress;
  }
  if (locking_script_.IsP2wpkhScript()) {
    return AddressType::kP2wpkhAddress;
  }
  if (locking_script_.IsP2wshScript()) {
    return AddressType::kP2wshAddress;
  }
  if (locking_script_.IsTaprootScript()) {
    return AddressType::kTaprootAddress;
  }
  if (locking_script_.IsP2pkhScript()) {
    return AddressType::kP2pkhAddress;
  }
  if (locking_script_.IsP2pkScript() || locking_script_.IsMultisigScript()) {
    return AddressType::kP2shAddress;  // unsupported script
  }
  warn(CFD_LOG_SOURCE, "Failed to GetAddressType. unknown address type.");
  throw CfdException(
      CfdError::kCfdIllegalArgumentError, "unknown address type.");
}

HashType DescriptorScriptReference::GetHashType() const {
  if (locking_script_.IsP2shScript()) {
    return HashType::kP2sh;
  }
  if (locking_script_.IsP2wpkhScript()) {
    return HashType::kP2wpkh;
  }
  if (locking_script_.IsP2wshScript()) {
    return HashType::kP2wsh;
  }
  if (locking_script_.IsTaprootScript()) {
    return HashType::kTaproot;
  }
  if (locking_script_.IsP2pkScript()) {
    return HashType::kP2pkh;
  }
  warn(CFD_LOG_SOURCE, "Failed to GetHashType. unsupported hash type.");
  throw CfdException(
      CfdError::kCfdIllegalArgumentError, "unsupported hash type.");
}

bool DescriptorScriptReference::HasRedeemScript() const {
  return !redeem_script_.IsEmpty();
}

Script DescriptorScriptReference::GetRedeemScript() const {
  return redeem_script_;
}

bool DescriptorScriptReference::HasChild() const { return is_script_; }

DescriptorScriptReference DescriptorScriptReference::GetChild() const {
  if (is_script_) {
    return *child_script_;
  }
  return DescriptorScriptReference();
}

bool DescriptorScriptReference::HasReqNum() const {
  return (script_type_ == DescriptorScriptType::kDescriptorScriptMulti ||
          script_type_ ==
              DescriptorScriptType::kDescriptorScriptSortedMulti) &&
         (req_num_ > 0);
}

uint32_t DescriptorScriptReference::GetReqNum() const {
  if (HasReqNum()) {
    return req_num_;
  }
  return 0;
}

bool DescriptorScriptReference::HasKey() const { return !keys_.empty(); }

uint32_t DescriptorScriptReference::GetKeyNum() const {
  return static_cast<uint32_t>(keys_.size());
}

std::vector<DescriptorKeyReference> DescriptorScriptReference::GetKeyList()
    const {
  return keys_;
}

bool DescriptorScriptReference::HasTapBranch() const { return is_tapbranch_; }

TapBranch DescriptorScriptReference::GetTapBranch() const {
  return tapbranch_;
}

bool DescriptorScriptReference::HasScriptTree() const {
  return !script_tree_.GetScript().IsEmpty();
}

TaprootScriptTree DescriptorScriptReference::GetScriptTree() const {
  return script_tree_;
}

DescriptorScriptType DescriptorScriptReference::GetScriptType() const {
  return script_type_;
}

// -----------------------------------------------------------------------------
// DescriptorNode
// -----------------------------------------------------------------------------
DescriptorNode::DescriptorNode()
    : node_type_(DescriptorNodeType::kDescriptorTypeNull),
      script_type_(DescriptorScriptType::kDescriptorScriptNull),
      key_type_(DescriptorKeyType::kDescriptorKeyNull) {
  addr_prefixes_ = GetBitcoinAddressFormatList();
  network_type_ = NetType::kMainnet;
}

DescriptorNode::DescriptorNode(
    const std::vector<AddressFormatData>& network_parameters,
    NetType network_type) {
  addr_prefixes_ = network_parameters;
  network_type_ = network_type;
}

DescriptorNode::DescriptorNode(const DescriptorNode& object) {
  name_ = object.name_;
  value_ = object.value_;
  key_info_ = object.key_info_;
  is_uncompressed_key_ = object.is_uncompressed_key_;
  base_extkey_ = object.base_extkey_;
  tweak_sum_ = object.tweak_sum_;
  number_ = object.number_;
  child_node_ = object.child_node_;
  tree_node_ = object.tree_node_;
  checksum_ = object.checksum_;
  depth_ = object.depth_;
  need_arg_num_ = object.need_arg_num_;
  node_type_ = object.node_type_;
  script_type_ = object.script_type_;
  key_type_ = object.key_type_;
  addr_prefixes_ = object.addr_prefixes_;
  parent_kind_ = object.parent_kind_;
  network_type_ = object.network_type_;
}

DescriptorNode& DescriptorNode::operator=(const DescriptorNode& object) {
  if (this != &object) {
    name_ = object.name_;
    value_ = object.value_;
    key_info_ = object.key_info_;
    is_uncompressed_key_ = object.is_uncompressed_key_;
    base_extkey_ = object.base_extkey_;
    tweak_sum_ = object.tweak_sum_;
    number_ = object.number_;
    child_node_ = object.child_node_;
    tree_node_ = object.tree_node_;
    checksum_ = object.checksum_;
    depth_ = object.depth_;
    need_arg_num_ = object.need_arg_num_;
    node_type_ = object.node_type_;
    script_type_ = object.script_type_;
    key_type_ = object.key_type_;
    addr_prefixes_ = object.addr_prefixes_;
    parent_kind_ = object.parent_kind_;
    network_type_ = object.network_type_;
  }
  return *this;
}

DescriptorNode DescriptorNode::Parse(
    const std::string& output_descriptor,
    const std::vector<AddressFormatData>& network_parameters,
    NetType network_type) {
  DescriptorNode node(network_parameters, network_type);
  node.node_type_ = DescriptorNodeType::kDescriptorTypeScript;
  node.AnalyzeChild(output_descriptor, 0);
  node.AnalyzeAll("");
  // Script generate test
  std::vector<std::string> list;
  for (uint32_t index = 0; index < node.GetNeedArgumentNum(); ++index) {
    list.push_back("0");
  }
  node.GetReference(&list);
  return node;
}

void DescriptorNode::AnalyzeChild(
    const std::string& descriptor, uint32_t depth) {
  bool is_terminate = false;
  size_t offset = 0;
  uint32_t depth_work = depth;
  bool exist_child_node = false;
  depth_ = depth;
  std::string descriptor_main;
  info(CFD_LOG_SOURCE, "AnalyzeChild = {}", descriptor);

  for (size_t idx = 0; idx < descriptor.size(); ++idx) {
    const char& str = descriptor[idx];
    if (str == '#') {
      if (is_terminate) {
        offset = idx;
        checksum_ = descriptor.substr(idx + 1);
        descriptor_main = descriptor.substr(0, idx);
        if (checksum_.find("#") != std::string::npos) {
          warn(CFD_LOG_SOURCE, "Illegal data. Multiple '#' symbols.");
          throw CfdException(
              CfdError::kCfdIllegalArgumentError, "Multiple '#' symbols.");
        }
      } else {
        warn(CFD_LOG_SOURCE, "Illegal checksum data.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError, "Illegal checksum data.");
      }
    } else if (str == ',') {
      if (exist_child_node) {
        // through by child node
      } else if ((name_ == "multi") || (name_ == "sortedmulti")) {
        DescriptorNode node(addr_prefixes_, network_type_);
        node.value_ = descriptor.substr(offset, idx - offset);
        info(CFD_LOG_SOURCE, "multisig, node.value_ = {}", node.value_);
        if (child_node_.empty()) {
          node.node_type_ = DescriptorNodeType::kDescriptorTypeNumber;
          node.number_ = atoi(node.value_.c_str());
        } else {
          node.node_type_ = DescriptorNodeType::kDescriptorTypeKey;
        }
        node.depth_ = depth + 1;
        node.parent_kind_ = parent_kind_;
        child_node_.push_back(node);
        offset = idx + 1;
      } else if (name_ == "tr") {
        if (child_node_.empty()) {
          DescriptorNode node(addr_prefixes_, network_type_);
          node.value_ = descriptor.substr(offset, idx - offset);
          node.node_type_ = DescriptorNodeType::kDescriptorTypeKey;
          node.depth_ = depth + 1;
          node.parent_kind_ = parent_kind_;
          child_node_.push_back(node);
          offset = idx + 1;
        }
      } else {
        // ignore for miniscript
        // warn(CFD_LOG_SOURCE, "Illegal command.");
        // throw CfdException(
        //     CfdError::kCfdIllegalArgumentError, "Illegal command.");
      }
    } else if (str == ' ') {
      ++offset;
    } else if (str == '(') {
      if (depth_work == depth) {
        name_ = descriptor.substr(offset, idx - offset);
        offset = idx + 1;
      } else {
        exist_child_node = true;
      }
      info(
          CFD_LOG_SOURCE, "Target`(` depth_work={}, name={}", depth_work,
          name_);
      ++depth_work;
    } else if (str == ')') {
      --depth_work;
      info(CFD_LOG_SOURCE, "Target`)` depth_work = {}", depth_work);
      if (depth_work == depth) {
        value_ = descriptor.substr(offset, idx - offset);
        is_terminate = true;
        offset = idx + 1;
        if ((name_ == "addr") || (name_ == "raw")) {
          // do nothing
        } else {
          DescriptorNode node(addr_prefixes_, network_type_);
          if (name_ == "tr") {
            node.node_type_ = DescriptorNodeType::kDescriptorTypeScript;
            node.value_ = value_;
            node.depth_ = depth + 1;
            exist_child_node = false;
          } else if (exist_child_node) {
            node.node_type_ = DescriptorNodeType::kDescriptorTypeScript;
            node.AnalyzeChild(value_, depth + 1);
            exist_child_node = false;
          } else {
            node.node_type_ = DescriptorNodeType::kDescriptorTypeKey;
            node.value_ = value_;
            node.depth_ = depth + 1;
          }
          node.parent_kind_ = parent_kind_;
          child_node_.push_back(node);
          info(
              CFD_LOG_SOURCE, "Target`)` depth_work={}, child.value={}",
              depth_work, node.value_);
        }
      }
    }
  }

  if (name_.empty() || (name_ == "addr") || (name_ == "raw")) {
    // do nothing
  } else if (child_node_.empty()) {
    warn(CFD_LOG_SOURCE, "Failed to child node empty.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed to child node empty.");
  }

  if (!descriptor_main.empty()) {
    CheckChecksum(descriptor_main);
  }
}

void DescriptorNode::CheckChecksum(const std::string& descriptor) {
  if (checksum_.size() != 8) {
    warn(
        CFD_LOG_SOURCE, "Expected 8 character checksum, not {} characters.",
        checksum_.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Expected 8 character checksum.");
  }
  std::string checksum = GenerateChecksum(descriptor);
  if (checksum.empty()) {
    warn(CFD_LOG_SOURCE, "Invalid characters in payload.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid characters in payload.");
  }
  if (checksum_ != checksum) {
    warn(
        CFD_LOG_SOURCE,
        "Provided checksum '{}' does not match computed checksum '{}'.",
        checksum_, checksum);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Unmatch checksum.");
  }
}

std::string DescriptorNode::GenerateChecksum(const std::string& descriptor) {
  // base
  // bitcoin/src/script/descriptor.cpp
  // std::string DescriptorChecksum(const Span<const char>& span)

  /** A character set designed such that:
   *  - The most common 'unprotected' descriptor characters (hex, keypaths) are in the first group of 32.
   *  - Case errors cause an offset that's a multiple of 32.
   *  - As many alphabetic characters are in the same group (while following the above restrictions).
   *
   * If p(x) gives the position of a character c in this character set, every group of 3 characters
   * (a,b,c) is encoded as the 4 symbols (p(a) & 31, p(b) & 31, p(c) & 31, (p(a) / 32) + 3 * (p(b) / 32) + 9 * (p(c) / 32).
   * This means that changes that only affect the lower 5 bits of the position, or only the higher 2 bits, will just
   * affect a single symbol.
   *
   * As a result, within-group-of-32 errors count as 1 symbol, as do cross-group errors that don't affect
   * the position within the groups.
   */
  static const std::string kInputCharset =
      "0123456789()[],'/*abcdefgh@:$%{}"
      "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
      "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

  /** The character set for the checksum itself (same as bech32). */
  static const std::string kChecksumCharset =
      "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

  static auto poly_mod = [](uint64_t c, int val) -> uint64_t {
    uint8_t c0 = c >> 35;
    c = ((c & 0x7ffffffff) << 5) ^ val;
    if (c0 & 1) c ^= 0xf5dee51989;
    if (c0 & 2) c ^= 0xa9fdca3312;
    if (c0 & 4) c ^= 0x1bab10e32d;
    if (c0 & 8) c ^= 0x3706b1677a;
    if (c0 & 16) c ^= 0x644d626ffd;
    return c;
  };

  uint64_t c = 1;
  int cls = 0;
  int clscount = 0;
  for (size_t idx = 0; idx < descriptor.size(); ++idx) {
    const char& ch = descriptor[idx];
    auto pos = kInputCharset.find(ch);
    if (pos == std::string::npos) return "";
    // Emit a symbol for the position inside the group, for every character.
    c = poly_mod(c, pos & 31);
    // Accumulate the group numbers
    cls = cls * 3 + static_cast<int>(pos >> 5);
    if (++clscount == 3) {
      // NOLINT Emit an extra symbol representing the group numbers, for every 3 characters.
      c = poly_mod(c, cls);
      cls = 0;
      clscount = 0;
    }
  }
  if (clscount > 0) c = poly_mod(c, cls);
  // Shift further to determine the checksum.
  for (int j = 0; j < 8; ++j) c = poly_mod(c, 0);
  // Prevent appending zeroes from not affecting the checksum.
  c ^= 1;

  std::string ret(8, ' ');
  for (int j = 0; j < 8; ++j)
    ret[j] = kChecksumCharset[(c >> (5 * (7 - j))) & 31];

  return ret;
}

void DescriptorNode::AnalyzeKey() {
  // key analyze
  key_info_ = value_;
  if (value_[0] == '[') {
    // key origin information check
    // cut to ']'
    auto pos = value_.find("]");
    if (pos != std::string::npos) {
      key_info_ = value_.substr(pos + 1);
    }
  }
  // derive key check (xpub,etc)
  info(CFD_LOG_SOURCE, "key_info_ = {}", key_info_);
  std::string hdkey_top;
  if (key_info_.size() > 4) {
    hdkey_top = key_info_.substr(1, 3);
  }
  if ((hdkey_top == "pub") || (hdkey_top == "prv")) {
    key_type_ = DescriptorKeyType::kDescriptorKeyBip32;
    if (hdkey_top == "prv") {
      key_type_ = DescriptorKeyType::kDescriptorKeyBip32Priv;
    }
    ExtPubkey xpub;
    std::string path;
    std::string key;
    bool hardened = false;
    std::vector<std::string> list = StringUtil::Split(key_info_, "/");
    key = list[0];
    if (list.size() > 1) {
      if (key_info_.find("*") != std::string::npos) {
        need_arg_num_ = 1;
      }
      size_t index;
      for (index = 1; index < list.size(); ++index) {
        if (list[index] == "*") break;
        if ((list[index] == "*'") || (list[index] == "*h")) {
          hardened = true;
          break;
        }
        if (index != 1) {
          path += "/";
        }
        path += list[index];
      }
      if ((index + 1) < list.size()) {
        warn(
            CFD_LOG_SOURCE,
            "Failed to extkey path. "
            "A '*' can only be specified at the end.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError,
            "Failed to extkey path. "
            "A '*' can only be specified at the end.");
      }
    }
    info(CFD_LOG_SOURCE, "key = {}, path = {}", key, path);
    if (key_type_ == DescriptorKeyType::kDescriptorKeyBip32Priv) {
      ExtPrivkey xpriv(key);
      base_extkey_ = key;
      if (!path.empty()) xpriv = xpriv.DerivePrivkey(path);
      key_info_ = xpriv.ToString();
      tweak_sum_ = xpriv.GetPubTweakSum().GetHex();
    } else if (hardened) {
      warn(
          CFD_LOG_SOURCE, "Failed to extPubkey. hardened is extPrivkey only.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to extPubkey. hardened is extPrivkey only.");
    } else {
      xpub = ExtPubkey(key);
      base_extkey_ = key;
      if (!path.empty()) xpub = xpub.DerivePubkey(path);
      key_info_ = xpub.ToString();
      tweak_sum_ = xpub.GetPubTweakSum().GetHex();
    }
  } else {
    key_type_ = DescriptorKeyType::kDescriptorKeyPublic;
    bool is_wif = false;
    Pubkey pubkey;
    SchnorrPubkey schnorr_pubkey;
    Privkey privkey;
    try {
      // pubkey format check
      ByteData bytes(key_info_);
      if (Pubkey::IsValid(bytes)) {
        // pubkey
        pubkey = Pubkey(bytes);
        if (parent_kind_ == "tr") {
          warn(
              CFD_LOG_SOURCE,
              "Failed to taproot key. taproot is xonly pubkey only.");
          throw CfdException(
              CfdError::kCfdIllegalArgumentError,
              "Failed to taproot key. taproot is xonly pubkey only.");
        }
        key_info_ = pubkey.GetHex();
      } else if (
          (parent_kind_ == "tr") &&
          (bytes.GetDataSize() == SchnorrPubkey::kSchnorrPubkeySize)) {
        // xonly pubkey
        schnorr_pubkey = SchnorrPubkey(bytes);
        pubkey = schnorr_pubkey.CreatePubkey();
        key_type_ = DescriptorKeyType::kDescriptorKeySchnorr;
        key_info_ = schnorr_pubkey.GetHex();
      } else {
        is_wif = true;
      }
    } catch (const CfdException& except) {
      std::string errmsg(except.what());
      if (errmsg.find("hex to byte convert error.") != std::string::npos) {
        is_wif = true;
      } else {
        throw except;
      }
    }
    if (is_wif) {
      // privkey WIF check
      bool is_compressed = true;
      NetType nettype = NetType::kMainnet;
      bool has_wif = Privkey::HasWif(key_info_, &nettype, &is_compressed);
      if (has_wif) {
        privkey = Privkey::FromWif(key_info_, nettype, is_compressed);
      }
      if (!privkey.IsValid()) {
        warn(CFD_LOG_SOURCE, "Failed to privkey.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError, "privkey invalid.");
      }
      pubkey = privkey.GeneratePubkey(is_compressed);
      key_info_ = pubkey.GetHex();
    }
    is_uncompressed_key_ = !pubkey.IsCompress();
  }
  info(CFD_LOG_SOURCE, "key_info = {}", key_info_);
}

bool DescriptorNode::ExistUncompressedKey() {
  if (is_uncompressed_key_) return true;
  for (auto& child : child_node_) {
    if (child.ExistUncompressedKey()) return true;
  }
  return false;
}

void DescriptorNode::AnalyzeAll(const std::string& parent_name) {
  if (node_type_ == DescriptorNodeType::kDescriptorTypeNumber) {
    return;
  }
  if (node_type_ == DescriptorNodeType::kDescriptorTypeKey) {
    AnalyzeKey();
    return;
  }
  if (name_.empty()) {
    warn(CFD_LOG_SOURCE, "Failed to name field empty. Analyze NG.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed to analyze descriptor.");
  }

  const DescriptorNodeScriptData* p_data = nullptr;
  for (const auto& node_data : kDescriptorNodeScriptTable) {
    if (name_ == node_data.name) {
      p_data = &node_data;
      break;
    }
  }
  if (p_data == nullptr) {
    if ((parent_name == "wsh") || (parent_name == "sh") ||
        (parent_name == "tr")) {
      size_t max_size = (parent_name == "sh") ? Script::kMaxRedeemScriptSize
                                              : Script::kMaxScriptSize;
      std::string miniscript = name_ + "(" + value_ + ")";
      std::vector<unsigned char> script(max_size);
      size_t written = 0;
      uint32_t flags = WALLY_MINISCRIPT_WITNESS_SCRIPT;
      if (parent_name == "tr") flags = WALLY_MINISCRIPT_TAPSCRIPT;
      int ret = wally_descriptor_parse_miniscript(
          miniscript.c_str(), nullptr, nullptr, 0, 0, flags, script.data(),
          script.size(), &written);
      if (ret == WALLY_OK) {
        script_type_ = DescriptorScriptType::kDescriptorScriptMiniscript;
        value_ = miniscript;
        name_ = "miniscript";
        number_ = static_cast<uint32_t>(written);
        need_arg_num_ = (miniscript.find("*") != std::string::npos) ? 1 : 0;
        child_node_.clear();
        return;
      } else {
        warn(
            CFD_LOG_SOURCE,
            "Failed to analyze descriptor. parse miniscript fail.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError,
            "Failed to analyze descriptor. parse miniscript fail.");
      }
    }

    warn(
        CFD_LOG_SOURCE,
        "Failed to analyze descriptor. script's name not found.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed to analyze descriptor.");
  }

  if (p_data->top_only && (depth_ != 0)) {
    warn(
        CFD_LOG_SOURCE,
        "Failed to analyse descriptor. The target can only exist at the top.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to analyse descriptor. The target can only exist at the top.");
  }
  if (p_data->has_child) {
    if (child_node_.empty()) {
      warn(CFD_LOG_SOURCE, "Failed to child node empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Failed to child node empty.");
    }
  } else if (!child_node_.empty()) {
    warn(
        CFD_LOG_SOURCE, "Failed to child node num. size={}",
        child_node_.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed to child node num.");
  }

  if (p_data->multisig) {
    if (parent_kind_ == "tr") {
      warn(CFD_LOG_SOURCE, "Failed to multisig. taproot is unsupported.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to multisig. taproot is unsupported.");
    }
    if (child_node_.size() < 2) {
      warn(
          CFD_LOG_SOURCE, "Failed to multisig node low. size={}",
          child_node_.size());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Failed to multisig node low.");
    }
    size_t pubkey_num = child_node_.size() - 1;
    if ((child_node_[0].number_ == 0) ||
        (pubkey_num < static_cast<size_t>(child_node_[0].number_))) {
      warn(
          CFD_LOG_SOURCE, "Failed to multisig require num. num={}",
          child_node_[0].number_);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to multisig require num.");
    }
    size_t max_pubkey_num =
        (parent_name == "wsh") ? Script::kMaxMultisigPubkeyNum : 16;
    if (pubkey_num > max_pubkey_num) {
      warn(
          CFD_LOG_SOURCE, "Failed to multisig pubkey num. num={}",
          child_node_.size() - 1);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to multisig pubkey num.");
    }
    for (auto& child : child_node_) {
      child.AnalyzeAll(name_);
    }
    if (parent_name == "sh") {
      script_type_ = p_data->type;
      DescriptorScriptReference ref = GetReference(nullptr, this);
      Script script = ref.GetLockingScript();
      if ((script.GetData().GetDataSize() + 3) >
          Script::kMaxRedeemScriptSize) {
        warn(
            CFD_LOG_SOURCE, "Failed to script size over. size={}",
            script.GetData().GetDataSize());
        throw CfdException(
            CfdError::kCfdIllegalArgumentError, "Failed to script size over.");
      }
    } else if (parent_name == "wsh") {
      // check compress pubkey
      std::vector<std::string> temp_args;
      for (auto& child : child_node_) {
        if (child.node_type_ == DescriptorNodeType::kDescriptorTypeNumber) {
          continue;
        }
        temp_args.push_back("0");
        if (!child.GetPubkey(&temp_args).IsCompress()) {
          warn(
              CFD_LOG_SOURCE,
              "Failed to multisig uncompress pubkey. wsh is compress only.");
          throw CfdException(
              CfdError::kCfdIllegalArgumentError,
              "Failed to multisig uncompress pubkey. wsh is compress only.");
        }
      }
    }
  } else if (name_ == "addr") {
    Address addr(value_, addr_prefixes_);
    info(CFD_LOG_SOURCE, "Address={}", addr.GetAddress());
  } else if (name_ == "raw") {
    Script script(value_);
    info(CFD_LOG_SOURCE, "script size={}", script.GetData().GetDataSize());
  } else if (name_ == "tr") {
    if ((child_node_.size() != 1) && (child_node_.size() != 2)) {
      warn(
          CFD_LOG_SOURCE, "Failed to taproot node num. size={}",
          child_node_.size());
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to taproot node num." + child_node_[0].value_);
    }
    child_node_[0].node_type_ = DescriptorNodeType::kDescriptorTypeKey;
    child_node_[0].parent_kind_ = "tr";
    child_node_[0].AnalyzeAll(name_);

    std::vector<std::string> temp_args;
    temp_args.push_back("0");
    if (!child_node_[0].GetPubkey(&temp_args).IsCompress()) {
      warn(
          CFD_LOG_SOURCE,
          "Failed to taproot pubkey. taproot is compress only.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to taproot uncompress pubkey. taproot is compress only.");
    }
    if (child_node_.size() == 2) {
      child_node_[1].parent_kind_ = "tr";
      child_node_[1].AnalyzeScriptTree();
      for (uint32_t index = 0; index < child_node_[1].GetNeedArgumentNum();
           ++index) {
        temp_args.push_back("0");
      }
      child_node_[1].GetTapBranch(&temp_args);  // check
    }
  } else if (child_node_.size() != 1) {
    warn(
        CFD_LOG_SOURCE, "Failed to child node num. size={}",
        child_node_.size());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Failed to child node num.");
  } else {
    if ((name_ == "wsh") && (!parent_name.empty()) && (parent_name != "sh")) {
      warn(CFD_LOG_SOURCE, "Failed to wsh parent. only top or sh.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to wsh parent. only top or sh.");
    } else if (
        (name_ == "wpkh") && (!parent_name.empty()) && (parent_name != "sh")) {
      warn(CFD_LOG_SOURCE, "Failed to wpkh parent. only top or sh.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to wpkh parent. only top or sh.");
    } else if (
        ((name_ == "wsh") || (name_ == "sh")) &&
        (child_node_[0].node_type_ !=
         DescriptorNodeType::kDescriptorTypeScript)) {
      warn(
          CFD_LOG_SOURCE,
          "Failed to check script type. child is script only. nodetype={}",
          child_node_[0].node_type_);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to check script type. child is script only.");
    } else if (
        (name_ != "wsh") && (name_ != "sh") &&
        (child_node_[0].node_type_ !=
         DescriptorNodeType::kDescriptorTypeKey)) {
      warn(
          CFD_LOG_SOURCE,
          "Failed to check key-hash type. child is key only. nodetype={}",
          child_node_[0].node_type_);
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to check key-hash type. child is key only.");
    } else if ((parent_name == "tr") && (name_ == "pkh")) {
      warn(CFD_LOG_SOURCE, "Failed to taproot. pkh is unsupported.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to taproot. pkh is unsupported.");
    }
    child_node_[0].parent_kind_ = parent_kind_;
    child_node_[0].AnalyzeAll(name_);

    if ((name_ == "wpkh") || (name_ == "wsh")) {
      if (ExistUncompressedKey()) {
        warn(
            CFD_LOG_SOURCE,
            "Failed to unsing uncompressed pubkey."
            " witness cannot uncompressed pubkey.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError,
            "Failed to unsing uncompressed pubkey.");
      }
    }
  }
  script_type_ = p_data->type;
}

void DescriptorNode::AnalyzeScriptTree() {
  const auto& desc = value_;

  uint32_t script_depth = 0;
  size_t offset = 0;
  std::string tapscript;
  uint32_t tapleaf_count = 0;
  std::string temp_name;
  for (size_t idx = 0; idx < desc.size(); ++idx) {
    const char& str = desc[idx];
    if ((str == ' ') || (str == '{')) {
      if (script_depth == 0) ++offset;
    } else if ((str == ',') || (str == '}')) {
      if (script_depth == 0) {
        tapscript = desc.substr(offset, idx - offset);
        if (tapscript.length() >= (kByteData256Length * 2)) {
          offset = idx + 1;
          DescriptorNode node(addr_prefixes_, network_type_);
          node.name_ = temp_name;
          node.node_type_ = DescriptorNodeType::kDescriptorTypeKey;
          node.value_ = tapscript;
          node.depth_ = 1;
          node.parent_kind_ = "tr";
          if (!temp_name.empty()) {
            node.AnalyzeChild(tapscript, 2);
          }
          node.AnalyzeAll("tr");
          tree_node_.emplace(tapscript, node);
          child_node_.emplace_back(node);
          ++tapleaf_count;
          tapscript = "";
          temp_name = "";
          info(
              CFD_LOG_SOURCE, "HashTarget script_depth={}, child.value={}",
              script_depth, node.value_);
        } else {
          ++offset;
        }
      }
    } else if (str == '(') {
      if (script_depth == 0) {
        temp_name = desc.substr(offset, idx - offset);
        // offset = idx + 1;
      }
      info(
          CFD_LOG_SOURCE, "Target`(` script_depth={}, name={}", script_depth,
          temp_name);
      ++script_depth;
    } else if (str == ')') {
      --script_depth;
      info(CFD_LOG_SOURCE, "Target`)` script_depth = {}", script_depth);
      if (script_depth == 0) {
        tapscript = desc.substr(offset, idx - offset + 1);
        offset = idx + 1;
        DescriptorNode node(addr_prefixes_, network_type_);
        node.name_ = temp_name;
        node.node_type_ = DescriptorNodeType::kDescriptorTypeScript;
        node.value_ = tapscript;
        node.depth_ = 1;
        node.parent_kind_ = "tr";
        if (!temp_name.empty()) {
          node.AnalyzeChild(tapscript, 2);
        }
        node.AnalyzeAll("tr");
        tree_node_.emplace(tapscript, node);
        child_node_.emplace_back(node);
        ++tapleaf_count;
        tapscript = "";
        temp_name = "";
        info(
            CFD_LOG_SOURCE, "Target`)` script_depth={}, child.value={}",
            script_depth, node.value_);
      }
    }
  }
  if (tree_node_.empty()) {
    if (value_.length() >= (kByteData256Length * 2)) {
      tapscript = value_;
      DescriptorNode node(addr_prefixes_, network_type_);
      node.name_ = temp_name;
      node.node_type_ = DescriptorNodeType::kDescriptorTypeKey;
      node.value_ = tapscript;
      node.depth_ = 1;
      node.parent_kind_ = "tr";
      if (!temp_name.empty()) {
        node.AnalyzeChild(tapscript, 2);
      }
      node.AnalyzeAll("tr");
      tree_node_.emplace(tapscript, node);
      child_node_.emplace_back(node);
      ++tapleaf_count;
      tapscript = "";
      temp_name = "";
      info(
          CFD_LOG_SOURCE, "LastTarget script_depth={}, child.value={}",
          script_depth, node.value_);
    } else {
      warn(CFD_LOG_SOURCE, "Failed to taproot. empty script.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to taproot. empty script.");
    }
  }
}

DescriptorScriptReference DescriptorNode::GetReference(
    std::vector<std::string>* array_argument,
    const DescriptorNode* parent) const {
  std::vector<DescriptorScriptReference> list;
  list = GetReferences(array_argument, parent);
  return list[0];
}

std::vector<DescriptorScriptReference> DescriptorNode::GetReferences(
    std::vector<std::string>* array_argument,
    const DescriptorNode* parent) const {
  if ((depth_ == 0) && (array_argument) && (array_argument->size() > 1)) {
    std::reverse(array_argument->begin(), array_argument->end());
  }
  std::vector<DescriptorScriptReference> result;
  ScriptBuilder build;
  Script locking_script;

  if (node_type_ == DescriptorNodeType::kDescriptorTypeKey) {
    // do nothing
  } else if (node_type_ == DescriptorNodeType::kDescriptorTypeNumber) {
    ScriptElement elem(static_cast<int64_t>(number_));
    build.AppendElement(elem);
  } else if (node_type_ == DescriptorNodeType::kDescriptorTypeScript) {
    if (script_type_ == DescriptorScriptType::kDescriptorScriptMiniscript) {
      uint32_t child_num = 0;
      if (need_arg_num_ == 0) {
        // do nothing
      } else if ((array_argument == nullptr) || array_argument->empty()) {
        warn(CFD_LOG_SOURCE, "Failed to generate miniscript from hdkey.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError,
            "Failed to generate miniscript from hdkey.");
      } else if (
          (array_argument != nullptr) && (!array_argument->empty()) &&
          (array_argument->at(0) == std::string(kArgumentBaseExtkey))) {
        // do nothing
      } else if (array_argument != nullptr) {
        std::string arg_value = array_argument->back();
        array_argument->pop_back();
        if (arg_value.rfind("/") != std::string::npos) {
          warn(
              CFD_LOG_SOURCE,
              "Failed to invalid argument. miniscript is single child.");
          throw CfdException(
              CfdError::kCfdIllegalArgumentError,
              "Failed to invalid argument. miniscript is single child.");
        }
        std::size_t end_pos = 0;
        child_num = static_cast<uint32_t>(std::stoul(arg_value, &end_pos, 10));
        if ((end_pos != 0) && (end_pos < arg_value.size())) {
          warn(CFD_LOG_SOURCE, "Failed to invalid argument. number only.");
          throw CfdException(
              CfdError::kCfdIllegalArgumentError,
              "Failed to invalid argument. number only.");
        }
      }
      std::vector<uint8_t> script(number_);
      size_t written = 0;
      uint32_t flags = 0;
      if (parent_kind_ == "tr") flags = WALLY_MINISCRIPT_TAPSCRIPT;
      int ret = wally_descriptor_parse_miniscript(
          value_.c_str(), nullptr, nullptr, 0, child_num, flags, script.data(),
          script.size(), &written);
      if ((ret == WALLY_OK) && (written <= script.size())) {
        locking_script = Script(script);
        result.emplace_back(locking_script, script_type_, addr_prefixes_);
      } else {
        warn(
            CFD_LOG_SOURCE, "Failed to parse miniscript.({}, size:{})", ret,
            written);
        throw CfdException(
            CfdError::kCfdIllegalArgumentError, "Failed to parse miniscript.");
      }
    } else if (script_type_ == DescriptorScriptType::kDescriptorScriptRaw) {
      locking_script = Script(value_);
      result.emplace_back(locking_script, script_type_, addr_prefixes_);
    } else if (script_type_ == DescriptorScriptType::kDescriptorScriptAddr) {
      Address addr(value_, addr_prefixes_);
      result.emplace_back(addr, addr_prefixes_);
      locking_script = addr.GetLockingScript();
    } else if (
        (script_type_ == DescriptorScriptType::kDescriptorScriptMulti) ||
        (script_type_ == DescriptorScriptType::kDescriptorScriptSortedMulti)) {
      uint32_t reqnum = child_node_[0].number_;
      std::vector<Pubkey> pubkeys;
      std::vector<DescriptorKeyReference> keys;
      DescriptorKeyReference key_ref;
      for (size_t index = 1; index < child_node_.size(); ++index) {
        key_ref = child_node_[index].GetKeyReferences(array_argument);
        keys.push_back(key_ref);
        pubkeys.push_back(key_ref.GetPubkey());
      }
      if (script_type_ == DescriptorScriptType::kDescriptorScriptSortedMulti) {
        // https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki
        std::sort(pubkeys.begin(), pubkeys.end(), Pubkey::IsLarge);
      }
      bool has_witness = false;
      if ((parent != nullptr) &&
          (parent->GetScriptType() ==
           DescriptorScriptType::kDescriptorScriptWsh)) {
        has_witness = true;
      }
      locking_script =
          ScriptUtil::CreateMultisigRedeemScript(reqnum, pubkeys, has_witness);
      result.emplace_back(
          locking_script, script_type_, keys, addr_prefixes_, reqnum);
    } else if (
        (script_type_ == DescriptorScriptType::kDescriptorScriptSh) ||
        (script_type_ == DescriptorScriptType::kDescriptorScriptWsh)) {
      DescriptorScriptReference ref =
          child_node_[0].GetReference(array_argument, this);
      Script script = ref.GetLockingScript();
      if (script_type_ == DescriptorScriptType::kDescriptorScriptWsh) {
        locking_script = ScriptUtil::CreateP2wshLockingScript(script);
      } else {
        locking_script = ScriptUtil::CreateP2shLockingScript(script);
      }
      result.emplace_back(locking_script, script_type_, ref, addr_prefixes_);
    } else if (
        script_type_ == DescriptorScriptType::kDescriptorScriptTaproot) {
      std::vector<DescriptorKeyReference> keys;
      DescriptorKeyReference ref =
          child_node_[0].GetKeyReferences(array_argument);
      SchnorrPubkey pubkey = ref.GetSchnorrPubkey();
      keys.push_back(ref);
      TapBranch branch(network_type_);
      if (child_node_.size() >= 2) {
        branch = child_node_[1].GetTapBranch(array_argument);
      }
      if (branch.HasTapLeaf()) {
        TaprootScriptTree tree(branch);
        TaprootUtil::CreateTapScriptControl(
            pubkey, tree, nullptr, &locking_script);
        result.emplace_back(
            locking_script, script_type_, keys, tree, addr_prefixes_);
      } else {
        // see: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
        // see: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-22 // NOLINT
        TaprootUtil::CreateTapScriptControl(
            pubkey, branch, nullptr, &locking_script);
        result.emplace_back(
            locking_script, script_type_, keys, branch, addr_prefixes_);
      }
    } else {
      std::vector<DescriptorKeyReference> keys;
      DescriptorKeyReference ref =
          child_node_[0].GetKeyReferences(array_argument);
      keys.push_back(ref);
      Bip32FormatType bip32_type = Bip32FormatType::kNormal;
      if (ref.HasExtPubkey()) {
        bip32_type = ref.GetExtPubkey().GetFormatType();
      }
      Pubkey pubkey = ref.GetPubkey();
      if (script_type_ == DescriptorScriptType::kDescriptorScriptCombo) {
        if (pubkey.IsCompress()) {
          if (bip32_type != Bip32FormatType::kBip49) {
            // p2wpkh
            locking_script = ScriptUtil::CreateP2wpkhLockingScript(pubkey);
            result.emplace_back(
                locking_script, script_type_, keys, addr_prefixes_);
          }

          if (bip32_type != Bip32FormatType::kBip84) {
            // p2sh-p2wpkh
            DescriptorScriptReference child_script(
                locking_script, DescriptorScriptType::kDescriptorScriptWpkh,
                keys, addr_prefixes_);
            locking_script =
                ScriptUtil::CreateP2shLockingScript(locking_script);
            result.emplace_back(
                locking_script, script_type_, child_script, addr_prefixes_);
          }
        }

        if (bip32_type == Bip32FormatType::kNormal) {
          // p2pkh
          locking_script = ScriptUtil::CreateP2pkhLockingScript(pubkey);
          result.emplace_back(
              locking_script, script_type_, keys, addr_prefixes_);

          // p2pk
          build << pubkey << ScriptOperator::OP_CHECKSIG;
          locking_script = build.Build();
          result.emplace_back(
              locking_script, script_type_, keys, addr_prefixes_);
        }
      } else {
        if (script_type_ == DescriptorScriptType::kDescriptorScriptPkh) {
          if (bip32_type != Bip32FormatType::kNormal) {
            throw CfdException(
                CfdError::kCfdIllegalArgumentError,
                "invalid bip32 format. pkh is not using bip49 or bip84.");
          }
          locking_script = ScriptUtil::CreateP2pkhLockingScript(pubkey);
        } else if (
            script_type_ == DescriptorScriptType::kDescriptorScriptWpkh) {
          if ((bip32_type == Bip32FormatType::kBip49) &&
              ((parent == nullptr) ||
               (parent->GetScriptType() !=
                DescriptorScriptType::kDescriptorScriptSh))) {
            throw CfdException(
                CfdError::kCfdIllegalArgumentError,
                "invalid bip32 format. bip49 is using sh-wpkh only.");
          } else if (
              (bip32_type == Bip32FormatType::kBip84) && (parent != nullptr)) {
            throw CfdException(
                CfdError::kCfdIllegalArgumentError,
                "invalid bip32 format. bip84 is using wpkh only.");
          }
          locking_script = ScriptUtil::CreateP2wpkhLockingScript(pubkey);
        } else if (script_type_ == DescriptorScriptType::kDescriptorScriptPk) {
          if (bip32_type != Bip32FormatType::kNormal) {
            throw CfdException(
                CfdError::kCfdIllegalArgumentError,
                "invalid bip32 format. pk is not using bip49 or bip84.");
          }
          if (parent_kind_ == "tr") {
            build << SchnorrPubkey::FromPubkey(pubkey).GetData()
                  << ScriptOperator::OP_CHECKSIG;
          } else {
            build << pubkey << ScriptOperator::OP_CHECKSIG;
          }
          locking_script = build.Build();
        }
        result.emplace_back(
            locking_script, script_type_, keys, addr_prefixes_);
      }
    }
  } else {
    // do nothing
  }

  return result;
}

Pubkey DescriptorNode::GetPubkey(
    std::vector<std::string>* array_argument) const {
  DescriptorKeyReference ref = GetKeyReferences(array_argument);
  return ref.GetPubkey();
}

TapBranch DescriptorNode::GetTapBranch(
    std::vector<std::string>* array_argument) const {
  static auto sort_func = [](const std::string& src, const std::string& dest) {
    return src.length() > dest.length();
  };
  std::vector<std::string> key_list;
  for (const auto& tree_node : tree_node_) {
    key_list.emplace_back(tree_node.first);
  }
  std::sort(key_list.begin(), key_list.end(), sort_func);

  std::string desc = value_;
  std::string target;
  Script first_script;
  for (const auto& script_str : key_list) {
    const auto& node_ref = tree_node_.at(script_str);
    if (node_ref.node_type_ == DescriptorNodeType::kDescriptorTypeKey) {
      auto ref = node_ref.GetKeyReferences(array_argument);
      target = ref.GetSchnorrPubkey().GetHex();
    } else {
      const auto obj = node_ref.GetReference(array_argument);
      Script script = obj.HasRedeemScript() ? obj.GetRedeemScript()
                                            : obj.GetLockingScript();
      if (first_script.IsEmpty()) first_script = script;
      target = "tl(" + script.GetHex() + ")";
    }
    if (script_str != target) {
      auto offset = desc.find(script_str);
      while (offset != std::string::npos) {
        desc = desc.replace(offset, script_str.length(), target);
        offset = desc.find(script_str);
      }
    }
  }

  TapBranch tree(network_type_);
  if (desc.empty() || (desc == "{}")) {
    // do nothing
  } else {
    tree = TapBranch::FromString(desc, network_type_);
    if ((!tree.HasTapLeaf()) && (!first_script.IsEmpty())) {
      tree = tree.ChangeTapLeaf(first_script);
    }
  }
  return tree;
}

DescriptorKeyReference DescriptorNode::GetKeyReferences(
    std::vector<std::string>* array_argument) const {
  DescriptorKeyReference result;
  Pubkey pubkey;
  std::string using_key = key_info_;
  KeyData key_data;
  if (key_type_ == DescriptorKeyType::kDescriptorKeyPublic) {
    pubkey = Pubkey(key_info_);
    result = DescriptorKeyReference(pubkey);
    try {
      key_data = KeyData(value_);
      result = DescriptorKeyReference(key_data);
    } catch (const CfdException& except) {
      if (value_[0] == '[') throw except;
    }
  } else if (key_type_ == DescriptorKeyType::kDescriptorKeySchnorr) {
    SchnorrPubkey schnorr_pubkey = SchnorrPubkey(key_info_);
    result = DescriptorKeyReference(schnorr_pubkey);
    try {
      key_data = KeyData(value_, -1, true);
      result = DescriptorKeyReference(key_data);
    } catch (const CfdException& except) {
      if (value_[0] == '[') throw except;
    }
    pubkey = schnorr_pubkey.CreatePubkey();
  } else if (
      (key_type_ == DescriptorKeyType::kDescriptorKeyBip32) ||
      (key_type_ == DescriptorKeyType::kDescriptorKeyBip32Priv)) {
    std::string arg_value;
    std::string* arg_pointer = nullptr;
    uint32_t need_arg_num = need_arg_num_;
    bool has_base = false;
    if (need_arg_num == 0) {
      // Fixed key. For strengthened keys, xprv/tprv is required.
    } else if ((array_argument == nullptr) || array_argument->empty()) {
      warn(CFD_LOG_SOURCE, "Failed to generate pubkey from hdkey.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to generate pubkey from hdkey.");
    } else if (
        (array_argument != nullptr) && (!array_argument->empty()) &&
        (array_argument->at(0) == std::string(kArgumentBaseExtkey))) {
      using_key = base_extkey_;
      need_arg_num = 0;
      has_base = true;
    } else {
      // Dynamic key generation. For strengthened keys, xprv/tprv is required.
      // If array_argument is nullptr, set it to 0 temporarily.
      // (For generate test)
      arg_value = "0";
      if (array_argument != nullptr) {
        arg_value = array_argument->back();
        array_argument->pop_back();
      }
      arg_pointer = &arg_value;
    }

    ExtPubkey xpub;
    ByteData256 tweak_sum;
    if (!tweak_sum_.empty()) tweak_sum = ByteData256(tweak_sum_);
    if (key_type_ == DescriptorKeyType::kDescriptorKeyBip32Priv) {
      ExtPrivkey xpriv(using_key, tweak_sum);
      if (need_arg_num != 0) {
        xpriv = xpriv.DerivePrivkey(arg_value);
      }
      xpub = xpriv.GetExtPubkey();
      result = DescriptorKeyReference(xpriv, arg_pointer);
    } else {
      xpub = ExtPubkey(using_key, tweak_sum);
      if (need_arg_num != 0) {
        xpub = xpub.DerivePubkey(arg_value);
      }
      result = DescriptorKeyReference(xpub, arg_pointer);
    }

    if (!xpub.IsValid()) {
      warn(CFD_LOG_SOURCE, "Failed to generate pubkey from hdkey.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to generate pubkey from hdkey.");
    }
    pubkey = xpub.GetPubkey();

    try {
      if (((need_arg_num == 0) && (!has_base)) ||
          ((!arg_value.empty()) &&
           (arg_value.find('/') == std::string::npos))) {
        key_data = KeyData(value_, static_cast<int32_t>(xpub.GetChildNum()));
        result = DescriptorKeyReference(key_data, arg_pointer);
      }
    } catch (const CfdException& except) {
      if (value_[0] == '[') throw except;
    }
  }

  if (!pubkey.IsValid()) {
    warn(
        CFD_LOG_SOURCE, "Failed to pubkey. type={}-{}, key_info={}",
        node_type_, key_type_, using_key);
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "Invalid pubkey data.");
  }
  return result;
}

uint32_t DescriptorNode::GetNeedArgumentNum() const {
  uint32_t result = need_arg_num_;
  if (!child_node_.empty()) {
    for (const auto& child : child_node_) {
      result += child.GetNeedArgumentNum();
    }
  }
  return result;
}

std::string DescriptorNode::ToString(bool append_checksum) const {
  std::string result;
  info(CFD_LOG_SOURCE, "name={}, value={}", name_, value_);

  if (name_.empty() || (name_ == "miniscript")) {
    result = value_;
  } else if (child_node_.empty()) {
    result = name_ + "(" + value_ + ")";
  } else {
    result = name_ + "(";
    std::string child_text;
    for (const auto& child : child_node_) {
      if (!child_text.empty()) child_text += ",";
      child_text += child.ToString();
    }
    result += child_text + ")";
  }

  if ((depth_ == 0) && append_checksum) {
    std::string checksum = GenerateChecksum(result);
    if (!checksum.empty()) {
      result += "#";
      result += checksum;
    }
  }
  return result;
}

// -----------------------------------------------------------------------------
// Descriptor
// -----------------------------------------------------------------------------
Descriptor::Descriptor() {}

Descriptor::Descriptor(const Descriptor& object) {
  root_node_ = object.root_node_;
}

Descriptor& Descriptor::operator=(const Descriptor& object) {
  if (this != &object) {
    root_node_ = object.root_node_;
  }
  return *this;
}

Descriptor Descriptor::Parse(
    const std::string& output_descriptor,
    const std::vector<AddressFormatData>* network_parameters,
    NetType network_type) {
  std::vector<AddressFormatData> network_pefixes;
  if (network_parameters) {
    network_pefixes = *network_parameters;
  } else {
    network_pefixes = GetBitcoinAddressFormatList();
  }
  Descriptor desc;
  desc.root_node_ =
      DescriptorNode::Parse(output_descriptor, network_pefixes, network_type);
  return desc;
}

#ifndef CFD_DISABLE_ELEMENTS
Descriptor Descriptor::ParseElements(const std::string& output_descriptor) {
  std::vector<AddressFormatData> network_pefixes =
      GetElementsAddressFormatList();
  return Parse(output_descriptor, &network_pefixes, NetType::kLiquidV1);
}
#endif  // CFD_DISABLE_ELEMENTS

Descriptor Descriptor::CreateDescriptor(
    DescriptorScriptType type, const DescriptorKeyInfo& key_info,
    const std::vector<AddressFormatData>* network_parameters) {
  std::vector<DescriptorScriptType> types;
  std::vector<DescriptorKeyInfo> keys;
  types.push_back(type);
  keys.push_back(key_info);
  return CreateDescriptor(types, keys, 1, network_parameters);
}

Descriptor Descriptor::CreateDescriptor(
    const std::vector<DescriptorScriptType>& type_list,
    const std::vector<DescriptorKeyInfo>& key_info_list, uint32_t require_num,
    const std::vector<AddressFormatData>* network_parameters) {
  if (type_list.empty()) {
    warn(CFD_LOG_SOURCE, "Failed to type list.");
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to type list. list is empty.");
  }
  std::string output_descriptor;
  std::vector<DescriptorScriptType> types(type_list);
  for (auto ite = types.rbegin(); ite != types.rend(); ++ite) {
    DescriptorScriptType type = *ite;

    std::string key_text;
    if (output_descriptor.empty() && (!key_info_list.empty())) {
      for (const auto& key_info : key_info_list) {
        if (key_text.empty()) {
          key_text = key_info.ToString();
        } else {
          key_text += "," + key_info.ToString();
        }
      }
    }

    const DescriptorNodeScriptData* p_data = nullptr;
    for (const auto& node_data : kDescriptorNodeScriptTable) {
      if (type == node_data.type) {
        p_data = &node_data;
        break;
      }
    }
    switch (type) {
      case DescriptorScriptType::kDescriptorScriptPk:
      case DescriptorScriptType::kDescriptorScriptPkh:
      case DescriptorScriptType::kDescriptorScriptWpkh:
      case DescriptorScriptType::kDescriptorScriptCombo:
      case DescriptorScriptType::kDescriptorScriptMulti:
      case DescriptorScriptType::kDescriptorScriptSortedMulti:
        if (!output_descriptor.empty()) {
          warn(CFD_LOG_SOURCE, "key hash type is bottom only.");
          throw CfdException(
              CfdError::kCfdIllegalArgumentError,
              "Failed to createDescriptor. key hash type is bottom only.");
        }
        if (key_text.empty()) {
          warn(CFD_LOG_SOURCE, "key list is empty");
          throw CfdException(
              CfdError::kCfdIllegalArgumentError,
              "Failed to createDescriptor. key list is empty.");
        }
        if ((p_data != nullptr) && (!p_data->multisig) &&
            (key_info_list.size() > 1)) {
          warn(CFD_LOG_SOURCE, "multiple key is multisig only.");
          throw CfdException(
              CfdError::kCfdIllegalArgumentError,
              "Failed to createDescriptor. multiple key is multisig only.");
        }
        break;
      case DescriptorScriptType::kDescriptorScriptSh:
      case DescriptorScriptType::kDescriptorScriptWsh:
        if (output_descriptor.empty()) {
          warn(CFD_LOG_SOURCE, "Failed to script hash type.");
          throw CfdException(
              CfdError::kCfdIllegalArgumentError,
              "Failed to script hash type. this type is unsupported of key.");
        }
        break;
      case DescriptorScriptType::kDescriptorScriptTaproot:
        // fall-through: unsupported yet.
      case DescriptorScriptType::kDescriptorScriptNull:
      case DescriptorScriptType::kDescriptorScriptAddr:
      case DescriptorScriptType::kDescriptorScriptRaw:
      default:
        warn(CFD_LOG_SOURCE, "Failed to script type.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError,
            "Failed to script type. this type is unsupported.");
        break;
    }

    if (p_data == nullptr) {
      warn(CFD_LOG_SOURCE, "Failed to script type.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to script type. this type is unsupported.");
    } else if (key_text.empty()) {
      output_descriptor = p_data->name + "(" + output_descriptor + ")";
    } else if (p_data->multisig) {
      output_descriptor = p_data->name + "(" + std::to_string(require_num) +
                          "," + key_text + ")";
    } else {
      output_descriptor = p_data->name + "(" + key_text + ")";
    }
  }

  // Check descriptor script format.
  return Parse(output_descriptor, network_parameters);
}

bool Descriptor::IsComboScript() const {
  if (root_node_.GetScriptType() !=
      DescriptorScriptType::kDescriptorScriptCombo) {
    return false;
  }
  return true;
}

uint32_t Descriptor::GetNeedArgumentNum() const {
  return root_node_.GetNeedArgumentNum();
}

Script Descriptor::GetLockingScript() const {
  if (GetNeedArgumentNum() != 0) {
    warn(CFD_LOG_SOURCE, "Failed to empty argument. {}", GetNeedArgumentNum());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to empty argument. need argument descriptor.");
  }
  std::vector<std::string> list;
  return GetLockingScriptAll(&list)[0];
}

Script Descriptor::GetLockingScript(const std::string& argument) const {
  std::vector<std::string> list;
  for (uint32_t index = 0; index < GetNeedArgumentNum(); ++index) {
    list.push_back(argument);
  }
  return GetLockingScriptAll(&list)[0];
}

Script Descriptor::GetLockingScript(
    const std::vector<std::string>& array_argument) const {
  std::vector<std::string> copy_list = array_argument;
  return GetLockingScriptAll(&copy_list)[0];
}

std::vector<Script> Descriptor::GetLockingScriptAll(
    const std::vector<std::string>* array_argument) const {
  std::vector<DescriptorScriptReference> ref_list =
      GetReferenceAll(array_argument);
  std::vector<Script> result;
  for (const auto& ref : ref_list) {
    result.push_back(ref.GetLockingScript());
  }
  return result;
}

DescriptorScriptReference Descriptor::GetReference(
    const std::vector<std::string>* array_argument) const {
  return GetReferenceAll(array_argument)[0];
}

std::vector<DescriptorScriptReference> Descriptor::GetReferenceAll(
    const std::vector<std::string>* array_argument) const {
  std::vector<std::string> copy_list;
  if (array_argument) copy_list = *array_argument;
  std::vector<DescriptorScriptReference> ref_list;
  return root_node_.GetReferences(&copy_list);
}

KeyData Descriptor::GetKeyData() const {
  if (GetNeedArgumentNum() != 0) {
    warn(CFD_LOG_SOURCE, "Failed to empty argument. {}", GetNeedArgumentNum());
    throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Failed to empty argument. need argument descriptor.");
  }
  std::vector<std::string> list;
  auto key_list = GetKeyDataAll(&list);
  if (key_list.empty()) return KeyData();
  return key_list[0];
}

KeyData Descriptor::GetKeyData(const std::string& argument) const {
  std::vector<std::string> list;
  for (uint32_t index = 0; index < GetNeedArgumentNum(); ++index) {
    list.push_back(argument);
  }
  return GetKeyData(list);
}

KeyData Descriptor::GetKeyData(
    const std::vector<std::string>& array_argument) const {
  std::vector<std::string> copy_list = array_argument;
  auto key_list = GetKeyDataAll(&copy_list);
  if (key_list.empty()) return KeyData();
  return key_list[0];
}

std::vector<KeyData> Descriptor::GetKeyDataAll(
    const std::vector<std::string>* array_argument) const {
  std::vector<DescriptorScriptReference> ref_list =
      GetReferenceAll(array_argument);
  std::vector<KeyData> result;

  for (const auto& ref : ref_list) {
    DescriptorScriptReference script_data = ref;
    do {
      if (script_data.HasKey()) {
        auto key_list = script_data.GetKeyList();
        for (const auto& key : key_list) {
          auto key_data = key.GetKeyData();
          if (key_data.IsValid()) {
            result.push_back(key_data);
          }
        }
      }
      if (!script_data.HasChild()) {
        break;
      }
      script_data = script_data.GetChild();
    } while (true);
  }
  return result;
}

std::string Descriptor::ToString(bool append_checksum) const {
  return root_node_.ToString(append_checksum);
}

DescriptorNode Descriptor::GetNode() const { return root_node_; }

}  // namespace core
}  // namespace cfd
