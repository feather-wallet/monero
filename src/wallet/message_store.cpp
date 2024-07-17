// Copyright (c) 2018-2022, The Monero Project

//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "message_store.h"
#include <boost/archive/portable_binary_iarchive.hpp>
#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/system/error_code.hpp>
#include <boost/filesystem.hpp>
#include <fstream>
#include <sstream>
#include "file_io_utils.h"
#include "storages/http_abstract_invoke.h"
#include "wallet_errors.h"
#include "serialization/binary_utils.h"
#include "common/base58.h"
#include "common/util.h"
#include "common/utf8.h"
#include "string_tools.h"
#include "string_coding.h"


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.mms"

namespace mms
{

message_store::message_store(std::unique_ptr<epee::net_utils::http::abstract_http_client> http_client) : m_transporter(std::move(http_client))
{
  m_active = false;
  m_auto_send = false;
  m_next_message_id = 1;
  m_num_authorized_signers = 0;
  m_num_required_signers = 0;
  m_nettype = cryptonote::network_type::UNDEFINED;
  m_run = true;
}

void message_store::init_from_setup_key(const multisig_wallet_state &state, const std::string &auto_config_token, const std::string &own_label)
{
  setup_key key;
  bool valid_setup_key = check_auto_config_token(auto_config_token, key);
  THROW_WALLET_EXCEPTION_IF(!valid_setup_key, tools::error::wallet_internal_error, "Invalid setup key");

  m_num_required_signers = key.threshold;
  m_num_authorized_signers = key.participants;
  m_signers.clear();
  m_messages.clear();
  m_next_message_id = 1;

  // The vector "m_signers" gets here once the required number of elements, one for each authorized signer,
  // and is never changed again. The rest of the code relies on "size(m_signers) == m_num_authorized_signers"
  // without further checks.
  authorized_signer signer;
  for (uint32_t i = 0; i < m_num_authorized_signers; ++i)
  {
    signer.me = signer.index == 0;    // Strict convention: The very first signer is fixed as / must be "me"
    m_signers.push_back(signer);
    signer.index++;
  }

  // the label gets set later
  authorized_signer &me = m_signers[0];
  crypto::generate_keys(me.public_key, me.secret_key);
  me.public_key_known = true;

  set_signer(state, 0, own_label, {});

  m_service_url = key.service_url;
  m_service_channel = key.service_channel;

  m_transporter.set_options(key.service_url, {});

  if (key.mode == setup_mode::automatic) {
    // TODO: make sure this gets wiped when we no longer need it
    m_auto_config_secret_key = key.key;
    crypto::secret_key_to_public_key(m_auto_config_secret_key , m_auto_config_public_key);
    m_auto_config_running = true;
  }

  m_nettype = state.nettype;
  set_active(true);
  m_filename = state.mms_file;
  save(state);
}

void message_store::init_from_recovery(const mms::multisig_wallet_state &state, const std::string &recovery, uint32_t signers, uint32_t total) {
    std::string prefix(RECOVERY_INFO_PREFIX);
    std::string recovery_sub(recovery.substr(prefix.length()));
    std::string decoded;
    bool r = tools::base58::decode(recovery_sub, decoded);
    THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, "Unable to decode recovery info");

    recovery_info info;
    try
    {
        binary_archive<false> ar{epee::strspan<std::uint8_t>(decoded)};
        THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, info), tools::error::wallet_internal_error, "Failed to deserialize MMS recovery info");
    }
    catch (...)
    {
        THROW_WALLET_EXCEPTION_IF(true, tools::error::wallet_internal_error, "Invalid structure of MMS recovery info");
    }

    m_num_required_signers = signers;
    m_num_authorized_signers = total;
    m_signers.clear();
    m_messages.clear();
    m_next_message_id = 1;

    authorized_signer signer;
    for (uint32_t i = 0; i < m_num_authorized_signers; ++i)
    {
        signer.me = signer.index == 0;
        m_signers.push_back(signer);
        signer.index++;
    }


    m_service_url = info.service_url;
    m_service_channel = info.service_channel;
    m_service_token = info.service_token;
    m_transporter.set_options(info.service_url, {});

    THROW_WALLET_EXCEPTION_IF(info.signer_info.size() != m_num_authorized_signers, tools::error::wallet_internal_error, "MMS recovery info does not contain enough signer info");

    authorized_signer &me = m_signers[0];
    me.secret_key = info.secret_key;

    // TODO: check if secret_key matches public_key

    for (size_t i = 0; i < m_num_authorized_signers; ++i) {
        authorized_signer &s = m_signers[i];
        auto_config_data &m = info.signer_info[i];

        s.label = m.label;
        s.public_key = m.public_key;
        s.public_key_known = true;
    }

    // TODO: verify the number of signers match m_num_authorized_signers

    m_nettype = state.nettype;
    set_active(true);
    m_filename = state.mms_file;
    save(state);
}

void message_store::set_service_details(const std::string &message_service_address, const epee::wipeable_string &message_service_login)
{
  // TODO: only the key creator should call this
  m_transporter.set_options(message_service_address, message_service_login);
}

std::string message_store::get_recovery_info(const multisig_wallet_state &state, uint64_t restore_height) {
  recovery_info info;

  authorized_signer &me = m_signers[0];
  info.secret_key = me.secret_key;

  info.service_url = m_service_url;
  info.service_channel = m_service_channel;
  info.service_token = m_service_token;

  info.restore_height = restore_height;

  for (size_t i = 0; i < m_num_authorized_signers; i++) {
      const authorized_signer &signer = m_signers[i];

      auto_config_data data;
      data.public_key = signer.public_key;
      data.label = signer.label;

      info.signer_info.push_back(data);
  }

  std::stringstream oss;
  binary_archive<true> ar(oss);
  THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, info), tools::error::wallet_internal_error, "Failed to serialize recovery info");
  std::string buf = oss.str();

  return RECOVERY_INFO_PREFIX + tools::base58::encode(buf);
}

void message_store::set_signer(const multisig_wallet_state &state,
                               uint32_t index,
                               const boost::optional<std::string> &label,
                               const boost::optional<crypto::public_key> &public_key)
{
  THROW_WALLET_EXCEPTION_IF(index >= m_num_authorized_signers, tools::error::wallet_internal_error, "Invalid signer index " + std::to_string(index));
  authorized_signer &m = m_signers[index];
  if (label)
  {
    m.label = get_sanitized_text(label.get(), 50);
  }
  if (public_key)
  {
    m.public_key_known = true;
    m.public_key = public_key.get();
  }
  // Save to minimize the chance to lose that info
  save(state);
}

const authorized_signer &message_store::get_signer(uint32_t index) const
{
  THROW_WALLET_EXCEPTION_IF(index >= m_num_authorized_signers, tools::error::wallet_internal_error, "Invalid signer index " + std::to_string(index));
  return m_signers[index];
}

bool message_store::signer_config_complete() const
{
  for (uint32_t i = 0; i < m_num_authorized_signers; ++i)
  {
    const authorized_signer &m = m_signers[i];
    if (m.label.empty() || !m.public_key_known)
    {
      return false;
    }
  }
  return true;
}

bool message_store::signer_keys_complete() const
{
  for (uint32_t i = 0; i < m_num_authorized_signers; ++i)
  {
    const authorized_signer &m = m_signers[i];
    if (!m.public_key_known)
    {
      return false;
    }
  }
  return true;
}

// Check if all signers have a label set (as it's a requirement for starting auto-config
// by the "manager")
bool message_store::signer_labels_complete() const
{
  for (uint32_t i = 0; i < m_num_authorized_signers; ++i)
  {
    const authorized_signer &m = m_signers[i];
    if (m.label.empty())
    {
      return false;
    }
  }
  return true;
}

void message_store::get_signer_config(std::string &signer_config)
{
  std::stringstream oss;
  binary_archive<true> ar(oss);
  THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, m_signers), tools::error::wallet_internal_error, "Failed to serialize signer config");
  signer_config = oss.str();
}

// Check auto-config token string and convert to standardized form;
// Try to make it as foolproof as possible, with built-in tolerance to make up for
// errors in transmission that still leave the token recognizable.
bool message_store::check_auto_config_token(const std::string &raw_token,
                                            setup_key &key) const
{
  std::string prefix(AUTO_CONFIG_TOKEN_PREFIX);
  uint32_t num_hex_digits = (AUTO_CONFIG_TOKEN_BYTES + 2) * 2;
  uint32_t full_length = num_hex_digits + prefix.length();
  uint32_t raw_length = raw_token.length();
  std::string hex_digits;

  // Prefix must be there; accept it in any casing
  std::string raw_prefix(raw_token.substr(0, 3));
  boost::algorithm::to_lower(raw_prefix);
  if (raw_prefix != prefix)
  {
    return false;
  }

  std::string base58 = raw_token.substr(3);

  std::string decoded;
  bool ok = tools::base58::decode(base58, decoded);

  if (!ok) {
    return false;
  }

  std::string hash_str = decoded.substr(decoded.length() - 2, 2);
  std::string uniform = decoded.substr(0, decoded.length() - 2);

  crypto::chacha_key k;
  crypto::generate_chacha_key(hash_str.data(), hash_str.size(), k, 1);

  std::string query;
  query.resize(uniform.size());
  crypto::chacha_iv iv = {0};
  crypto::chacha20(uniform.data(), uniform.size(), k, iv, &query[0]);

  binary_archive<false> ar{epee::strspan<std::uint8_t>(query)};
  if (!::serialization::serialize(ar, key)) {
    return false;
  }

  //
  // bool r = epee::serialization::load_t_from_binary(key, query);
  //
  // if (!r) {
  //   return false;
  // }

  // // Now it must be correct hex with correct checksum, no further tolerance possible
  // std::string token_bytes;
  // if (!epee::string_tools::parse_hexstr_to_binbuff(hex_digits, token_bytes))
  // {
  //   return false;
  // }
  // const crypto::hash &hash = crypto::cn_fast_hash(token_bytes.data(), token_bytes.size() - 2);
  // if (token_bytes[AUTO_CONFIG_TOKEN_BYTES] != hash.data[0])
  // {
  //   return false;
  // }
  // adjusted_token = prefix + hex_digits;

  // threshold = key.threshold;
  // total = key.participants;
  //
  // if (threshold < 1) {
  //   return false;
  // }
  //
  // if (total < threshold) {
  //   return false;
  // }
  //
  // if (threshold > 16) {
  //   return false;
  // }

  return true;
}

bool message_store::register_channel(std::string &channel, uint32_t user_limit) {
  return m_transporter.register_channel(channel, user_limit);
}

bool message_store::register_user() {
  if (!m_service_token.empty()) {
    return true;
  }

  authorized_signer &me = m_signers[0];
  m_transporter.register_user(m_service_channel, epee::string_tools::pod_to_hex(me.public_key), m_service_token);

  return true;
}

bool message_store::get_channel_users(const multisig_wallet_state &state, uint32_t &num_users) {
  if (signer_keys_complete()) {
    return true;
  }

  authorized_signer &me = m_signers[0];
  std::vector<std::string> users = m_transporter.get_channel_users(m_service_channel, m_service_token);

  num_users = users.size();

  std::vector<crypto::public_key> filtered_keys;
  for (const auto &user : users) {
    crypto::public_key key;
    THROW_WALLET_EXCEPTION_IF(!epee::string_tools::hex_to_pod(user, key), tools::error::wallet_internal_error, "Invalid user in channel");

    if (me.public_key == key) {
      continue;
    }

    filtered_keys.push_back(key);
  }

  if (filtered_keys.size() != (m_num_authorized_signers - 1)) {
    // TODO: inform GUI about lack of signers
    return false;
  }

  for (size_t i = 1; i < m_num_authorized_signers; i++) {
    authorized_signer &signer = m_signers[i];
    signer.public_key = filtered_keys[i-1];
    signer.public_key_known = true;
  }

  add_auto_config_data_messages(state);

  return true;
}

// Create a new setup key
std::string message_store::create_setup_key(uint32_t threshold, uint32_t total, const std::string &service, const std::string &channel, setup_mode mode) {
  THROW_WALLET_EXCEPTION_IF(threshold < 1, tools::error::wallet_internal_error, "Threshold can't be zero");
  THROW_WALLET_EXCEPTION_IF(total < threshold, tools::error::wallet_internal_error, "Total number of signers can't be lower than threshold");
  THROW_WALLET_EXCEPTION_IF(threshold > 16, tools::error::wallet_internal_error, "Threshold can't exceed 16");
  THROW_WALLET_EXCEPTION_IF(total > 255, tools::error::wallet_internal_error, "Total number of signers can't exceed 255");

  setup_key key;
  key.mode = mode;
  key.threshold = threshold;
  key.participants = total;
  key.service_url = service;
  key.service_channel = channel;
  key.key = rct::rct2sk(rct::skGen());

  // std::string query;
  // query += "v=0";
  // query += "&t=" + std::to_string(threshold);
  // query += "&p=" + std::to_string(total);
  // query += "&c=" + channel;
  // query += "&k=" + epee::string_tools::pod_to_hex(me.auto_config_public_key);
  // query += "&s=" + service;

  std::stringstream oss;
  binary_archive<true> ar(oss);
  THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, key), tools::error::wallet_internal_error, "Failed to serialize setup key");

  std::string query = oss.str();

  LOG_ERROR(query);

  std::string hash_str;
  const crypto::hash &hash = crypto::cn_fast_hash(query.data(), query.size());
  hash_str += hash.data[0];
  hash_str += hash.data[1];

  crypto::chacha_key k;
  crypto::generate_chacha_key(hash_str.data(), hash_str.size(), k, 1);

  std::string uniform;
  uniform.resize(query.size());
  crypto::chacha_iv iv = {0};
  crypto::chacha20(query.data(), query.size(), k, iv, &uniform[0]);

  return AUTO_CONFIG_TOKEN_PREFIX + tools::base58::encode(uniform + hash_str);
}

// Add a message for sending "me" address data to the auto-config transport address
// that can be derived from the token and activate auto-config
size_t message_store::add_auto_config_data_messages(const multisig_wallet_state &state)
{
  authorized_signer &me = m_signers[0];

  for (uint32_t i = 1; i < m_num_authorized_signers; ++i)
  {
    auto_config_data data;
    data.label = me.label;
    data.public_key = me.public_key;

    std::stringstream oss;
    binary_archive<true> ar(oss);
    THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, data), tools::error::wallet_internal_error, "Failed to serialize auto config data");

    add_message(state, i, message_type::auto_config_data, message_direction::out, oss.str());
  }

  return 0;
}

auto_config_data message_store::get_auto_config_data(uint32_t id)
{
  const message &m = get_message_ref_by_id(id);
  auto_config_data data;
  try
  {
    binary_archive<false> ar{epee::strspan<std::uint8_t>(m.content)};
    THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, data), tools::error::wallet_internal_error, "Failed to serialize auto config data");
  }
  catch (...)
  {
    THROW_WALLET_EXCEPTION_IF(true, tools::error::wallet_internal_error, "Invalid structure of auto config data");
  }
  return data;
}

std::vector<auto_config_data> message_store::get_auto_config_data()
{
  std::vector<auto_config_data> data;

  std::vector<crypto::public_key> public_keys;

  for (const auto &m : m_messages)
  {
    if ((m.type == message_type::auto_config_data))
    {
      auto d = get_auto_config_data(m.id);

      if (std::find(public_keys.begin(), public_keys.end(), d.public_key) != public_keys.end()) {
        continue;
      }

      public_keys.push_back(d.public_key);
      data.push_back(d);
    }
  }

  return data;
}

bool message_store::auto_config_data_complete(std::vector<uint32_t> &auto_config_messages)
{
  std::vector<uint32_t> filtered_messages;
  std::vector<crypto::public_key> public_keys;

  for (size_t i = 0; i < auto_config_messages.size(); i++)
  {
    auto data = get_auto_config_data(auto_config_messages[i]);

    // Don't include ourselves
    if (data.public_key == m_signers[0].public_key) {
      continue;
    }

    // Don't include duplicates
    if (std::find(public_keys.begin(), public_keys.end(), data.public_key) != public_keys.end()) {
      continue;
    }

    public_keys.push_back(data.public_key);
    filtered_messages.push_back(auto_config_messages[i]);
  }

  // TODO: if there are more messages than authorized signers throw some kind of error and abort setup
  if (filtered_messages.size() != (m_num_authorized_signers - 1)) {
    return false;
  }

  auto_config_messages = filtered_messages;
  return true;
}

// Process a single message with auto-config data, destined for "message.signer_index"
void message_store::process_auto_config_data_message(uint32_t id)
{
  const message &m = get_message_ref_by_id(id);

  auto_config_data data;
  try
  {
    binary_archive<false> ar{epee::strspan<std::uint8_t>(m.content)};
    THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, data), tools::error::wallet_internal_error, "Failed to serialize auto config data");
  }
  catch (...)
  {
    THROW_WALLET_EXCEPTION_IF(true, tools::error::wallet_internal_error, "Invalid structure of auto config data");
  }

  if (data.public_key == m_signers[0].public_key) {
    return;
  }

  uint32_t index;
  bool r =  get_signer_index_by_public_key(data.public_key, index);
  // TODO: make sure this call succeeds


  authorized_signer &signer = m_signers[index];
  signer.public_key_known = true;
  signer.public_key = data.public_key;
  MWARNING("Setting signer public key to: " << epee::string_tools::pod_to_hex(data.public_key));
  signer.label = data.label;
}

void add_hash(crypto::hash &sum, const crypto::hash &summand)
{
  for (uint32_t i = 0; i < crypto::HASH_SIZE; ++i)
  {
    uint32_t x = (uint32_t)sum.data[i];
    uint32_t y = (uint32_t)summand.data[i];
    sum.data[i] = (char)((x + y) % 256);
  }
}

// Calculate a checksum that allows signers to make sure they work with an identical signer config
// by exchanging and comparing checksums out-of-band i.e. not using the MMS;
// Because different signers have a different order of signers in the config work with "adding"
// individual hashes because that operation is commutative
std::string message_store::get_config_checksum() const
{
  crypto::hash sum = crypto::null_hash;
  uint32_t num = SWAP32LE(m_num_authorized_signers);
  add_hash(sum, crypto::cn_fast_hash(&num, sizeof(num)));
  num = SWAP32LE(m_num_required_signers);
  add_hash(sum, crypto::cn_fast_hash(&num, sizeof(num)));
  for (uint32_t i = 0; i < m_num_authorized_signers; ++i)
  {
    const authorized_signer &m = m_signers[i];
    if (m.public_key_known)
    {
      add_hash(sum, crypto::cn_fast_hash(&m.public_key, sizeof(m.public_key)));
    }
  }
  std::string checksum_bytes;
  checksum_bytes += sum.data[0];
  checksum_bytes += sum.data[1];
  checksum_bytes += sum.data[2];
  checksum_bytes += sum.data[3];
  return epee::string_tools::buff_to_hex_nodelimer(checksum_bytes);
}

void message_store::stop_auto_config()
{
  authorized_signer &me = m_signers[0];
  m_auto_config_running = false;
  m_auto_config_secret_key = crypto::null_skey;
}

bool message_store::get_signer_index_by_public_key(const crypto::public_key &public_key, uint32_t &index) const
{
  for (uint32_t i = 0; i < m_num_authorized_signers; ++i)
  {
    const authorized_signer &m = m_signers[i];
      MWARNING("We have a signer with public_key: " << epee::string_tools::pod_to_hex(m.public_key));
    if (m.public_key == public_key)
    {
      index = m.index;
      return true;
    }
  }
  MWARNING("No authorized signer with Monero address " << epee::string_tools::pod_to_hex(public_key));
  return false;
}

bool message_store::get_signer_index_by_label(const std::string label, uint32_t &index) const
{
  for (uint32_t i = 0; i < m_num_authorized_signers; ++i)
  {
    const authorized_signer &m = m_signers[i];
    if (m.label == label)
    {
      index = m.index;
      return true;
    }
  }
  MWARNING("No authorized signer with label " << label);
  return false;
}

void message_store::process_wallet_created_data(const multisig_wallet_state &state, message_type type, const std::string &content, std::vector<uint32_t> &ids)
{
  switch(type)
  {
  case message_type::key_set:
    // Result of a "prepare_multisig" command in the wallet
    // Send the key set to all other signers
  case message_type::additional_key_set:
    // Result of a "make_multisig" command or a "exchange_multisig_keys" in the wallet in case of M/N multisig
    // Send the additional key set to all other signers
  case message_type::multisig_sync_data:
    // Result of a "export_multisig_info" command in the wallet
    // Send the sync data to all other signers
    for (uint32_t i = 1; i < m_num_authorized_signers; ++i)
    {
      uint32_t id = 0;
      add_message(state, i, type, message_direction::out, content, &id);
      ids.push_back(id);
    }
    break;

  case message_type::partially_signed_tx: {
      // Result of a "transfer" command in the wallet, or a "sign_multisig" command
      // that did not yet result in the minimum number of signatures required
      // Create a message "from me to me" as a container for the tx data
      if (m_num_required_signers == 1) {
          // Probably rare, but possible: The 1 signature is already enough, correct the type
          // Easier to correct here than asking all callers to detect this rare special case
          type = message_type::fully_signed_tx;
      }
      uint32_t id = 0;
      add_message(state, 0, type, message_direction::in, content, &id);
      ids.push_back(id);
      break;
  }
  case message_type::fully_signed_tx: {
      uint32_t id = 0;
      add_message(state, 0, type, message_direction::in, content, &id);
      ids.push_back(id);
      break;
  }
  default:
    THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, "Illegal message type " + std::to_string((uint32_t)type));
    break;
  }
}

size_t message_store::add_message(const multisig_wallet_state &state,
                                  uint32_t signer_index, message_type type, message_direction direction,
                                  const std::string &content, uint32_t *message_id)
{
  message m;
  m.id = m_next_message_id++;
  m.type = type;
  m.direction = direction;
  m.content = content;
  m.created = (uint64_t)time(NULL);
  m.modified = m.created;
  m.sent = 0;
  m.signer_index = signer_index;
  if (direction == message_direction::out)
  {
    m.state = message_state::ready_to_send;
  }
  else
  {
    m.state = message_state::waiting;
  };
  m.wallet_height = (uint32_t)state.num_transfer_details;
  if (m.type == message_type::additional_key_set)
  {
    m.round = state.multisig_rounds_passed;
  }
  else
  {
    m.round = 0;
  }
  m.signature_count = 0;  // Future expansion for signature counting when signing txs
  m.hash = crypto::null_hash;
  m_messages.push_back(m);

  // Save for every new message right away (at least while in beta)
  save(state);

  MINFO(boost::format("Added %s message %s for signer %s of type %s")
          % message_direction_to_string(direction) % m.id % signer_index % message_type_to_string(type));

  if (message_id) {
      *message_id = m.id;
  }

  return m_messages.size() - 1;
}

// Get the index of the message with id "id", return false if not found
bool message_store::get_message_index_by_id(uint32_t id, size_t &index) const
{
  for (size_t i = 0; i < m_messages.size(); ++i)
  {
    if (m_messages[i].id == id)
    {
      index = i;
      return true;
    }
  }
  MWARNING("No message found with an id of " << id);
  return false;
}

// Get the index of the message with id "id" that must exist
size_t message_store::get_message_index_by_id(uint32_t id) const
{
  size_t index;
  bool found = get_message_index_by_id(id, index);
  THROW_WALLET_EXCEPTION_IF(!found, tools::error::wallet_internal_error, "Invalid message id " + std::to_string(id));
  return index;
}

// Get the modifiable message with id "id" that must exist; private/internal use!
message& message_store::get_message_ref_by_id(uint32_t id)
{
  return m_messages[get_message_index_by_id(id)];
}

// Get the message with id "id", return false if not found
// This version of the method allows to check whether id is valid without triggering an error
bool message_store::get_message_by_id(uint32_t id, message &m) const
{
  size_t index;
  bool found = get_message_index_by_id(id, index);
  if (found)
  {
    m = m_messages[index];
  }
  return found;
}

// Get the message with id "id" that must exist
message message_store::get_message_by_id(uint32_t id) const
{
  message m;
  bool found = get_message_by_id(id, m);
  THROW_WALLET_EXCEPTION_IF(!found, tools::error::wallet_internal_error, "Invalid message id " + std::to_string(id));
  return m;
}

bool message_store::any_message_of_type(message_type type, message_direction direction) const
{
  for (size_t i = 0; i < m_messages.size(); ++i)
  {
    if ((m_messages[i].type == type) && (m_messages[i].direction == direction))
    {
      return true;
    }
  }
  return false;
}

bool message_store::any_message_with_hash(const crypto::hash &hash) const
{
  for (size_t i = 0; i < m_messages.size(); ++i)
  {
    if (m_messages[i].hash == hash)
    {
      return true;
    }
  }
  return false;
}

// Count the ids in the vector that are set i.e. not 0, while ignoring index 0
// Mostly used to check whether we have a message for each authorized signer except me,
// with the signer index used as index into 'ids'; the element at index 0, for me,
// is ignored, to make constant subtractions of 1 for indices when filling the
// vector unnecessary
size_t message_store::get_other_signers_id_count(const std::vector<uint32_t> &ids) const
{
  size_t count = 0;
  for (size_t i = 1 /* and not 0 */; i < ids.size(); ++i)
  {
    if (ids[i] != 0)
    {
      count++;
    }
  }
  return count;
}

// Is in every element of vector 'ids' (except at index 0) a message id i.e. not 0?
bool message_store::message_ids_complete(const std::vector<uint32_t> &ids) const
{
  return get_other_signers_id_count(ids) == (ids.size() - 1);
}

void message_store::delete_message(uint32_t id)
{
  size_t index = get_message_index_by_id(id);
  m_messages.erase(m_messages.begin() + index);
}

void message_store::delete_all_messages()
{
  m_messages.clear();
}

// Make a text, which is "attacker controlled data", reasonably safe to display
// This is mostly geared towards the safe display of notes sent by "mms note" with a "mms show" command
std::string message_store::get_sanitized_text(const std::string &text, size_t max_length)
{
  // Restrict the size to fend of DOS-style attacks with heaps of data
  size_t length = std::min(text.length(), max_length);
  std::string sanitized_text = text.substr(0, length);

  try
  {
    sanitized_text = tools::utf8canonical(sanitized_text, [](wint_t c)
    {
      if ((c < 0x20) || (c == 0x7f) || (c >= 0x80 && c <= 0x9f))
      {
        // Strip out any controls, especially ESC for getting rid of potentially dangerous
        // ANSI escape sequences that a console window might interpret
        c = '?';
      }
      else if ((c == '<') || (c == '>'))
      {
        // Make XML or HTML impossible that e.g. might contain scripts that Qt might execute
        // when displayed in the GUI wallet
        c = '?';
      }
      return c;
    });
  }
  catch (const std::exception &e)
  {
    sanitized_text = "(Illegal UTF-8 string)";
  }
  return sanitized_text;
}

void message_store::write_to_file(const multisig_wallet_state &state, const std::string &filename)
{
  std::stringstream oss;
  binary_archive<true> ar(oss);
  THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, *this), tools::error::wallet_internal_error, "Failed to serialize MMS state");
  std::string buf = oss.str();

  crypto::chacha_key key;
  crypto::generate_chacha_key(&state.view_secret_key, sizeof(crypto::secret_key), key, 1);

  file_data write_file_data = {};
  write_file_data.magic_string = "MMS";
  write_file_data.file_version = 0;
  write_file_data.iv = crypto::rand<crypto::chacha_iv>();
  std::string encrypted_data;
  encrypted_data.resize(buf.size());
  crypto::chacha20(buf.data(), buf.size(), key, write_file_data.iv, &encrypted_data[0]);
  write_file_data.encrypted_data = encrypted_data;

  std::stringstream file_oss;
  binary_archive<true> file_ar(file_oss);
  THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(file_ar, write_file_data), tools::error::wallet_internal_error, "Failed to serialize MMS state");

  bool success = epee::file_io_utils::save_string_to_file(filename, file_oss.str());
  THROW_WALLET_EXCEPTION_IF(!success, tools::error::file_save_error, filename);
}

void message_store::read_from_file(const multisig_wallet_state &state, const std::string &filename, bool load_deprecated_formats)
{
  boost::system::error_code ignored_ec;
  bool file_exists = boost::filesystem::exists(filename, ignored_ec);
  if (!file_exists)
  {
    // Simply do nothing if the file is not there; allows e.g. easy recovery
    // from problems with the MMS by deleting the file
    MINFO("No message store file found: " << filename);
    return;
  }

  std::string buf;
  bool success = epee::file_io_utils::load_file_to_string(filename, buf);
  THROW_WALLET_EXCEPTION_IF(!success, tools::error::file_read_error, filename);

  bool loaded = false;
  file_data read_file_data;
  try
  {
    binary_archive<false> ar{epee::strspan<std::uint8_t>(buf)};
    if (::serialization::serialize(ar, read_file_data))
      if (::serialization::check_stream_state(ar))
        loaded = true;
  }
  catch (...) {}
  if (!loaded)
  {
    MERROR("MMS file " << filename << " has bad structure <iv,encrypted_data>");
    THROW_WALLET_EXCEPTION_IF(true, tools::error::file_read_error, filename);
  }

  crypto::chacha_key key;
  crypto::generate_chacha_key(&state.view_secret_key, sizeof(crypto::secret_key), key, 1);
  std::string decrypted_data;
  decrypted_data.resize(read_file_data.encrypted_data.size());
  crypto::chacha20(read_file_data.encrypted_data.data(), read_file_data.encrypted_data.size(), key, read_file_data.iv, &decrypted_data[0]);

  loaded = false;
  try
  {
    binary_archive<false> ar{epee::strspan<std::uint8_t>(decrypted_data)};
    if (::serialization::serialize(ar, *this))
      if (::serialization::check_stream_state(ar))
        loaded = true;
  }
  catch(...) {}
  if (!loaded)
  {
    MERROR("MMS file " << filename << " has bad structure");
    THROW_WALLET_EXCEPTION_IF(true, tools::error::file_read_error, filename);
  }

  m_transporter.set_options(m_service_url, {});
  m_filename = filename;
}

// Save to the same file this message store was loaded from
// Called after changes deemed "important", to make it less probable to lose messages in case of
// a crash; a better and long-term solution would of course be to use LMDB ...
void message_store::save(const multisig_wallet_state &state)
{
  if (!m_filename.empty())
  {
    write_to_file(state, m_filename);
  }
}

bool message_store::process_sync_data(std::vector<uint32_t> &message_ids)
{
    message_ids.resize(m_num_authorized_signers, 0);
    for (auto &m : m_messages)
    {
        if (m.type == message_type::multisig_sync_data)
        {
            if (m.direction == message_direction::in) // Reimport processed sync data
            {
                // Take last
                message_ids[m.signer_index] = m.id;
            }
            // set message processed or sent
            m.state = mms::message_state::processed;
        }
    }

    for (auto id : message_ids) {
        if (id == 0) {
            return false;
        }
    }

    return true;
}

bool message_store::get_processable_messages(const multisig_wallet_state &state,
                                             bool force_sync, std::vector<processing_data> &data_list, std::string &wait_reason)
{
  data_list.clear();
  wait_reason.clear();
  // In all scans over all messages looking for complete sets (1 message for each signer),
  // if there are duplicates, the OLDEST of them is taken. This may not play a role with
  // any of the current message types, but may with future ones, and it's probably a good
  // idea to have a clear and somewhat defensive strategy.

  const authorized_signer &me = m_signers[0];

  std::vector<uint32_t> auto_config_messages;
  bool any_auto_config = false;

  std::vector<uint32_t> introduction_messages;
  bool any_introduction_message = false;

  if (m_auto_config_running) {
    // We have imported introduction keys, but
    if (!any_message_of_type(message_type::auto_config_data, message_direction::out)) {
      // we haven't sent our signe

      processing_data data;
      data.processing = message_processing::add_auto_config_data;
      data_list.push_back(data);
      return true;
    }

    for (const auto &m : m_messages)
    {
      if ((m.type == message_type::auto_config_data) && m.direction == message_direction::in)
      {
        auto_config_messages.push_back(m.id);
        any_auto_config = true;
      }
    }

    if (any_auto_config)
    {
      LOG_ERROR("We have auto config data waiting");
      if (auto_config_messages.size() < (m_num_authorized_signers - 1)) {
        wait_reason = "Waiting for signer info (" + std::to_string(auto_config_messages.size()) + "/" + std::to_string(m_num_authorized_signers - 1) + ")";
        return false;
      }

      if (auto_config_messages.size() <= (m_num_authorized_signers-1)) {
        processing_data data;
        data.processing = message_processing::process_auto_config_data;
        data.message_ids = auto_config_messages;
        data_list.push_back(data);
        return true;
      }
      else
      {
        wait_reason = tr("Auto-config cannot proceed because auto config data from other signers is not complete");
        return false;
        // With ANY auto config data present but not complete refuse to check for any
        // other processing. Manually delete those messages to abort such an auto config
        // phase if needed.
      }
    }
  }

  // ALL of the following processings depend on the signer info being complete
  if (!signer_config_complete())
  {
    wait_reason = tr("Something went wrong: the signer config is not complete, setup aborted.");
    return false;
  }

  if (!state.multisig)
  {
    
    if (!any_message_of_type(message_type::key_set, message_direction::out))
    {
      // With the own key set not yet ready we must do "prepare_multisig" first;
      // Key sets from other signers may be here already, but if we process them now
      // the wallet will go multisig too early: we can't produce our own key set any more!
      processing_data data;
      data.processing = message_processing::prepare_multisig;
      data_list.push_back(data);
      return true;
    }

    // Ids of key set messages per signer index, to check completeness
    // Naturally, does not care about the order of the messages and is trivial to secure against
    // key sets that were received more than once
    // With full M/N multisig now possible consider only key sets of the right round, i.e.
    // with not yet multisig the only possible round 0
    std::vector<uint32_t> key_set_messages(m_num_authorized_signers, 0);

    for (size_t i = 0; i < m_messages.size(); ++i)
    {
      message &m = m_messages[i];
      if ((m.type == message_type::key_set) && (m.state == message_state::waiting)
          && (m.round == 0))
      {
        if (key_set_messages[m.signer_index] == 0)
        {
          key_set_messages[m.signer_index] = m.id;
        }
        // else duplicate key set, ignore
      }
    }

    bool key_sets_complete = message_ids_complete(key_set_messages);
    if (key_sets_complete)
    {
      // Nothing else can be ready to process earlier than this, ignore everything else and give back
      processing_data data;
      data.processing = message_processing::make_multisig;
      data.message_ids = key_set_messages;
      data.message_ids.erase(data.message_ids.begin());
      data_list.push_back(data);
      return true;
    }
    else
    {
      wait_reason = tr("Wallet can't go multisig because key sets from other signers are missing or not complete.");
      return false;
    }
  }

  if (state.multisig && !state.multisig_is_ready)
  {
    // In the case of M/N multisig the call 'wallet2::multisig' returns already true
    // after "make_multisig" but with calls to "exchange_multisig_keys" still needed, and
    // sets the parameter 'ready' to false to document this particular "in-between" state.
    // So what may be possible here, with all necessary messages present, is a call to
    // "exchange_multisig_keys".
    // Consider only messages belonging to the next round to do, which has the number
    // "state.multisig_rounds_passed".
    std::vector<uint32_t> additional_key_set_messages(m_num_authorized_signers, 0);

    for (size_t i = 0; i < m_messages.size(); ++i)
    {
      message &m = m_messages[i];
      if ((m.type == message_type::additional_key_set) && (m.state == message_state::waiting)
         && (m.round == state.multisig_rounds_passed))
      {
        if (additional_key_set_messages[m.signer_index] == 0)
        {
          additional_key_set_messages[m.signer_index] = m.id;
        }
        // else duplicate key set, ignore
      }
    }

    bool key_sets_complete = message_ids_complete(additional_key_set_messages);
    if (key_sets_complete)
    {
      processing_data data;
      data.processing = message_processing::exchange_multisig_keys;
      data.message_ids = additional_key_set_messages;
      data.message_ids.erase(data.message_ids.begin());
      data_list.push_back(data);
      return true;
    }
    else
    {
      wait_reason = tr("Wallet can't start another key exchange round because key sets from other signers are missing or not complete.");
      return false;
    }
  }

  bool waiting_found = false;
  bool note_found = false;
  bool sync_data_found = false;
  for (size_t i = 0; i < m_messages.size(); ++i)
  {
    message &m = m_messages[i];
    if (m.state == message_state::waiting)
    {
      waiting_found = true;
      switch (m.type)
      {
      case message_type::fully_signed_tx:
      {
        // We can either submit it ourselves, or send it to any other signer for submission
        processing_data data;
        data.processing = message_processing::submit_tx;
        data.message_ids.push_back(m.id);
        data_list.push_back(data);

        data.processing = message_processing::send_tx;
        for (uint32_t j = 1; j < m_num_authorized_signers; ++j)
        {
          data.receiving_signer_index = j;
          data_list.push_back(data);
        }
        return true;
      }

      case message_type::partially_signed_tx:
      {
        if (m.signer_index == 0)
        {
          // We started this ourselves, or signed it but with still signatures missing:
          // We can send it to any other signer for signing / further signing
          // In principle it does not make sense to send it back to somebody who
          // already signed, but the MMS does not / not yet keep track of that,
          // because that would be somewhat complicated.
          processing_data data;
          data.processing = message_processing::send_tx;
          data.message_ids.push_back(m.id);
          for (uint32_t j = 1; j < m_num_authorized_signers; ++j)
          {
            data.receiving_signer_index = j;
            data_list.push_back(data);
          }
          return true;
        }
        else
        {
          // Somebody else sent this to us: We can sign it
          // It would be possible to just pass it on, but that's not directly supported here
          processing_data data;
          data.processing = message_processing::sign_tx;
          data.message_ids.push_back(m.id);
          data_list.push_back(data);
          return true;
        }
      }

      case message_type::note:
        note_found = true;
        break;

      case message_type::multisig_sync_data:
        sync_data_found = true;
        break;

      default:
        break;
      }
    }
  }
  if (waiting_found)
  {
    wait_reason = tr("There are waiting messages, but nothing is ready to process under normal circumstances");
    if (sync_data_found)
    {
      wait_reason += tr("\nUse \"mms next sync\" if you want to force processing of the waiting sync data");
    }
    if (note_found)
    {
      wait_reason += tr("\nUse \"mms note\" to display the waiting notes");
    }
  }
  else
  {
    wait_reason = tr("There are no messages waiting to be processed.");
  }

  return false;
}

void message_store::set_messages_processed(const processing_data &data)
{
  for (size_t i = 0; i < data.message_ids.size(); ++i)
  {
    set_message_processed_or_sent(data.message_ids[i]);
  }
}

void message_store::set_message_processed_or_sent(uint32_t id)
{
  message &m = get_message_ref_by_id(id);
  if (m.state == message_state::waiting)
  {
    // So far a fairly cautious and conservative strategy: Only delete from Bitmessage
    // when fully processed (and e.g. not already after reception and writing into
    // the message store file)
//    delete_transport_message(id);
    m.state = message_state::processed;
  }
  else if (m.state == message_state::ready_to_send)
  {
    m.state = message_state::sent;
  }
  m.modified = (uint64_t)time(NULL);
}

void message_store::encrypt(crypto::public_key public_key, const std::string &plaintext,
                            std::string &ciphertext, crypto::public_key &encryption_public_key, crypto::chacha_iv &iv)
{
  crypto::secret_key encryption_secret_key;
  crypto::generate_keys(encryption_public_key, encryption_secret_key);

  crypto::key_derivation derivation;
  bool success = crypto::generate_key_derivation(public_key, encryption_secret_key, derivation);
  THROW_WALLET_EXCEPTION_IF(!success, tools::error::wallet_internal_error, "Failed to generate key derivation for message encryption");

  crypto::chacha_key chacha_key;
  crypto::generate_chacha_key(&derivation, sizeof(derivation), chacha_key, 1);
  iv = crypto::rand<crypto::chacha_iv>();
  ciphertext.resize(plaintext.size());
  crypto::chacha20(plaintext.data(), plaintext.size(), chacha_key, iv, &ciphertext[0]);
}

void message_store::decrypt(const std::string &ciphertext, const crypto::public_key &encryption_public_key, const crypto::chacha_iv &iv,
                            const crypto::secret_key &secret_key, std::string &plaintext)
{
  crypto::key_derivation derivation;
  bool success = crypto::generate_key_derivation(encryption_public_key, secret_key, derivation);
  THROW_WALLET_EXCEPTION_IF(!success, tools::error::wallet_internal_error, "Failed to generate key derivation for message decryption");
  crypto::chacha_key chacha_key;
  crypto::generate_chacha_key(&derivation, sizeof(derivation), chacha_key, 1);
  plaintext.resize(ciphertext.size());
  crypto::chacha20(ciphertext.data(), ciphertext.size(), chacha_key, iv, &plaintext[0]);
}

void message_store::send_message(const multisig_wallet_state &state, uint32_t id)
{
  message &m = get_message_ref_by_id(id);
  const authorized_signer &me = m_signers[0];
  const authorized_signer &receiver = m_signers[m.signer_index];
  transport_message dm;
  crypto::public_key public_key;

  std::string recipient;

  dm.timestamp = (uint64_t)time(nullptr);
  dm.source_public_key = me.public_key;

  if (m.type == message_type::auto_config_data)
  {
    // Encrypt with the public key derived from the auto-config token, and send to the
    // transport address likewise derived from that token
    public_key = m_auto_config_public_key;
  }
  else {
    // Encrypt with the receiver's view public key
    public_key = receiver.public_key;
  }

  dm.destination_public_key = receiver.public_key;
  dm.content = m.content;

  recipient = epee::string_tools::pod_to_hex(receiver.public_key);

  dm.type = (uint32_t)m.type;
  dm.round = m.round;

  encrypted_message em;
  std::string json_content = epee::serialization::store_t_to_json(dm);

  encrypt(public_key, json_content, em.message, em.encryption_public_key, em.iv);

  em.hash = crypto::cn_fast_hash(em.message.data(), em.message.size());

  // TODO: Sign with setup key signer info?
  crypto::generate_signature(em.hash, me.public_key, me.secret_key, em.signature);

  std::string sender = epee::string_tools::pod_to_hex(me.public_key);

  if (m.type == mms::message_type::multisig_sync_data) {
    m_transporter.send_pinned_message(em, m_service_channel, m_service_token, recipient);
  }
  else {
    m_transporter.send_message(em, m_service_channel, m_service_token, recipient);
  }

  m.state=message_state::sent;
  m.sent= (uint64_t)time(nullptr);
}

bool message_store::check_for_messages(const multisig_wallet_state &state, std::vector<message> &messages)
{
  m_run.store(true, std::memory_order_relaxed);
  const authorized_signer &me = m_signers[0];


  std::string last_id;
  std::vector<encrypted_message> encrypted_messages;
  if (!m_transporter.receive_messages(m_service_channel, m_service_token, m_last_processed_message, encrypted_messages, last_id))
  {
    return false;
  }
  if (!m_run.load(std::memory_order_relaxed))
  {
    // Stop was called, don't waste time processing the messages
    // (but once started processing them, don't react to stop request anymore, avoid receiving them "partially)"
    return false;
  }

  if (encrypted_messages.empty()) {
    return false;
  }

  bool new_messages = false;
  for (size_t i = 0; i < encrypted_messages.size(); ++i)
  {
    encrypted_message &rm = encrypted_messages[i];
    if (any_message_with_hash(rm.hash))
    {
        LOG_ERROR("We already saw this message");
        continue;
      // Already seen, do not take again
    }

    crypto::hash actual_hash = crypto::cn_fast_hash(rm.message.data(), rm.message.size());
    THROW_WALLET_EXCEPTION_IF(actual_hash != rm.hash, tools::error::wallet_internal_error, "Message hash mismatch");

    // Decrypt here?

    crypto::secret_key decrypt_key;
    if (m_auto_config_running) {
      decrypt_key = m_auto_config_secret_key;
    }
    else {
      decrypt_key = me.secret_key;
    }

    std::string plaintext;
    decrypt(rm.message, rm.encryption_public_key, rm.iv, decrypt_key, plaintext);

    transport_message tm;
    if (!epee::serialization::load_t_from_json(tm, plaintext))
    {
      // TODO: get rid of this double decrypt
      decrypt(rm.message, rm.encryption_public_key, rm.iv, me.secret_key, plaintext);
      if (!epee::serialization::load_t_from_json(tm, plaintext)) {
        MERROR("Failed to deserialize messages");
        continue;
      }
    }

    bool signature_valid = crypto::check_signature(actual_hash, tm.source_public_key, rm.signature);
    THROW_WALLET_EXCEPTION_IF(!signature_valid, tools::error::wallet_internal_error, "Message signature not valid");

    uint32_t sender_index;

//    if (m_auto_config_running) {
//      // if (m_waiting_for_introduction_key && (message_type)tm.type != mms::message_type::introduction_key) {
//      //   MERROR("Invalid message type");
//      //   continue;
//      // }
//      // elif ((message_type)tm.type != mms::message_type::auto_config_data) {
//      //   MERROR("Invalid message type during auto config");
//      //   continue;
//      // }
//
//      // We haven't assigned signer indexes at this point, so just use 0
//      sender_index = 0;
//    } else {
      // Only accept from senders that are known as signer here, otherwise just ignore
      bool known_sender = get_signer_index_by_public_key(tm.source_public_key, sender_index);

      if (!known_sender) {
        MERROR("Sender unknown");
        continue;
      }
//    }

    // TODO: If we receive multisig_sync_data, set all previously received multisig_sync_data from that co-signer to "processed"

    size_t index = add_message(state, sender_index, (message_type)tm.type, message_direction::in, tm.content);
    message &m = m_messages[index];
    m.hash = rm.hash;
    m.sent = tm.timestamp;
    m.round = tm.round;
    messages.push_back(m);
    new_messages = true;
  }

  m_last_processed_message = last_id;

  return new_messages;
}

const char* message_store::message_type_to_string(message_type type)
{
  switch (type)
  {
  case message_type::key_set:
    return tr("key set");
  case message_type::additional_key_set:
    return tr("additional key set");
  case message_type::multisig_sync_data:
    return tr("multisig info");
  case message_type::partially_signed_tx:
    return tr("partially signed tx");
  case message_type::fully_signed_tx:
    return tr("fully signed tx");
  case message_type::note:
    return tr("note");
  case message_type::signer_config:
    return tr("signer config");
  case message_type::auto_config_data:
    return tr("auto-config data");
  default:
    return tr("unknown message type");
  }
}

const char* message_store::message_direction_to_string(message_direction direction)
{
  switch (direction)
  {
  case message_direction::in:
    return tr("in");
  case message_direction::out:
    return tr("out");
  default:
    return tr("unknown message direction");
  }
}

const char* message_store::message_state_to_string(message_state state)
{
  switch (state)
  {
  case message_state::ready_to_send:
    return tr("ready to send");
  case message_state::sent:
    return tr("sent");
  case message_state::waiting:
    return tr("waiting");
  case message_state::processed:
    return tr("processed");
  case message_state::cancelled:
    return tr("cancelled");
  default:
    return tr("unknown message state");
  }
}

// Convert a signer to string suitable for a column in a list, with 'max_width'
// Format: label: transport_address
std::string message_store::signer_to_string(const authorized_signer &signer, uint32_t max_width)
{
  return signer.label;
}

}
