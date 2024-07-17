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

#pragma once

#include <cstdlib>
#include <string>
#include <vector>
#include "crypto/hash.h"
#include <boost/serialization/vector.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/optional/optional.hpp>
#include "serialization/serialization.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_basic/account_boost_serialization.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "common/i18n.h"
#include "common/command_line.h"
#include "wipeable_string.h"
#include "net/abstract_http_client.h"
#include "serialization/crypto.h"
#include "serialization/string.h"
#include "serialization/containers.h"
#include "message_transporter.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.mms"
#define AUTO_CONFIG_TOKEN_BYTES 35
#define AUTO_CONFIG_TOKEN_PREFIX "mms"
#define RECOVERY_INFO_PREFIX "MMS_RECOVERY-"

namespace mms
{
  enum class message_type
  {
    key_set,
    additional_key_set,
    multisig_sync_data,
    partially_signed_tx,
    fully_signed_tx,
    note,
    signer_config,
    auto_config_data,
    introduction_key
  };

  enum class message_direction
  {
    in,
    out
  };

  enum class message_state
  {
    ready_to_send,
    sent,

    waiting,
    processed,

    cancelled
  };

  enum class message_processing
  {
    prepare_multisig,
    make_multisig,
    exchange_multisig_keys,
    create_sync_data,
    process_sync_data,
    sign_tx,
    send_tx,
    submit_tx,
    process_signer_config,
    add_auto_config_data,
    process_auto_config_data,
    process_introduction_keys,
  };

  struct message
  {
    uint32_t id;
    message_type type;
    message_direction direction;
    std::string content;
    uint64_t created;
    uint64_t modified;
    uint64_t sent;
    uint32_t signer_index;
    crypto::hash hash;
    message_state state;
    uint32_t wallet_height;
    uint32_t round;
    uint32_t signature_count;
    std::string transport_id;

    BEGIN_SERIALIZE_OBJECT()
      VERSION_FIELD(0)
      VARINT_FIELD(id)
      VARINT_FIELD(type)
      VARINT_FIELD(direction)
      FIELD(content)
      VARINT_FIELD(created)
      VARINT_FIELD(modified)
      VARINT_FIELD(sent)
      VARINT_FIELD(signer_index)
      FIELD(hash)
      VARINT_FIELD(state)
      VARINT_FIELD(wallet_height)
      VARINT_FIELD(round)
      VARINT_FIELD(signature_count)
      FIELD(transport_id)
    END_SERIALIZE()
  };
  // "wallet_height" (for lack of a short name that would describe what it is about)
  // is the number of transfers present in the wallet at the time of message
  // construction; used to coordinate generation of sync info (which depends
  // on the content of the wallet at time of generation)

  struct authorized_signer
  {
    std::string label;
    bool public_key_known;
    crypto::secret_key secret_key;
    crypto::public_key public_key;
    bool me;
    uint32_t index;

    BEGIN_SERIALIZE_OBJECT()
      VERSION_FIELD(0)
      FIELD(label)
      FIELD(public_key_known)
      FIELD(secret_key)
      FIELD(public_key)
      FIELD(me)
      VARINT_FIELD(index)
    END_SERIALIZE()

    authorized_signer()
    {
      public_key_known = false;
      public_key = crypto::null_pkey;
      me = false;
      index = 0;
    };
  };

  struct processing_data
  {
    message_processing processing;
    std::vector<uint32_t> message_ids;
    uint32_t receiving_signer_index = 0;
  };
  
  struct auto_config_data
  {
    std::string label;
    crypto::public_key public_key;

    BEGIN_SERIALIZE_OBJECT()
      VERSION_FIELD(0)
      FIELD(label)
      FIELD(public_key)
    END_SERIALIZE()
  };

  struct introduction_key {
    crypto::public_key key;

    BEGIN_SERIALIZE_OBJECT()
      VERSION_FIELD(0)
      FIELD(key)
    END_SERIALIZE()
  };

  // Overal .mms file structure, with the "message_store" object serialized to and
  // encrypted in "encrypted_data"
  struct file_data
  {
    std::string magic_string;
    uint32_t file_version;
    crypto::chacha_iv iv;
    std::string encrypted_data;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(magic_string)
      FIELD(file_version)
      FIELD(iv)
      FIELD(encrypted_data)
    END_SERIALIZE()
  };

    // The following struct provides info about the current state of a "wallet2" object
  // at the time of a "message_store" method call that those methods need. See on the
  // one hand a first parameter of this type for several of those methods, and on the
  // other hand the method "wallet2::get_multisig_wallet_state" which clients like the
  // CLI wallet can use to get that info.
  //
  // Note that in the case of a wallet that is already multisig "address" is NOT the
  // multisig address, but the "original" wallet address at creation time. Likewise
  // "view_secret_key" is the original view secret key then.
  //
  // This struct definition is here and not in "wallet2.h" to avoid circular imports.
  struct multisig_wallet_state
  {
    cryptonote::account_public_address address;
    cryptonote::network_type nettype;
    crypto::secret_key view_secret_key;
    bool multisig;
    bool multisig_is_ready;
    bool has_multisig_partial_key_images;
    uint32_t multisig_rounds_passed;
    size_t num_transfer_details;
    std::string mms_file;

    BEGIN_SERIALIZE_OBJECT()
      VERSION_FIELD(0)
      VARINT_FIELD(nettype)
      FIELD(view_secret_key)
      FIELD(multisig)
      FIELD(multisig_is_ready)
      FIELD(has_multisig_partial_key_images)
      VARINT_FIELD(multisig_rounds_passed)
      VARINT_FIELD(num_transfer_details)
      FIELD(mms_file)
    END_SERIALIZE()
  };

  enum class setup_mode {
    automatic,
    semi_automatic,
    manual,
  };

  struct setup_key
  {
    setup_mode mode = setup_mode::automatic;
    uint32_t threshold = 0;
    uint32_t participants = 0;
    std::string service_url;
    std::string service_channel;
    crypto::secret_key key;

    BEGIN_SERIALIZE_OBJECT()
      VERSION_FIELD(0)
      VARINT_FIELD(mode)
      VARINT_FIELD(threshold)
      VARINT_FIELD(participants)
      FIELD(service_url)
      FIELD(service_channel)
      FIELD(key)
    END_SERIALIZE()
  };

  struct recovery_info
  {
      std::string service_url;
      std::string service_channel;
      std::string service_token;

      crypto::secret_key secret_key;
      std::vector<auto_config_data> signer_info;
      uint64_t restore_height = 0;

      BEGIN_SERIALIZE_OBJECT()
          VERSION_FIELD(0)
          FIELD(service_url)
          FIELD(service_channel)
          FIELD(service_token)
          FIELD(secret_key)
          FIELD(signer_info)
          VARINT_FIELD(restore_height)
      END_SERIALIZE()
  };

  class message_store
  {
  public:
    message_store(std::unique_ptr<epee::net_utils::http::abstract_http_client> http_client);

    void init_from_setup_key(const multisig_wallet_state &state, const std::string &setup_key, const std::string &own_label);
    void init_from_recovery(const multisig_wallet_state &state, const std::string &recovery, uint32_t signers, uint32_t total);

    void set_service_details(const std::string &message_service_address, const epee::wipeable_string &message_service_login);

    std::string get_recovery_info(const multisig_wallet_state &state, uint64_t restore_height);

    void set_active(bool active) { m_active = active; };
    void set_auto_send(bool auto_send) { m_auto_send = auto_send; };

    bool get_active() const { return m_active; };
    bool get_auto_send() const { return m_auto_send; };

    uint32_t get_num_required_signers() const { return m_num_required_signers; };
    uint32_t get_num_authorized_signers() const { return m_num_authorized_signers; };

    void set_signer(const multisig_wallet_state &state,
                    uint32_t index,
                    const boost::optional<std::string> &label,
                    const boost::optional<crypto::public_key> &public_key);

    const authorized_signer &get_signer(uint32_t index) const;
    bool get_signer_index_by_public_key(const crypto::public_key &public_key, uint32_t &index) const;
    bool get_signer_index_by_label(const std::string label, uint32_t &index) const;
    const std::vector<authorized_signer> &get_all_signers() const { return m_signers; };
    bool signer_config_complete() const;
    bool signer_keys_complete() const;
    bool signer_labels_complete() const;
    void get_signer_config(std::string &signer_config);

    bool check_auto_config_token(const std::string &raw_token,
                                 setup_key &key) const;

    size_t add_introduction_key_message(const multisig_wallet_state &state);

    size_t add_auto_config_data_messages(const multisig_wallet_state &state);


    auto_config_data get_auto_config_data(uint32_t id);

    std::vector<auto_config_data> get_auto_config_data();

    bool auto_config_data_complete(std::vector<uint32_t> &auto_config_messages);

    void process_auto_config_data_message(uint32_t id);
    std::string get_config_checksum() const;
    void stop_auto_config();

    // Process data just created by "me" i.e. the own local wallet, e.g. as the result of a "prepare_multisig" command
    // Creates the resulting messages to the right signers
    void process_wallet_created_data(const multisig_wallet_state &state, message_type type, const std::string &content, std::vector<uint32_t> &message_ids);

    // Go through all the messages, look at the "ready to process" ones, and check whether any single one
    // or any group of them can be processed, because they are processable as single messages (like a tx
    // that is fully signed and thus ready for submit to the net) or because they form a complete group
    // (e.g. key sets from all authorized signers to make the wallet multisig). If there are multiple
    // candidates, e.g. in 2/3 multisig sending to one OR the other signer to sign, there will be more
    // than 1 element in 'data' for the user to choose. If nothing is ready "false" is returned.
    // The method mostly ignores the order in which the messages were received because messages may be delayed
    // (e.g. sync data from a signer arrives AFTER a transaction to submit) or because message time stamps
    // may be wrong so it's not possible to order them reliably.
    // Messages also may be ready by themselves but the wallet not yet ready for them (e.g. sync data already
    // arriving when the wallet is not yet multisig because key sets were delayed or were lost altogether.)
    // If nothing is ready 'wait_reason' may contain further info about the reason why.
    bool get_processable_messages(const multisig_wallet_state &state,
                                  bool force_sync,
                                  std::vector<processing_data> &data_list,
                                  std::string &wait_reason);
    void set_messages_processed(const processing_data &data);

    bool process_sync_data(std::vector<uint32_t> &message_ids);

    size_t add_message(const multisig_wallet_state &state,
                       uint32_t signer_index, message_type type, message_direction direction,
                       const std::string &content, uint32_t *message_id = nullptr);
    const std::vector<message> &get_all_messages() const { return m_messages; };
    bool get_message_by_id(uint32_t id, message &m) const;
    message get_message_by_id(uint32_t id) const;
    void set_message_processed_or_sent(uint32_t id);
    void delete_message(uint32_t id);
    void delete_all_messages();
    static std::string get_sanitized_text(const std::string &text, size_t max_length);

    void send_message(const multisig_wallet_state &state, uint32_t id);
    bool check_for_messages(const multisig_wallet_state &state, std::vector<message> &messages);
    void stop() { m_run.store(false, std::memory_order_relaxed); m_transporter.stop(); }

    void write_to_file(const multisig_wallet_state &state, const std::string &filename);
    void read_from_file(const multisig_wallet_state &state, const std::string &filename, bool load_deprecated_formats = false);

    BEGIN_SERIALIZE_OBJECT()
      VERSION_FIELD(1)
      FIELD(m_active)
      VARINT_FIELD(m_num_authorized_signers)
      VARINT_FIELD(m_nettype)
      VARINT_FIELD(m_num_required_signers)
      FIELD(m_signers)
      FIELD(m_messages)
      VARINT_FIELD(m_next_message_id)
      FIELD(m_auto_send)
      if (version < 1)
      {
        m_last_processed_message = "-";
        return true;
      }
      FIELD(m_last_processed_message)
      FIELD(m_service_url)
      FIELD(m_service_channel)
      FIELD(m_service_token)
    END_SERIALIZE()

    static const char* message_type_to_string(message_type type);
    static const char* message_direction_to_string(message_direction direction);
    static const char* message_state_to_string(message_state state);
    std::string signer_to_string(const authorized_signer &signer, uint32_t max_width);
    
    static const char *tr(const char *str) { return i18n_translate(str, "tools::mms"); }

    bool register_channel(std::string &channel, uint32_t user_limit);
    bool register_user();

    bool get_channel_users(const multisig_wallet_state &state, uint32_t &num_users);

    std::string create_setup_key(uint32_t threshold, uint32_t signers, const std::string &service, const std::string &channel, setup_mode mode);

  private:
    bool m_active;
    uint32_t m_num_authorized_signers;
    uint32_t m_num_required_signers;
    bool m_auto_send;
    cryptonote::network_type m_nettype;
    std::vector<authorized_signer> m_signers;
    std::vector<message> m_messages;
    uint32_t m_next_message_id;
    std::string m_filename;
    message_transporter m_transporter;
    std::atomic<bool> m_run;
    std::string m_last_processed_message;
    bool m_user_registered = false;

    std::string m_service_url;
    std::string m_service_channel;
    std::string m_service_token;

    bool m_auto_config_running = false;
    crypto::public_key m_auto_config_public_key = crypto::null_pkey;
    crypto::secret_key m_auto_config_secret_key = crypto::null_skey;

    bool get_message_index_by_id(uint32_t id, size_t &index) const;
    size_t get_message_index_by_id(uint32_t id) const;
    message& get_message_ref_by_id(uint32_t id);
    bool any_message_of_type(message_type type, message_direction direction) const;
    bool any_message_with_hash(const crypto::hash &hash) const;
    size_t get_other_signers_id_count(const std::vector<uint32_t> &ids) const;
    bool message_ids_complete(const std::vector<uint32_t> &ids) const;
    void encrypt(crypto::public_key public_key, const std::string &plaintext,
                 std::string &ciphertext, crypto::public_key &encryption_public_key, crypto::chacha_iv &iv);
    void decrypt(const std::string &ciphertext, const crypto::public_key &encryption_public_key, const crypto::chacha_iv &iv,
                 const crypto::secret_key &view_secret_key, std::string &plaintext);

    void save(const multisig_wallet_state &state);
  };
}
