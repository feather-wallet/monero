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
#include "serialization/keyvalue_serialization.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_basic/account_boost_serialization.h"
#include "net/http_server_impl_base.h"
#include "net/http_client.h"
#include "net/abstract_http_client.h"
#include "common/util.h"
#include "wipeable_string.h"
#include <vector>

namespace mms
{

struct transport_message_t
{
  crypto::public_key source_public_key;
  crypto::public_key destination_public_key;
  uint64_t timestamp;
  uint32_t type;
  std::string content;
  uint32_t round;

  BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE_VAL_POD_AS_BLOB(source_public_key)
    KV_SERIALIZE_VAL_POD_AS_BLOB(destination_public_key)
    KV_SERIALIZE(timestamp)
    KV_SERIALIZE(type)
    KV_SERIALIZE(content)
    KV_SERIALIZE(round)
  END_KV_SERIALIZE_MAP()
};
typedef epee::misc_utils::struct_init<transport_message_t> transport_message;

struct encrypted_message
{
  crypto::chacha_iv iv;
  crypto::public_key encryption_public_key;
  crypto::hash hash;
  crypto::signature signature;
  std::string message;

  BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE_VAL_POD_AS_BLOB(iv)
    KV_SERIALIZE_VAL_POD_AS_BLOB(encryption_public_key)
    KV_SERIALIZE_VAL_POD_AS_BLOB(hash)
    KV_SERIALIZE_VAL_POD_AS_BLOB(signature)
    KV_SERIALIZE(message)
  END_KV_SERIALIZE_MAP()
};

class message_transporter
{
public:
  message_transporter(std::unique_ptr<epee::net_utils::http::abstract_http_client> http_client);
  void set_options(const std::string &message_service_address, const epee::wipeable_string &message_service_login);

  bool register_channel(std::string &channel, uint32_t user_limit);
  bool register_user(const std::string &channel, const std::string &user, std::string &token);

  std::vector<std::string> get_channel_users(const std::string &channel, const std::string &token);

  bool send_message(const encrypted_message &message, const std::string &channel, const std::string &token, const std::string &recipient);
  bool send_pinned_message(const encrypted_message &message, const std::string &channel, const std::string &token, const std::string &recipient);
  bool receive_messages(const std::string &channel, const std::string &token, const std::string &after, std::vector<encrypted_message> &messages, std::string &last_id);
  void stop() { m_run.store(false, std::memory_order_relaxed); }

private:
  const std::unique_ptr<epee::net_utils::http::abstract_http_client> m_http_client;
  std::string m_message_service_url;
  epee::wipeable_string m_message_service_login;
  std::atomic<bool> m_run;

  bool post_request(const std::string &endpoint, const std::string &request, std::string &answer);
};

}
