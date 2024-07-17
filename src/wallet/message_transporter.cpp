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

#include "message_transporter.h"
#include "string_coding.h"
#include <boost/format.hpp>
#include "wallet_errors.h"
#include "net/http_client.h"
#include "net/net_parse_helpers.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include <algorithm>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.mms"
#define MESSAGE_SERVICE_DEFAULT_API_PORT 8442

namespace mms
{

message_transporter::message_transporter(std::unique_ptr<epee::net_utils::http::abstract_http_client> http_client) : m_http_client(std::move(http_client))
{
  m_run = true;
  m_message_service_url = "http://localhost:8442/";
  epee::net_utils::http::url_content address_parts{};
  epee::net_utils::parse_url(m_message_service_url, address_parts);
  if (address_parts.port == 0)
  {
      address_parts.port = MESSAGE_SERVICE_DEFAULT_API_PORT;
  }

  m_http_client->set_server(address_parts.host, std::to_string(address_parts.port), boost::none, epee::net_utils::ssl_support_t::e_ssl_support_disabled);
}

void message_transporter::set_options(const std::string &bitmessage_address, const epee::wipeable_string &bitmessage_login)
{
  m_message_service_url = bitmessage_address;
  epee::net_utils::http::url_content address_parts{};
  epee::net_utils::parse_url(m_message_service_url, address_parts);
  if (address_parts.port == 0)
  {
    address_parts.port = MESSAGE_SERVICE_DEFAULT_API_PORT;
  }
  m_message_service_login = bitmessage_login;

  // TODO: enable ssl
  m_http_client->set_server(address_parts.host, std::to_string(address_parts.port), boost::none, epee::net_utils::ssl_support_t::e_ssl_support_disabled);
}

bool message_transporter::receive_messages(const std::string &channel,
                                           const std::string &token,
                                           const std::string &after,
                                           std::vector<encrypted_message> &messages,
                                           std::string &last_id)
{
  m_run.store(true, std::memory_order_relaxed);

  rapidjson::Document req;
  req.SetObject();

  rapidjson::Value dest(rapidjson::kStringType);
  dest.SetString(channel.data(), channel.size());
  req.AddMember("channel", dest, req.GetAllocator());

  rapidjson::Value source(rapidjson::kStringType);
  source.SetString(token.data(), token.size());
  req.AddMember("token", source, req.GetAllocator());

  rapidjson::Value after_value(rapidjson::kStringType);
  after_value.SetString(after.data(), after.size());
  req.AddMember("after", after_value, req.GetAllocator());

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  req.Accept(writer);

  std::string request = buffer.GetString();

  std::string answer;
  post_request("getMessages", request, answer);

  rapidjson::Document document;

  if (document.Parse(answer.c_str()).HasParseError()) {
    std::cerr << "JSON parse error" << std::endl;
    // Handle parse error (e.g., return from function)
    return false;
  }

  if (!document.IsObject()) {
    return false;
    // Handle error
  }

  if (!document.HasMember("last_id")) {
    return false;
  }

  if (!document.HasMember("messages")) {
    return false;
  }

  for (auto& v : document["messages"].GetArray()) {
    auto the_string =  epee::string_encoding::base64_decode(v.GetString());

    encrypted_message message;

    if (!epee::serialization::load_t_from_json(message, the_string))
    {
      MERROR("Failed to deserialize messages");
      return true;
    }

    messages.push_back(message);
  }

  last_id = document["last_id"].GetString();

  return true;
}

bool message_transporter::register_channel(std::string &channel, uint32_t user_limit)
{
  // TODO: check auto config token
  rapidjson::Document req;
  req.SetObject();

  rapidjson::Value source(rapidjson::kStringType);
  source.SetString(m_message_service_login.data(), m_message_service_login.size());
  req.AddMember("api_key", source, req.GetAllocator());

  rapidjson::Value userLimit(rapidjson::kStringType);
  userLimit.SetInt(user_limit);
  req.AddMember("user_limit", userLimit, req.GetAllocator());

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  req.Accept(writer);

  std::string request = buffer.GetString();
  std::string answer;
  post_request("registerChannel", request, answer);

  rapidjson::Document document;
  THROW_WALLET_EXCEPTION_IF(document.Parse(answer.c_str()).HasParseError(), tools::error::message_service_api_error, "Invalid response from message service")
  THROW_WALLET_EXCEPTION_IF(!document.IsObject() || !document.HasMember("data"), tools::error::message_service_api_error, "Invalid response from message service")

  channel = document["data"]["channel"].GetString();

  //
  // if (status != "ok") {
  //   THROW_WALLET_EXCEPTION_IF(!document.HasMember("message"), tools::error::message_service_api_error, "Message service returned: unknown error")
  //   std::string error_message = document["message"].GetString();
  //   THROW_WALLET_EXCEPTION(tools::error::message_service_api_error, "Message service returned: " + error_message);
  // }

  return true;
}

bool message_transporter::register_user(const std::string &channel, const std::string &user, std::string &token)
{
  rapidjson::Document req;
  req.SetObject();

  rapidjson::Value dest(rapidjson::kStringType);
  dest.SetString(channel.data(), channel.size());
  req.AddMember("channel", dest, req.GetAllocator());

  rapidjson::Value source(rapidjson::kStringType);
  source.SetString(user.data(), user.size());
  req.AddMember("user", source, req.GetAllocator());

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  req.Accept(writer);

  std::string request = buffer.GetString();
  std::string answer;
  post_request("registerUser", request, answer);

  rapidjson::Document document;
  THROW_WALLET_EXCEPTION_IF(document.Parse(answer.c_str()).HasParseError(), tools::error::message_service_api_error, "Invalid response from message service")
  THROW_WALLET_EXCEPTION_IF(!document.IsObject() || !document.HasMember("data"), tools::error::message_service_api_error, "Invalid response from message service")

  token = document["data"]["token"].GetString();

  return true;
}

std::vector<std::string> message_transporter::get_channel_users(const std::string &channel, const std::string &token)
{
  rapidjson::Document req;
  req.SetObject();

  rapidjson::Value dest(rapidjson::kStringType);
  dest.SetString(channel.data(), channel.size());
  req.AddMember("channel", dest, req.GetAllocator());

  rapidjson::Value source(rapidjson::kStringType);
  source.SetString(token.data(), token.size());
  req.AddMember("token", source, req.GetAllocator());

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  req.Accept(writer);

  std::string request = buffer.GetString();
  std::string answer;
  post_request("channelUsers", request, answer);

  rapidjson::Document document;
  THROW_WALLET_EXCEPTION_IF(document.Parse(answer.c_str()).HasParseError(), tools::error::message_service_api_error, "Invalid response from message service")
  THROW_WALLET_EXCEPTION_IF(!document.IsObject() || !document.HasMember("data"), tools::error::message_service_api_error, "Invalid response from message service")

  std::vector<std::string> users;

  for (auto& v : document["data"]["users"].GetArray()) {
    if (v.IsString()) {
      users.emplace_back(v.GetString());
    }
  }

  return users;
}

bool message_transporter::send_message(const encrypted_message &message, const std::string &channel, const std::string &token, const std::string &recipient)
{
  rapidjson::Document req;
  req.SetObject();

  rapidjson::Value dest(rapidjson::kStringType);
  dest.SetString(channel.data(), channel.size());
  req.AddMember("channel", dest, req.GetAllocator());

  rapidjson::Value toke(rapidjson::kStringType);
  toke.SetString(token.data(), token.size());
  req.AddMember("token", toke, req.GetAllocator());

  rapidjson::Value source(rapidjson::kStringType);
  source.SetString(recipient.data(), recipient.size());
  req.AddMember("recipient", source, req.GetAllocator());

  std::string json = epee::serialization::store_t_to_json(message);
  std::string message_body = epee::string_encoding::base64_encode(json);  // See comment in "receive_message" about reason for (double-)Base64 encoding
  rapidjson::Value body(rapidjson::kStringType);
  body.SetString(message_body.data(), message_body.size());
  req.AddMember("data", body, req.GetAllocator());

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  req.Accept(writer);

  std::string request = buffer.GetString();
  std::string answer;
  post_request("addMessage", request, answer);
  return true;
}

bool message_transporter::send_pinned_message(const encrypted_message &message, const std::string &channel, const std::string &token, const std::string &recipient)
{
  rapidjson::Document req;
  req.SetObject();

  rapidjson::Value dest(rapidjson::kStringType);
  dest.SetString(channel.data(), channel.size());
  req.AddMember("channel", dest, req.GetAllocator());

  rapidjson::Value toke(rapidjson::kStringType);
  toke.SetString(token.data(), token.size());
  req.AddMember("token", toke, req.GetAllocator());

  rapidjson::Value source(rapidjson::kStringType);
  source.SetString(recipient.data(), recipient.size());
  req.AddMember("recipient", source, req.GetAllocator());

    rapidjson::Value id(rapidjson::kStringType);
    std::string empty = "";
    source.SetString(empty.data(), empty.size());
    req.AddMember("id", source, req.GetAllocator());

  std::string json = epee::serialization::store_t_to_json(message);
  std::string message_body = epee::string_encoding::base64_encode(json);  // See comment in "receive_message" about reason for (double-)Base64 encoding
  rapidjson::Value body(rapidjson::kStringType);
  body.SetString(message_body.data(), message_body.size());
  req.AddMember("data", body, req.GetAllocator());

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  req.Accept(writer);

  std::string request = buffer.GetString();
  std::string answer;
  post_request("addPinnedMessage", request, answer);
  return true;
}

bool message_transporter::post_request(const std::string &endpoint, const std::string &request, std::string &answer)
{
  // Somehow things do not work out if one tries to connect "m_http_client" to Bitmessage
  // and keep it connected over the course of several calls. But with a new connection per
  // call and disconnecting after the call there is no problem (despite perhaps a small
  // slowdown)
  epee::net_utils::http::fields_list additional_params;

  additional_params.push_back(std::make_pair("Content-Type", "application/json; charset=utf-8"));
  const epee::net_utils::http::http_response_info* response = NULL;
  std::chrono::milliseconds timeout = std::chrono::seconds(15);
  bool r = m_http_client->invoke("/" + endpoint, "POST", request, timeout, std::addressof(response), std::move(additional_params));
  if (r)
  {
    answer = response->m_body;
  }
  else
  {
    LOG_ERROR("POST request failed: " << request.substr(0, 300));
    THROW_WALLET_EXCEPTION_IF(!response, tools::error::message_service_api_error, "Unable to connect to to message service.")
    THROW_WALLET_EXCEPTION_IF(response->m_response_code == 401, tools::error::message_service_api_error, "Message service requires authentication. Incorrect username or password.")
    THROW_WALLET_EXCEPTION_IF(response->m_response_code == 500, tools::error::message_service_api_error, "Message service experienced an internal server error")
    THROW_WALLET_EXCEPTION(tools::error::no_connection_to_message_service, m_message_service_url);
  }
  m_http_client->disconnect();  // see comment above

  return r;
}

}
