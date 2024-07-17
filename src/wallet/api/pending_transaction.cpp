// Copyright (c) 2014-2022, The Monero Project
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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "pending_transaction.h"
#include "wallet.h"
#include "common_defines.h"

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "common/base58.h"
#include "string_coding.h"

#include <memory>
#include <vector>
#include <sstream>
#include <boost/format.hpp>
#include <boost/filesystem.hpp>

using namespace std;

namespace Monero {

PendingTransaction::~PendingTransaction() {}


PendingTransactionImpl::PendingTransactionImpl(WalletImpl &wallet)
    : m_wallet(wallet)
{
  m_status = Status_Ok;
}

PendingTransactionImpl::~PendingTransactionImpl()
{

}

int PendingTransactionImpl::status() const
{
    return m_status;
}

string PendingTransactionImpl::errorString() const
{
    return m_errorString;
}

std::vector<std::string> PendingTransactionImpl::txid() const
{
    std::vector<std::string> txid;
    for (const auto &pt: m_pending_tx)
        txid.push_back(epee::string_tools::pod_to_hex(cryptonote::get_transaction_hash(pt.tx)));
    return txid;
}

std::vector<std::string> PendingTransactionImpl::prefixHashes() const
{
    std::vector<std::string> phash;
    for (const auto &pt : m_pending_tx)
        phash.push_back(epee::string_tools::pod_to_hex(cryptonote::get_transaction_prefix_hash(pt.tx)));
    return phash;
}

bool PendingTransactionImpl::commit(const std::string &filename, bool overwrite)
{

    LOG_PRINT_L3("m_pending_tx size: " << m_pending_tx.size());

    try {
      // Save tx to file
      if (!filename.empty()) {
        boost::system::error_code ignore;
        bool tx_file_exists = boost::filesystem::exists(filename, ignore);
        if(tx_file_exists && !overwrite){
          m_errorString = string(tr("Attempting to save transaction to file, but specified file(s) exist. Exiting to not risk overwriting. File:")) + filename;
          m_status = Status_Error;
          LOG_ERROR(m_errorString);
          return false;
        }
        bool r = m_wallet.m_wallet->save_tx(m_pending_tx, filename);
        if (!r) {
          m_errorString = tr("Failed to write transaction(s) to file");
          m_status = Status_Error;
        } else {
          m_status = Status_Ok;
        }
      }
      // Commit tx
      else {
        auto multisigState = m_wallet.multisig();
        if (multisigState.isMultisig && m_signers.size() < multisigState.threshold) {
            throw runtime_error("Not enough signers to send multisig transaction");
        }

        m_wallet.pauseRefresh();

        const bool tx_cold_signed = m_wallet.m_wallet->get_account().get_device().has_tx_cold_sign();
        if (tx_cold_signed){
          std::unordered_set<size_t> selected_transfers;
          for(const tools::wallet2::pending_tx & ptx : m_pending_tx){
            for(size_t s : ptx.selected_transfers){
              selected_transfers.insert(s);
            }
          }

          m_wallet.m_wallet->cold_tx_aux_import(m_pending_tx, m_tx_device_aux);
          bool r = m_wallet.m_wallet->import_key_images(m_key_images, 0, selected_transfers);
          if (!r){
            throw runtime_error("Cold sign transaction submit failed - key image sync fail");
          }
        }

        while (!m_pending_tx.empty()) {
            auto & ptx = m_pending_tx.back();
            m_wallet.m_wallet->commit_tx(ptx);
            // if no exception, remove element from vector
            m_pending_tx.pop_back();
        } // TODO: extract method;
      }
    } catch (const tools::error::daemon_busy&) {
        // TODO: make it translatable with "tr"?
        m_errorString = tr("daemon is busy. Please try again later.");
        m_status = Status_Error;
    } catch (const tools::error::no_connection_to_daemon&) {
        m_errorString = tr("no connection to daemon. Please make sure daemon is running.");
        m_status = Status_Error;
    } catch (const tools::error::tx_rejected& e) {
        std::ostringstream writer(m_errorString);
        writer << (boost::format(tr("transaction %s was rejected by daemon with status: ")) % get_transaction_hash(e.tx())) <<  e.status();
        std::string reason = e.reason();
        m_status = Status_Error;
        m_errorString = writer.str();
        if (!reason.empty())
          m_errorString += string(tr(". Reason: ")) + reason;
    } catch (const std::exception &e) {
        m_errorString = string(tr("Unknown exception: ")) + e.what();
        m_status = Status_Error;
    } catch (...) {
        m_errorString = tr("Unhandled exception");
        LOG_ERROR(m_errorString);
        m_status = Status_Error;
    }

    m_wallet.startRefresh();
    return m_status == Status_Ok;
}

uint64_t PendingTransactionImpl::amount() const
{
    uint64_t result = 0;
    for (const auto &ptx : m_pending_tx)   {
        for (const auto &dest : ptx.dests) {
            result += dest.amount;
        }
    }
    return result;
}

uint64_t PendingTransactionImpl::dust() const
{
    uint64_t result = 0;
    for (const auto & ptx : m_pending_tx) {
        result += ptx.dust;
    }
    return result;
}

uint64_t PendingTransactionImpl::fee() const
{
    uint64_t result = 0;
    for (const auto &ptx : m_pending_tx) {
        result += ptx.fee;
    }
    return result;
}

uint64_t PendingTransactionImpl::txCount() const
{
    return m_pending_tx.size();
}

std::vector<uint32_t> PendingTransactionImpl::subaddrAccount() const
{
    std::vector<uint32_t> result;
    for (const auto& ptx : m_pending_tx)
        result.push_back(ptx.construction_data.subaddr_account);
    return result;
}

std::vector<std::set<uint32_t>> PendingTransactionImpl::subaddrIndices() const
{
    std::vector<std::set<uint32_t>> result;
    for (const auto& ptx : m_pending_tx)
        result.push_back(ptx.construction_data.subaddr_indices);
    return result;
}

std::string PendingTransactionImpl::multisigSignData() {
    try {
        if (!m_wallet.multisig().isMultisig) {
            throw std::runtime_error("wallet is not multisig");
        }

        tools::wallet2::multisig_tx_set txSet;
        txSet.m_ptx = m_pending_tx;
        txSet.m_signers = m_signers;
        auto cipher = m_wallet.m_wallet->save_multisig_tx(txSet);

        return epee::string_tools::buff_to_hex_nodelimer(cipher);
    } catch (const std::exception& e) {
        m_status = Status_Error;
        m_errorString = std::string(tr("Couldn't multisig sign data: ")) + e.what();
    }

    return std::string();
}

void PendingTransactionImpl::signMultisigTx() {
    try {
        std::vector<crypto::hash> ignore;

        tools::wallet2::multisig_tx_set txSet;
        txSet.m_ptx = m_pending_tx;
        txSet.m_signers = m_signers;

        if (!m_wallet.m_wallet->sign_multisig_tx(txSet, ignore)) {
            throw std::runtime_error("couldn't sign multisig transaction");
        }

        std::swap(m_pending_tx, txSet.m_ptx);
        std::swap(m_signers, txSet.m_signers);
    } catch (const std::exception& e) {
        m_status = Status_Error;
        m_errorString = std::string(tr("Couldn't sign multisig transaction: ")) + e.what();
    }
}

std::vector<std::string> PendingTransactionImpl::signersKeys() const {
    std::vector<std::string> keys;
    keys.reserve(m_signers.size());

    for (const auto& signer: m_signers) {
        keys.emplace_back(tools::base58::encode(cryptonote::t_serializable_object_to_blob(signer)));
    }

    return keys;
}

std::string PendingTransactionImpl::unsignedTxToBin() const {
    return m_wallet.m_wallet->dump_tx_to_str(m_pending_tx);
}

std::string PendingTransactionImpl::unsignedTxToBase64() const {
    return epee::string_encoding::base64_encode(m_wallet.m_wallet->dump_tx_to_str(m_pending_tx));
}

std::string PendingTransactionImpl::signedTxToHex(int index) const {
    auto index_ = static_cast<unsigned>(index);
    if (index < 0 || index_ >= m_pending_tx.size()) {
        return "";
    }

    return epee::string_tools::buff_to_hex_nodelimer(cryptonote::tx_to_blob(m_pending_tx[index_].tx));
}

size_t PendingTransactionImpl::signedTxSize(int index) const {
    auto index_ = static_cast<unsigned>(index);
    if (index < 0 || index_ >= m_pending_tx.size()) {
        return 0;
    }

    return cryptonote::tx_to_blob(m_pending_tx[index_].tx).size();
}

PendingTransactionInfo * PendingTransactionImpl::transaction(int index) const {
    if (index < 0)
        return nullptr;
    auto index_ = static_cast<unsigned>(index);
    return index_ < m_pending_tx_info.size() ? m_pending_tx_info[index_] : nullptr;
}

void PendingTransactionImpl::refresh() {
    for (auto t : m_pending_tx_info)
        delete t;
    m_pending_tx_info.clear();

    for (const auto& p : m_pending_tx)
        m_pending_tx_info.push_back(new PendingTransactionInfoImpl(m_wallet, p));
}

std::vector<PendingTransactionInfo*> PendingTransactionImpl::getAll() const {
    return m_pending_tx_info;
}

uint32_t PendingTransactionImpl::saveToMMS() {
    auto multisigState = m_wallet.multisig();
    if (!multisigState.isMultisig) {
        return false;
    }

    std::string ciphertext = m_wallet.m_wallet->save_multisig_tx(m_pending_tx);
    // TODO: check if ciphertext is empty

    std::vector<uint32_t> message_ids;
    m_wallet.m_wallet->get_message_store().process_wallet_created_data(m_wallet.m_wallet->get_multisig_wallet_state(), mms::message_type::partially_signed_tx, ciphertext, message_ids);
    return message_ids[0];
}

std::vector<std::string> PendingTransactionImpl::destinations(int index) const {
    auto index_ = static_cast<unsigned>(index);
    if (index < 0 || index_ >= m_pending_tx.size()) {
        return {};
    }

    std::vector<std::string> dests;
    auto tx = m_pending_tx[index_];
    for (const auto &dest : tx.dests) {
        // TODO: payment id?
        dests.push_back(dest.address(m_wallet.m_wallet->nettype(), crypto::null_hash));
    }
    return dests;
}

uint64_t PendingTransactionImpl::signaturesNeeded() const {
    auto multisigState = m_wallet.multisig();
    if (!multisigState.isMultisig) {
        return 0;
    }
    if (m_signers.size() > multisigState.threshold) {
        return 0;
    }
    return multisigState.threshold - m_signers.size();
}

bool PendingTransactionImpl::enoughMultisigSignatures() const {
    auto multisigState = m_wallet.multisig();
    if (multisigState.isMultisig && m_signers.size() < multisigState.threshold) {
        return false;
    }
    return true;
}

bool PendingTransactionImpl::haveWeSigned() const {
    const crypto::public_key local_signer = m_wallet.m_wallet->get_multisig_signer_public_key();

    return m_signers.find(local_signer) != m_signers.end();
}

bool PendingTransactionImpl::canSign() const {
    LOG_ERROR("Can we sign this tx?");

    const crypto::public_key local_signer = m_wallet.m_wallet->get_multisig_signer_public_key();

    // We already signed this transaction
    if (m_signers.find(local_signer) != m_signers.end()) {
        return false;
    }

    for (const auto& i : m_pending_tx[0].construction_data.selected_transfers) {
        auto td = m_wallet.m_wallet->get_transfer_details(i);

        for (auto &sig: m_pending_tx[0].multisig_sigs) {
            if (sig.ignore.find(local_signer) == sig.ignore.end()) {
                for (auto &k: td.m_multisig_k) {
                    if (k == rct::zero())
                        continue;

                    // TODO: L can only be used once, so we need to keep track
                    rct::key L;
                    rct::scalarmultBase(L, k);
                    if (sig.used_L.find(L) != sig.used_L.end()) {
                        break;
                    }
                    return false;
                }
            }
        }
    }
    return true;
}

}