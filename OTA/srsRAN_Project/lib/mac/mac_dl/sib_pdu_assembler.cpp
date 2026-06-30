/*
 *
 * Copyright 2021-2025 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#include "sib_pdu_assembler.h"
#include "srsran/srslog/srslog.h"
#include <cstdio>

using namespace srsran;

// Number of padding bytes to pre-reserve. This value is implementation-defined.
static constexpr unsigned MAX_PADDING_BYTES_LEN = 64;

// Max SI Message PDU size. This value is implementation-defined.
static constexpr unsigned MAX_BCCH_DL_SCH_PDU_SIZE = 2048;

// Payload of zeros sent to when an error occurs.
static const std::vector<uint8_t> zeros_payload(MAX_BCCH_DL_SCH_PDU_SIZE, 0);

sib_pdu_assembler::sib_pdu_assembler(const std::vector<byte_buffer>& bcch_dl_sch_payloads) :
  logger(srslog::fetch_basic_logger("MAC"))
{
  bcch_payloads.resize(bcch_dl_sch_payloads.size());
  for (unsigned i = 0, e = bcch_payloads.size(); i != e; ++i) {
    bcch_payloads[i].info.version      = 0;
    bcch_payloads[i].info.payload_size = units::bytes(bcch_dl_sch_payloads[i].length());

    // Note: Resizing the bcch_payload after this point onwards is forbidden to avoid vector memory relocations and
    // invalidation of pointers passed to the lower layers. For this reason, we pre-reserve space for any potential
    // padding bytes.
    bcch_payloads[i].info.payload_and_padding.resize(bcch_dl_sch_payloads[i].length() + MAX_PADDING_BYTES_LEN, 0);
    std::copy(bcch_dl_sch_payloads[i].begin(),
              bcch_dl_sch_payloads[i].end(),
              bcch_payloads[i].info.payload_and_padding.begin());
  }
  
  // Set num_fragments based on the number of SIB1 messages
  // In the current implementation, SIB1 messages are always at index 0 in bcch_payloads.
  // If multiple SIB1s are created, they should be consecutive at the start of the vector.
  // For now, we check if there are multiple messages and if they have similar sizes (indicating multiple SIB1s)
  // A more robust solution would be to pass the number of SIB1 messages explicitly, but for now we use a heuristic:
  // If we have more than 1 message and the first two have similar sizes, assume multiple SIB1s
  logger.info("sib_pdu_assembler constructor: bcch_payloads.size()={}, initial num_fragments={}", 
              bcch_payloads.size(), num_fragments);
  
  if (bcch_payloads.size() > 1) {
    // Check if first two messages have similar sizes (within 20% difference) - this suggests they might both be SIB1
    size_t size0 = bcch_payloads[0].info.payload_size.value();
    size_t size1 = bcch_payloads[1].info.payload_size.value();
    logger.info("Checking SIB1 detection: size0={}, size1={}", size0, size1);
    
    if (size0 > 0 && size1 > 0) {
      double size_ratio = static_cast<double>(std::max(size0, size1)) / static_cast<double>(std::min(size0, size1));
      logger.info("Size ratio: {:.2f} (threshold: 1.2)", size_ratio);
      
      if (size_ratio < 1.2) {  // Within 20% difference
        // Likely multiple SIB1 messages - count consecutive messages with similar sizes
        num_fragments = 2;
        for (size_t i = 2; i < bcch_payloads.size(); ++i) {
          size_t size_i = bcch_payloads[i].info.payload_size.value();
          if (size_i > 0) {
            double ratio_i = static_cast<double>(std::max(size0, size_i)) / static_cast<double>(std::min(size0, size_i));
            if (ratio_i < 1.2) {
              num_fragments++;
            } else if (ratio_i >= 1.2 && i == bcch_payloads.size() - 1) {
              // Last message can have size difference, so count it as well
              num_fragments++;
            }
            else {
              break;  // Stop at first message with significantly different size (likely SI message)
            }
          }
        }
        logger.info("Multiple SIB1 messages detected: num_fragments={}, fragmentation_supported={}", 
                    num_fragments, fragmentation_supported);
      } else {
        logger.info("Size ratio too large ({:.2f} >= 1.2), assuming single SIB1. num_fragments remains {}", 
                    size_ratio, num_fragments);
      }
    } else {
      logger.warning("Invalid sizes for SIB1 detection: size0={}, size1={}", size0, size1);
    }
  } else {
    logger.info("Only {} BCCH payload(s), assuming single SIB1. num_fragments remains {}", 
                bcch_payloads.size(), num_fragments);
  }
}

unsigned sib_pdu_assembler::handle_new_sib1_payload(const byte_buffer& sib1_pdu)
{
  unsigned version_id = bcch_payloads[0].info.version + 1;

  // Create new BCCH entry with a larger version.
  bcch_info new_bcch;
  new_bcch.version      = version_id;
  new_bcch.payload_size = units::bytes(sib1_pdu.length());
  // Note: Resizing the bcch_payload after this point onwards is forbidden to avoid vector memory relocations and
  // invalidation of pointers passed to the lower layers. For this reason, we pre-reserve space for any potential
  // padding bytes.
  new_bcch.payload_and_padding.resize(sib1_pdu.length() + MAX_PADDING_BYTES_LEN, 0);
  std::copy(sib1_pdu.begin(), sib1_pdu.end(), new_bcch.payload_and_padding.begin());

  // Mark old BCCH-DL-SCH message for deferred destruction and insert new BCCH-DL-SCH message in its place.
  bcch_payloads[0].old  = std::move(bcch_payloads[0].info);
  bcch_payloads[0].info = std::move(new_bcch);

  return version_id;
}

span<const uint8_t> sib_pdu_assembler::encode_sib1_pdu(unsigned si_version, units::bytes tbs_bytes)
{
  //89da36:start
  logger.info("encode_sib1_pdu called: fragmentation_supported={}, num_fragments={}, bcch_payloads.size()={}", 
              fragmentation_supported, num_fragments, bcch_payloads.size());
  
  if (fragmentation_supported && num_fragments > 1) {
    // Use fragmentation logic to cycle through different SIB1 messages
    // SIB1 messages are always at index 0, and if there are multiple, they should be consecutive
    // We only use the first num_fragments entries as SIB1 fragments
    if (num_fragments > bcch_payloads.size()) {
      logger.warning("Number of SIB1 fragments ({}) exceeds available BCCH payloads ({}). Using available payloads.",
                   num_fragments,
                   bcch_payloads.size());
      num_fragments = bcch_payloads.size();
    }
    unsigned idx = current_fragment % num_fragments;
    current_fragment = (current_fragment + 1) % num_fragments;

    // Simulate drop of the 3rd SIB1 fragment (idx == 2) for the first DROP_CYCLES cycles only
    static constexpr unsigned DROP_FRAGMENT_IDX = 4;
    static constexpr bool     do_drop           = false;
    static constexpr unsigned DROP_CYCLES       = 10;
    static unsigned           cycle_count       = 0;
    // Increment cycle counter each time idx wraps back to 0
    if (idx == 0) {
      cycle_count++;
    }
    bool drop_active = do_drop && (cycle_count <= DROP_CYCLES) && (idx == DROP_FRAGMENT_IDX);
    if (drop_active) {
      logger.warning("*** SIB1 FRAGMENT DROP SIMULATION: dropping fragment {}/{} (cycle {}/{}) ***",
                     idx + 1, num_fragments, cycle_count, DROP_CYCLES);
      std::printf("[gNB] SIB1 DROPPED (fragment %u/%zu, cycle %u/%u)\n",
                  idx + 1, num_fragments, cycle_count, DROP_CYCLES);
      std::fflush(stdout);
      return span<const uint8_t>(zeros_payload.data(), tbs_bytes.value());
    }

    logger.info("Encoding SIB1 fragment {}/{} (using bcch_payloads[{}])", idx + 1, num_fragments, idx);
    return encode_si_pdu(idx, si_version, tbs_bytes);
  } else {
    logger.info("Fragmentation not used: fragmentation_supported={}, num_fragments={}, using index 0", 
                fragmentation_supported, num_fragments);
  }
  //89da36:end
  return encode_si_pdu(0, si_version, tbs_bytes);
}

span<const uint8_t>
sib_pdu_assembler::encode_si_message_pdu(unsigned si_msg_idx, unsigned si_version, units::bytes tbs_bytes)
{
  // SI messages come after all SIB1 fragments in bcch_payloads.
  // Original code assumed 1 SIB1 (index 0), so SI msg 0 was at index 1.
  // With num_fragments SIB1s (indices 0..num_fragments-1), SI msg N is at index num_fragments+N.
  return encode_si_pdu(num_fragments + si_msg_idx, si_version, tbs_bytes);
}

span<const uint8_t> sib_pdu_assembler::encode_si_pdu(unsigned idx, unsigned si_version, units::bytes tbs_bytes)
{
  static constexpr unsigned TX_COUNT_BEFORE_OLD_VERSION_REMOVAL = 4;
  srsran_assert(tbs_bytes.value() <= MAX_BCCH_DL_SCH_PDU_SIZE, "Invalid TBS size for an BCCH-DL-SCH message");

  auto& bcch = bcch_payloads[idx];

  if (bcch.info.version == si_version) {
    // In case there is no pending reconfig of the SI.

    // In case the old version is pending for removal.
    // Note: Given that the lower layers could use a previously sent SI message payload for a bounded but undetermined
    // number of slots, we postpone the removal of the old BCCH-DL-SCH payload version by a fixed number of
    // transmissions of the new version.
    bcch.info.nof_tx++;
    if (bcch.info.nof_tx == TX_COUNT_BEFORE_OLD_VERSION_REMOVAL and bcch.old.has_value()) {
      // It is safe to remove old version at this point.
      bcch.old.reset();
    }

    return encode_bcch_pdu(idx, bcch.info, tbs_bytes);
  }

  if (bcch.old.has_value() and bcch.old.value().version == si_version) {
    // We need to send the old BCCH version instead.
    return encode_bcch_pdu(idx, bcch.old.value(), tbs_bytes);
  }

  // No SI-message with matching index and version was found. Return empty.
  return span<const uint8_t>(zeros_payload.data(), tbs_bytes.value());
}

span<const uint8_t> sib_pdu_assembler::encode_bcch_pdu(unsigned msg_idx, const bcch_info& bcch, units::bytes tbs) const
{
  if (tbs < bcch.payload_size) {
    logger.error("Failed to encode BCCH-DL-SCH Transport Block for SI{}. Cause: TBS cannot be smaller than the "
                 "respective message payload",
                 msg_idx == 0 ? fmt::format("B1") : fmt::format("-message {}", msg_idx + 1));
    return span<const uint8_t>(zeros_payload.data(), tbs.value());
  }
  if (tbs.value() > bcch.payload_and_padding.size()) {
    logger.error("Failed to encode BCCH-DL-SCH Transport Block for SI{}. Cause: Memory reallocations for payload are "
                 "not allowed. Consider reserving more bytes for PADDING",
                 msg_idx == 0 ? fmt::format("B1") : fmt::format("-message {}", msg_idx + 1));
    return span<const uint8_t>(zeros_payload.data(), tbs.value());
  }

  // Generation of TB was successful.
  return span<const uint8_t>(bcch.payload_and_padding.data(), tbs.value());
}
