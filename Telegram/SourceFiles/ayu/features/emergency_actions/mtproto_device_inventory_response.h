// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/emergency_actions/mtproto_session_effect_transport.h"
#include "scheme.h"

#include <algorithm>
#include <bit>
#include <set>

namespace Ayu::EmergencyActions::details {

[[nodiscard]] inline QString DeviceModelLabel(const QByteArray &model) {
	constexpr auto kMaximumLabelLength = 48;
	auto clean = QString();
	clean.reserve(kMaximumLabelLength);
	for (const auto ch : QString::fromUtf8(model.first(std::min(model.size(), qsizetype(192))))) {
		if (ch.isLetterOrNumber() || ch == '-' || ch == '.' || ch == '_'
			|| ch == '(' || ch == ')' || ch == '+') {
			clean.append(ch);
		} else if (ch.isSpace() && !clean.isEmpty() && clean.back() != ' ') {
			clean.append(QChar(' '));
		}
		if (clean.size() == kMaximumLabelLength) {
			break;
		}
	}
	return clean.trimmed();
}

[[nodiscard]] inline std::optional<std::vector<MtprotoDeviceInventoryEntry>>
ParseMtprotoDeviceInventory(std::span<const mtpPrime> reply) {
	constexpr auto kMaximumDevices = 256;
	constexpr auto kMaximumReplyWords = 128 * 1024;
	if (reply.size() < 4 || reply.size() > kMaximumReplyWords
		|| mtpTypeId(reply[0]) != mtpc_account_authorizations
		|| mtpTypeId(reply[2]) != mtpc_vector
		|| reply[3] <= 0 || reply[3] > kMaximumDevices) {
		return std::nullopt;
	}
	auto result = MTPaccount_Authorizations();
	auto from = reply.data();
	const auto end = from + reply.size();
	if (!result.read(from, end) || from != end) {
		return std::nullopt;
	}
	auto devices = std::vector<MtprotoDeviceInventoryEntry>();
	auto hashes = std::set<uint64_t>();
	auto hasCurrent = false;
	for (const auto &entry : result.data().vauthorizations().v) {
		const auto &data = entry.data();
		const auto current = data.is_current();
		const auto hash = std::bit_cast<uint64_t>(int64_t(data.vhash().v));
		if ((current && hasCurrent) || (!current && !hash)
			|| (hash && !hashes.emplace(hash).second)) {
			return std::nullopt;
		}
		hasCurrent = hasCurrent || current;
		devices.push_back({
			.id = current ? SessionId("current") : TelegramRemoteSessionId(hash),
			.current = current,
			.label = DeviceModelLabel(data.vdevice_model().v),
		});
	}
	return hasCurrent ? std::optional(std::move(devices)) : std::nullopt;
}

} // namespace Ayu::EmergencyActions::details
