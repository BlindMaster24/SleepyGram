// This is the source code of AyuGram for Desktop.
#include "ayu/features/emergency_actions/mtproto_device_inventory_response.h"

#include <cstdio>

namespace {

using namespace Ayu::EmergencyActions;
using namespace Ayu::EmergencyActions::details;

int Failures = 0;

void Check(bool passed, const char *name) {
	std::printf("%s %s\n", passed ? "PASS" : "FAIL", name);
	Failures += !passed;
}

MTPAuthorization Row(bool current, int64_t hash, QByteArray model) {
	using Flags = MTPDauthorization::Flags;
	return MTP_authorization(
		MTP_flags(current ? Flags(MTPDauthorization::Flag::f_current) : Flags()),
		MTP_long(hash),
		MTP_string(QString::fromUtf8(model)),
		MTP_string("unused platform"),
		MTP_string("unused OS version"),
		MTP_int(2040),
		MTP_string("unused client"),
		MTP_string("unused app version"),
		MTP_int(1),
		MTP_int(2),
		MTP_string("203.0.113.5"),
		MTP_string("unused country"),
		MTP_string("unused region"));
}

mtpBuffer Reply(const QVector<MTPAuthorization> &authorizations) {
	auto result = mtpBuffer();
	MTPaccount_Authorizations(MTP_account_authorizations(
		MTP_int(30),
		MTP_vector<MTPAuthorization>(authorizations))).write(result);
	return result;
}

std::optional<std::vector<MtprotoDeviceInventoryEntry>> Parse(const mtpBuffer &words) {
	return ParseMtprotoDeviceInventory(std::span(words.constData(), words.size()));
}

void CheckValidResponse() {
	const auto words = Reply({
		Row(false, -42, QByteArray(" Pixel\r\n  8<>")),
		Row(true, 9, QByteArray(" Desktop   (Home) ")),
	});
	const auto parsed = Parse(words);
	Check(parsed && parsed->size() == 2, "pinned Telegram schema parses both device rows");
	if (!parsed || parsed->size() != 2) {
		return;
	}
	const auto &other = parsed->front();
	const auto &current = parsed->back();
	Check(!other.current && other.id == TelegramRemoteSessionId(std::bit_cast<uint64_t>(int64_t(-42))),
		"negative signed response preserves the exact opaque hash bits");
	Check(current.current && current.id == SessionId("current"),
		"current authorization uses the separate non-revocable sentinel");
	Check(other.label == u"Pixel 8"_q && current.label == u"Desktop (Home)"_q,
		"inventory exposes short device model, omitting IP and other session fields");
	const auto dirty = QByteArray::fromHex("41e280ae42014309") + QByteArray(120, 'x');
	const auto clean = DeviceModelLabel(dirty);
	Check(clean.size() == 48 && clean.startsWith(u"ABC "_q),
		"bidi and control characters are stripped and output is capped");
}

void CheckMalformedResponse() {
	const auto current = Row(true, 0, QByteArray());
	const auto other = Row(false, 42, QByteArray("Remote"));
	Check(Parse(Reply({ current })).has_value(), "only current device is a confirmed inventory");
	Check(!Parse(Reply({ other })), "missing current authorization is unavailable");
	Check(!Parse(Reply({ current, current })), "multiple current authorizations are unavailable");
	Check(!Parse(Reply({ current, Row(false, 0, QByteArray()) })),
		"zero remote hash cannot become a selectable device");
	Check(!Parse(Reply({ current, other, other })), "duplicate hashes cannot become distinct selections");
	Check(!Parse(Reply({ Row(true, 42, QByteArray()), other })),
		"remote hash cannot alias the current authorization");
	auto malformed = Reply({ current });
	malformed[3] = 257;
	Check(!Parse(malformed), "oversized declared vector is refused before allocation");
	malformed = Reply({ current });
	malformed[2] = 0;
	Check(!Parse(malformed), "malformed vector constructor is refused");
	malformed = Reply({ current });
	malformed.push_back(0);
	Check(!Parse(malformed), "trailing unvalidated payload is refused");
	malformed = Reply({ current });
	malformed.pop_back();
	Check(!Parse(malformed), "truncated payload is refused");
}

} // namespace

int main() {
	CheckValidResponse();
	CheckMalformedResponse();
	return Failures ? 1 : 0;
}
