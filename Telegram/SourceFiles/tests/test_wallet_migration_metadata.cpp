/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "wallet/wallet_migration_metadata.h"

#include "storage/serialize_common.h"

#include <cstdio>

namespace {

const auto kCustodyKey = u"custody/records"_q;

QByteArray CustodyValue(
		quint32 version,
		const QByteArray &publicKey = {},
		quint32 flags = 0) {
	auto stream = Serialize::ByteArrayWriter();
	stream << version << quint32(0);
	if (version >= 2) {
		stream << publicKey;
	}
	if (version >= 3) {
		stream << flags;
	}
	return std::move(stream).result();
}

QByteArray CustodyWithSecret(bool active) {
	auto stream = Serialize::ByteArrayWriter();
	stream << quint32(4) << quint32(1)
		<< u"record-id"_q << u"address"_q << QByteArray(32, 'p')
		<< qint32(1) << u"private-ref"_q << quint32(active) << QByteArray()
		<< QByteArray(32, 'p') << quint32(0);
	return std::move(stream).result();
}

QByteArray CustodyWithPendingRotation() {
	auto stream = Serialize::ByteArrayWriter();
	stream << quint32(4) << quint32(0) << QByteArray(32, 'p') << quint32(1)
		<< u"record-id"_q << u"replacement-ref"_q << u"operation-id"_q
		<< QByteArray(32, 'r');
	return std::move(stream).result();
}

} // namespace

int main() {
	using Wallet::IsPublicWalletMigrationMetadata;
	auto checks = 0;
	auto failures = 0;
	const auto check = [&](bool passed, const char *name) {
		++checks;
		if (!passed) {
			++failures;
			std::fprintf(stderr, "Failed: %s\n", name);
		}
	};
	const auto accepts = [&](const QByteArray &value) {
		return IsPublicWalletMigrationMetadata(kCustodyKey, value);
	};
	const auto publicKey = QByteArray(32, 'p');
	const auto current = CustodyValue(4, publicKey);
	check(accepts(CustodyValue(1)), "v1 empty custody");
	check(accepts(CustodyValue(2, publicKey)), "v2 public key only");
	check(accepts(CustodyValue(3, publicKey)), "v3 public key only");
	check(accepts(current), "v4 public key only");
	check(accepts(CustodyValue(4)), "current null public key");
	check(accepts(CustodyValue(4, QByteArray(""))), "current empty public key");
	check(!accepts(CustodyValue(0)), "unknown version zero");
	check(!accepts(CustodyValue(5)), "future version");
	check(!accepts(CustodyValue(4, publicKey.chopped(1))), "short public key");
	check(!accepts(CustodyValue(4, publicKey + 'x')), "long public key");
	check(!accepts(CustodyValue(4, QByteArray(), 2)), "unknown flags");
	check(!accepts(CustodyValue(3, QByteArray(), 1)), "v3 pending rotation flag");
	check(!accepts(CustodyValue(4, QByteArray(), 1)), "v4 pending rotation flag");
	check(!accepts(CustodyWithPendingRotation()), "pending private reference");
	check(!accepts(CustodyWithSecret(true)), "active private reference");
	check(!accepts(CustodyWithSecret(false)), "parked private reference");
	check(!accepts(CustodyValue(4) + 'x'), "trailing byte");
	check(!accepts(QByteArray::fromHex("0000000400000000fffffffe")), "forged length");
	for (auto size = qsizetype(0); size != current.size(); ++size) {
		check(!accepts(current.first(size)), "truncated public metadata");
	}
	for (const auto &key : {
		u"custody/other"_q,
		u"custody/records/"_q,
		u"Custody/records"_q,
		u"journal/record/state"_q,
		u"secret/record"_q,
		u"vault/device-keyring"_q,
		u"vault/header"_q,
		QString(),
	}) {
		check(!IsPublicWalletMigrationMetadata(key, current), "wrong storage key");
	}
	std::printf("Passed %d of %d wallet metadata checks\n", checks - failures, checks);
	return failures ? 1 : 0;
}
