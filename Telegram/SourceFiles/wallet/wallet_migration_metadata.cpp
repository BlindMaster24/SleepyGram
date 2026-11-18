/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "wallet/wallet_migration_metadata.h"

#include "storage/serialize_common.h"
#include "wallet/wallet_custody.h"

namespace Wallet {

bool IsPublicWalletMigrationMetadata(
		const QString &storageKey,
		const QByteArray &decryptedValue) {
	constexpr auto kLastKnownVersion = quint32(4);
	constexpr auto kMaxPublicMetadataSize = 4 * sizeof(quint32)
		+ kCustodyPublicKeySize;
	if (storageKey != u"custody/records"_q
		|| decryptedValue.size() > qsizetype(kMaxPublicMetadataSize)) {
		return false;
	}
	auto stream = Serialize::ByteArrayReader(decryptedValue);
	auto version = quint32();
	auto recordCount = quint32();
	stream >> version >> recordCount;
	if (!stream.ok() || !version || version > kLastKnownVersion || recordCount) {
		return false;
	}
	if (version >= 2) {
		auto lastSeenServerKey = QByteArray();
		stream >> lastSeenServerKey;
		if (!lastSeenServerKey.isEmpty()
			&& lastSeenServerKey.size() != kCustodyPublicKeySize) {
			return false;
		}
	}
	auto flags = quint32();
	if (version >= 3) {
		stream >> flags;
	}
	return stream.ok() && !flags && stream.atEnd();
}

} // namespace Wallet
