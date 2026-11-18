// This is the source code of AyuGram for Desktop.
#pragma once

#include <QtCore/QByteArray>
#include <QtCore/QStringList>
#include <QtCore/QStringView>

#include <algorithm>
#include <optional>
#include <vector>

namespace Ayu::OfflineHistory {

enum class LegacyOfflinePathKind : uchar {
	Invalid,
	Directory,
	Snapshot,
	Manifest,
	Attachment,
};

struct LegacyOfflineEntry final {
	QString relativePath;
	QByteArray sha256;
};

using OfflineRetirementInventory = std::vector<LegacyOfflineEntry>;

namespace details {

inline constexpr auto kLegacyAccountMask = quint64(0xFFFFFFFFFFFFULL);

[[nodiscard]] inline std::optional<quint64> Decimal(QStringView text) {
	auto ok = false;
	const auto number = text.toULongLong(&ok);
	return (ok && number && QString::number(number) == text)
		? std::optional(number)
		: std::nullopt;
}

[[nodiscard]] inline bool KnownPeer(quint64 id) {
	return (id & kLegacyAccountMask) && (id >> 48) <= 2;
}

[[nodiscard]] inline bool LegacyAttachmentName(QStringView name) {
	const auto dot = name.lastIndexOf('.');
	if (dot < 0 || name.size() - dot - 1 < 1 || name.size() - dot - 1 > 10) {
		return false;
	}
	const auto parts = name.left(dot).split('-');
	const auto message = (parts.size() == 4) ? Decimal(parts[1]) : std::nullopt;
	return parts.size() == 4 && parts[0] == u"m"
		&& message && *message <= 0x3FFFFFFF
		&& (parts[2] == u"p" || parts[2] == u"d") && Decimal(parts[3])
		&& std::ranges::all_of(name.mid(dot + 1), [](QChar ch) {
			return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9');
		});
}

} // namespace details

[[nodiscard]] inline LegacyOfflinePathKind ClassifyLegacyOfflinePath(QStringView path) {
	using Kind = LegacyOfflinePathKind;
	const auto parts = path.split('/');
	if (parts.isEmpty() || parts[0] != u"offline-history") {
		return Kind::Invalid;
	} else if (parts.size() == 1) {
		return Kind::Directory;
	}
	const auto account = details::Decimal(parts[1]);
	if (!account || *account > details::kLegacyAccountMask) {
		return Kind::Invalid;
	} else if (parts.size() == 2) {
		return Kind::Directory;
	} else if (!details::KnownPeer(details::Decimal(parts[2]).value_or(0))) {
		return Kind::Invalid;
	} else if (parts.size() == 3) {
		return Kind::Directory;
	} else if (parts[3] == u"attachments") {
		return (parts.size() == 4)
			? Kind::Directory
			: (parts.size() == 5 && details::LegacyAttachmentName(parts[4]))
				? Kind::Attachment
				: Kind::Invalid;
	} else if (parts.size() == 4) {
		if (parts[3] == u"history.json" || parts[3] == u"history.partial.json") {
			return Kind::Snapshot;
		} else if (parts[3] == u"attachments.json") {
			return Kind::Manifest;
		}
	}
	return Kind::Invalid;
}

} // namespace Ayu::OfflineHistory
