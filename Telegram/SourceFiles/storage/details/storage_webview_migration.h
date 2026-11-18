// This is the source code of AyuGram for Desktop.
#pragma once

#include "storage/details/storage_hkdf.h"

#include <QtCore/QByteArray>

#include <array>
#include <optional>
#include <string_view>

namespace Storage::details {

enum class LegacyWebviewStorageProof : uchar {
	NoToken,
	FilePaths,
	Unsupported,
};

enum class LegacyWebviewBackend : uchar {
	SuppliedPaths,
	SharedOrNativeStorage,
};

struct ProtectedWebviewTokens final {
	QByteArray bots;
	QByteArray other;
};

[[nodiscard]] inline std::optional<ProtectedWebviewTokens> MakeProtectedWebviewTokens(
		bytes::const_span accountKey) {
	constexpr auto kTokenSize = size_t(16);
	constexpr auto context = std::string_view("SleepyGram scoped Mini App storage v1");
	auto tokens = std::array<unsigned char, 2 * kTokenSize>();
	if (!HkdfSha256(accountKey, {}, bytes::make_span(context), bytes::make_span(tokens))) {
		return std::nullopt;
	}
	const auto take = [&](size_t offset) {
		tokens[offset + 6] = (tokens[offset + 6] & 0x0F) | 0x40;
		tokens[offset + 8] = (tokens[offset + 8] & 0x3F) | 0x80;
		return QByteArray(reinterpret_cast<const char*>(tokens.data() + offset), kTokenSize);
	};
	auto result = ProtectedWebviewTokens{ take(0), take(kTokenSize) };
	OPENSSL_cleanse(tokens.data(), tokens.size());
	return result.bots != result.other ? std::optional(std::move(result)) : std::nullopt;
}

[[nodiscard]] inline LegacyWebviewStorageProof ClassifyLegacyWebviewTokens(
		const QByteArray &bots,
		const QByteArray &other,
		LegacyWebviewBackend backend) {
	constexpr auto kModernTokenSize = 16;
	using Proof = LegacyWebviewStorageProof;
	if (bots.isEmpty() && other.isEmpty()) {
		return Proof::NoToken;
	} else if (backend == LegacyWebviewBackend::SuppliedPaths
		&& (bots.isEmpty() || bots.size() == kModernTokenSize)
		&& (other.isEmpty() || other.size() == kModernTokenSize)) {
		return Proof::FilePaths;
	}
	return Proof::Unsupported;
}

[[nodiscard]] inline LegacyWebviewStorageProof ClassifyLegacyWebviewTokens(
		const QByteArray &bots,
		const QByteArray &other) {
#if defined Q_OS_WIN || defined Q_OS_MAC
	constexpr auto backend = LegacyWebviewBackend::SharedOrNativeStorage;
#else
	constexpr auto backend = LegacyWebviewBackend::SuppliedPaths;
#endif
	return ClassifyLegacyWebviewTokens(bots, other, backend);
}

} // namespace Storage::details
