// This is the source code of AyuGram for Desktop.
#pragma once

#include <QtCore/QByteArray>

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
