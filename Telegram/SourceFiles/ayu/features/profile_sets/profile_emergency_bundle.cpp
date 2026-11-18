// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_emergency_bundle.h"

#include "ayu/features/profile_sets/profile_vault.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QtEndian>

#include <cstring>

namespace Ayu::ProfileSets {
namespace {

constexpr char kMagic[] = "SGEB1";
constexpr auto kCapsuleLimit = EmergencyActions::kMaxSealedEmergencyRules;
constexpr auto kDigestSize = 32;
constexpr auto kBundleLimit = qsizetype(80 * 1024 * 1024);
constexpr auto kSizeLength = qsizetype(sizeof(quint32));

QByteArray Digest(QByteArrayView value) {
	return QCryptographicHash::hash(value, QCryptographicHash::Sha256);
}

void AddSize(QByteArray &data, size_t size) {
	const auto encoded = qToBigEndian(quint32(size));
	data.append(reinterpret_cast<const char*>(&encoded), sizeof(encoded));
}

std::optional<quint32> TakeSize(QByteArrayView &data) {
	if (data.size() < kSizeLength) {
		return std::nullopt;
	}
	const auto result = qFromBigEndian<quint32>(data.data());
	data = data.sliced(kSizeLength);
	return result;
}

} // namespace

std::optional<ProfileEmergencyBundle> ReadProfileEmergencyBundle(
		const CommittedMigration &committed) {
	const auto vault = ParseProfileVault(committed.profileVault);
	const auto magic = QByteArrayView(kMagic);
	auto bytes = QByteArrayView(committed.emergencyRules);
	const auto vaultSize = qsizetype(EmergencyActions::SealedEmergencyRulesSize());
	if (!vault || vault->version != kProfileVaultVersion || vault->id.size() != 16
		|| committed.transactionId.size() != 16 || !committed.legacyRetirement.isEmpty()
		|| bytes.size() > kBundleLimit || bytes.size() < magic.size() + vaultSize
		|| !bytes.startsWith(magic)) {
		return std::nullopt;
	}
	bytes = bytes.sliced(magic.size());
	auto result = ProfileEmergencyBundle();
	result.rules = bytes.first(vaultSize).toByteArray();
	const auto ruleDigest = Digest(result.rules);
	std::memcpy(result.authority.digest.data(), ruleDigest.data(), kDigestSize);
	result.authority.generation = {
		.installationId = EmergencyActions::InstallationId(vault->id.toHex().toStdString()),
		.transactionId = committed.transactionId.toHex().toStdString(),
	};
	bytes = bytes.sliced(vaultSize);
	const auto count = TakeSize(bytes);
	if (!count || *count > kCapsuleLimit) {
		return std::nullopt;
	}
	auto previous = QByteArray();
	for (auto i = quint32(0); i != *count; ++i) {
		if (bytes.size() < kDigestSize) {
			return std::nullopt;
		}
		auto digest = bytes.first(kDigestSize).toByteArray();
		bytes = bytes.sliced(kDigestSize);
		const auto size = TakeSize(bytes);
		if (!size || !*size || *size > bytes.size() || digest <= previous
			|| digest != Digest(bytes.first(*size))) {
			return std::nullopt;
		}
		previous = digest;
		result.capsules.emplace(std::move(digest), bytes.first(*size).toByteArray());
		bytes = bytes.sliced(*size);
	}
	return bytes.isEmpty() ? std::optional(std::move(result)) : std::nullopt;
}

QByteArray SerializeProfileEmergencyBundle(
		const QByteArray &rules,
		const std::map<QByteArray, QByteArray> &capsules) {
	if (size_t(rules.size()) != EmergencyActions::SealedEmergencyRulesSize()
		|| capsules.size() > kCapsuleLimit) {
		return {};
	}
	auto size = qsizetype(sizeof(kMagic) - 1) + rules.size() + kSizeLength;
	for (const auto &[digest, capsule] : capsules) {
		if (digest.size() != kDigestSize || capsule.isEmpty()
			|| capsule.size() > kBundleLimit - size - kDigestSize - kSizeLength
			|| Digest(capsule) != digest) {
			return {};
		}
		size += kDigestSize + kSizeLength + capsule.size();
	}
	auto result = QByteArray(kMagic) + rules;
	result.reserve(size);
	AddSize(result, capsules.size());
	for (const auto &[digest, capsule] : capsules) {
		result.append(digest);
		AddSize(result, capsule.size());
		result.append(capsule);
	}
	return result;
}

} // namespace Ayu::ProfileSets
