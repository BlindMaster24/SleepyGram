/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "wallet/wallet_profile_migration_storage.h"

#include "core/version.h"
#include "storage/details/storage_file_utilities.h"
#include "wallet/wallet_profile_migration.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>

#include <openssl/crypto.h>

#include <algorithm>
#include <cstring>
#include <filesystem>

namespace Wallet {
namespace {

namespace Legacy = Storage::details;
using State = LegacyWalletProfileRingReading::State;

constexpr auto kMaximumFileBytes = qint64(64 * 1024 * 1024);
constexpr auto kTdfMagicSize = qsizetype(4);
constexpr auto kTdfHeaderSize = kTdfMagicSize + qsizetype(sizeof(qint32));
constexpr auto kTdfChecksumSize = qsizetype(16);

struct SourceVariant {
	QString relativePath;
	qint64 size = 0;
	QDateTime created;
	QDateTime lastModified;
	QFileDevice::Permissions permissions;
	uint owner = 0;
	uint group = 0;

	friend bool operator==(const SourceVariant &, const SourceVariant &) = default;
};

struct SourceSnapshot {
	QByteArray bytes;
	std::vector<SourceVariant> files;

	friend bool operator==(const SourceSnapshot &, const SourceSnapshot &) = default;
};

bool CanonicalRoot(const QString &path) {
	const auto info = QFileInfo(path);
	return QDir::isAbsolutePath(path)
		&& !path.startsWith(':')
		&& !path.contains(QChar(0))
		&& QDir::cleanPath(path) == path
		&& !info.fileName().isEmpty()
		&& info.isDir()
		&& !info.isSymLink()
		&& !info.isJunction()
		&& info.canonicalFilePath() == path
		&& QDir(path).isReadable();
}

bool ValidDataName(const QString &name) {
	return !name.isEmpty()
		&& name.size() <= 120
		&& !name.endsWith('.')
		&& !name.endsWith(' ')
		&& std::ranges::none_of(name, [](QChar ch) {
			return ch.unicode() < 32 || u"/\\:\"<>|?*"_q.contains(ch);
		});
}

std::optional<SourceVariant> InspectSourceVariant(
		const QFileInfo &info,
		const QString &path,
		const QString &relativePath) {
	auto error = std::error_code();
	if (!info.isFile()
		|| info.isSymLink()
		|| info.isJunction()
		|| info.canonicalFilePath() != path
		|| info.size() < kTdfHeaderSize + kTdfChecksumSize + qsizetype(sizeof(quint32))
		|| info.size() > kMaximumFileBytes
		|| std::filesystem::hard_link_count(info.filesystemFilePath(), error) != 1
		|| error) {
		return std::nullopt;
	}
	return SourceVariant{
		.relativePath = relativePath,
		.size = info.size(),
		.created = info.birthTime(),
		.lastModified = info.lastModified(),
		.permissions = info.permissions(),
		.owner = info.ownerId(),
		.group = info.groupId(),
	};
}

std::optional<SourceSnapshot> CaptureSource(
		const QString &root,
		const QString &stem) {
	if (!CanonicalRoot(root)) {
		return std::nullopt;
	}
	auto result = SourceSnapshot();
	for (const auto suffix : { 's', '0', '1' }) {
		const auto name = stem + QLatin1Char(suffix);
		const auto path = root + '/' + name;
		const auto info = QFileInfo(path);
		if (!info.exists() && !info.isSymLink() && !info.isJunction()) {
			continue;
		}
		const auto before = InspectSourceVariant(info, path, name);
		auto file = QFile(path);
		if (!before || !file.open(QIODevice::ReadOnly) || file.size() != before->size) {
			return std::nullopt;
		}
		auto bytes = file.read(before->size + 1);
		if (bytes.size() != before->size
			|| file.error() != QFileDevice::NoError
			|| InspectSourceVariant(QFileInfo(path), path, name) != before
			|| (!result.files.empty() && result.bytes != bytes)) {
			return std::nullopt;
		}
		if (result.files.empty()) {
			result.bytes = std::move(bytes);
		}
		result.files.push_back(*before);
	}
	return result;
}

bool ValidTdfSnapshot(QByteArrayView snapshot, qint32 &version) {
	if (!snapshot.startsWith("TDF$")) {
		return false;
	}
	const auto versionBytes = snapshot.sliced(kTdfMagicSize, sizeof(version));
	std::memcpy(&version, versionBytes.data(), sizeof(version));
	if (version <= 0 || version > AppVersion) {
		return false;
	}
	const auto size = qint32(snapshot.size() - kTdfHeaderSize - kTdfChecksumSize);
	auto checksum = QCryptographicHash(QCryptographicHash::Md5);
	checksum.addData(snapshot.sliced(kTdfHeaderSize, size));
	checksum.addData(QByteArrayView(reinterpret_cast<const char*>(&size), sizeof(size)));
	checksum.addData(versionBytes);
	checksum.addData(snapshot.first(kTdfMagicSize));
	return checksum.resultView() == snapshot.last(kTdfChecksumSize);
}

bool ReadSourceEnvelope(
		const SourceSnapshot &source,
		const QString &root,
		const QString &stem,
		const MTP::AuthKeyPtr &key,
		Legacy::EncryptedDescriptor &decrypted) {
	const auto snapshot = QByteArrayView(source.bytes);
	auto version = qint32();
	auto file = Legacy::FileReadDescriptor();
	if (!ValidTdfSnapshot(snapshot, version)
		|| !Legacy::ReadFile(file, stem, root + '/', Legacy::LegacyBackupPolicy::Preserve)
		|| file.version != version
		|| file.data != snapshot.sliced(
			kTdfHeaderSize,
			snapshot.size() - kTdfHeaderSize - kTdfChecksumSize)) {
		return false;
	}
	auto encrypted = QByteArray();
	file.stream >> encrypted;
	return file.stream.status() == QDataStream::Ok && file.stream.atEnd()
		&& Legacy::DecryptLocal(decrypted, encrypted, key);
}

std::vector<LegacyWalletSourceFileProof> SourceProofs(
		const SourceSnapshot &snapshot,
		const QString &prefix = {}) {
	const auto sha256 = QCryptographicHash::hash(snapshot.bytes, QCryptographicHash::Sha256);
	auto result = std::vector<LegacyWalletSourceFileProof>();
	result.reserve(snapshot.files.size());
	for (const auto &file : snapshot.files) {
		result.push_back({ .relativePath = prefix + file.relativePath, .sha256 = sha256 });
	}
	return result;
}

KeyringReading ReadSourceRing(
		const SourceSnapshot &source,
		const QString &root,
		const QString &stem,
		const MTP::AuthKeyPtr &key) {
	using ReadState = KeyringReading::State;
	auto decrypted = Legacy::EncryptedDescriptor();
	auto serialized = QByteArray();
	const auto wipe = gsl::finally([&] {
		if (!decrypted.data.isEmpty()) {
			OPENSSL_cleanse(decrypted.data.data(), decrypted.data.size());
		}
		if (!serialized.isEmpty()) {
			OPENSSL_cleanse(serialized.data(), serialized.size());
		}
	});
	if (!ReadSourceEnvelope(source, root, stem, key, decrypted)) {
		return { .state = ReadState::Broken };
	}
	decrypted.stream >> serialized;
	return (decrypted.stream.status() == QDataStream::Ok && decrypted.stream.atEnd())
		? ParseDeviceKeyring(serialized)
		: KeyringReading{ .state = ReadState::Broken };
}

} // namespace

LegacyWalletProfileRingReading ReadLegacyWalletProfileRing(
		const QString &canonicalDataDirectory,
		const QString &dataName,
		const MTP::AuthKeyPtr &authenticatedLegacyKey,
		const SecureBytes *dedicatedWalletPasscode) {
	if (!authenticatedLegacyKey || !ValidDataName(dataName)) {
		return {};
	}
	const auto stem = u"wallet_keyring_"_q + dataName;
	const auto snapshot = CaptureSource(canonicalDataDirectory, stem);
	if (!snapshot) {
		return {};
	} else if (snapshot->files.empty()) {
		return { .state = State::Absent };
	}
	auto source = ReadSourceRing(*snapshot, canonicalDataDirectory, stem, authenticatedLegacyKey);
	if (source.state == KeyringReading::State::Unsupported) {
		return { .state = State::Unsupported };
	} else if (source.state != KeyringReading::State::Read) {
		return {};
	}
	const auto &wrap = source.keyring.wrap;
	if (wrap.kind != VaultKind::Passcode && wrap.kind != VaultKind::Open) {
		return { .state = State::Unsupported };
	}
	auto passcode = QByteArray();
	if (wrap.kind == VaultKind::Passcode) {
		if (!dedicatedWalletPasscode) {
			return { .state = State::WalletPasscodeRequired };
		} else if (dedicatedWalletPasscode->empty()) {
			return { .state = State::WalletPasscodeRejected };
		}
		const auto input = dedicatedWalletPasscode->span();
		passcode = QByteArray::fromRawData(
			reinterpret_cast<const char*>(input.data()),
			input.size());
	}
	const auto wrapKey = DeriveVaultWrapKey(wrap, passcode);
	if (!wrapKey) {
		return { .state = State::Unsupported };
	}
	auto deviceKey = UnwrapVaultKey(wrap, *wrapKey);
	if (!deviceKey) {
		return { .state = (wrap.kind == VaultKind::Passcode)
			? State::WalletPasscodeRejected
			: State::InvalidSource };
	} else if (CaptureSource(canonicalDataDirectory, stem) != snapshot) {
		return {};
	}
	return {
		.state = State::Ready,
		.unlocked = UnlockedLegacyWalletProfileRing{
			.keyring = std::move(source.keyring),
			.deviceKey = std::move(*deviceKey),
			.files = SourceProofs(*snapshot),
		},
	};
}

std::optional<VerifiedLegacyWalletProfileRecord> ReadLegacyWalletProfileRecord(
		const Storage::AccountPaths &authenticatedAccount,
		Storage::FileKey fileKey,
		const QString &storageKey,
		const MTP::AuthKeyPtr &authenticatedLegacyKey) {
	const auto custody = (storageKey == u"custody/records"_q);
	if (!authenticatedLegacyKey
		|| !fileKey
		|| (!custody && !storageKey.startsWith(u"secret/"_q))
		|| authenticatedAccount.mode != Storage::AccountStorageMode::Legacy
		|| !authenticatedAccount.dataNameKey
		|| authenticatedAccount.basePath != authenticatedAccount.authPath + '/') {
		return std::nullopt;
	}
	const auto &root = authenticatedAccount.authPath;
	const auto accountDirectory = Legacy::ToFilePart(authenticatedAccount.dataNameKey);
	if (QFileInfo(root).fileName() != accountDirectory) {
		return std::nullopt;
	}
	const auto stem = Legacy::ToFilePart(fileKey);
	const auto snapshot = CaptureSource(root, stem);
	if (!snapshot || snapshot->files.empty()) {
		return std::nullopt;
	}
	auto decrypted = Legacy::EncryptedDescriptor();
	auto value = QByteArray();
	const auto wipe = gsl::finally([&] {
		if (!decrypted.data.isEmpty()) {
			OPENSSL_cleanse(decrypted.data.data(), decrypted.data.size());
		}
		if (!value.isEmpty()) {
			OPENSSL_cleanse(value.data(), value.size());
		}
	});
	if (!ReadSourceEnvelope(*snapshot, root, stem, authenticatedLegacyKey, decrypted)) {
		return std::nullopt;
	}
	constexpr auto kWalletEngineFormatVersion = quint32(1);
	auto version = quint32();
	decrypted.stream >> version >> value;
	if (decrypted.stream.status() != QDataStream::Ok
		|| !decrypted.stream.atEnd()
		|| version != kWalletEngineFormatVersion
		|| (custody ? !ReadProfileMigrationCustodyRefs(storageKey, value) : !IsVaultRecord(value))
		|| CaptureSource(root, stem) != snapshot) {
		return std::nullopt;
	}
	return VerifiedLegacyWalletProfileRecord{
		.value = std::exchange(value, QByteArray()),
		.files = SourceProofs(*snapshot, accountDirectory + '/'),
	};
}

} // namespace Wallet
