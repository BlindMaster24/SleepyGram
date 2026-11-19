/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "wallet/wallet_profile_migration_storage.h"

#include "core/version.h"
#include "storage/details/storage_file_utilities.h"
#include "storage/details/storage_native_path.h"
#include "storage/serialize_common.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QTemporaryDir>

#include <algorithm>
#include <cstdio>
#include <filesystem>

namespace {

using namespace Wallet;
using State = LegacyWalletProfileRingReading::State;

const auto kDataName = u"fixture"_q;
const auto kRingName = u"wallet_keyring_fixture"_q;

MTP::AuthKeyPtr LegacyKey(gsl::byte seed) {
	auto bytes = MTP::AuthKey::Data();
	bytes.fill(seed);
	return std::make_shared<MTP::AuthKey>(bytes);
}

bool WriteBytes(const QString &path, const QByteArray &bytes) {
	auto file = QFile(path);
	return file.open(QIODevice::WriteOnly)
		&& file.write(bytes) == bytes.size()
		&& file.flush();
}

QByteArray ReadBytes(const QString &path) {
	auto file = QFile(path);
	return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
}

QByteArray EncodeFixture(
		const QByteArray &ring,
		const MTP::AuthKeyPtr &key,
		bool extraInnerByte = false,
		bool extraOuterByte = false) {
	auto inner = Storage::details::EncryptedDescriptor(
		Serialize::bytearraySize(ring) + int(extraInnerByte));
	inner.stream << ring;
	if (extraInnerByte) {
		inner.stream << quint8(7);
	}
	auto outer = Serialize::ByteArrayWriter();
	outer << Storage::details::PrepareEncrypted(inner, key);
	if (extraOuterByte) {
		outer << quint8(7);
	}
	const auto body = std::move(outer).result();
	const auto size = qint32(body.size());
	const auto version = qint32(AppVersion);
	auto file = QByteArray("TDF$");
	file.append(reinterpret_cast<const char*>(&version), sizeof(version));
	file.append(body);
	auto checksum = QCryptographicHash(QCryptographicHash::Md5);
	checksum.addData(body);
	checksum.addData(QByteArrayView(reinterpret_cast<const char*>(&size), sizeof(size)));
	checksum.addData(QByteArrayView(reinterpret_cast<const char*>(&version), sizeof(version)));
	checksum.addData(QByteArrayView("TDF$"));
	file.append(checksum.result());
	return file;
}

bool MatchesState(const LegacyWalletProfileRingReading &reading, State expected) {
	return reading.state == expected && (bool(reading.unlocked) == (expected == State::Ready));
}

bool MatchesProofs(
		const LegacyWalletProfileRingReading &reading,
		const QByteArray &source,
		const SecureBytes &deviceKey,
		std::initializer_list<QString> names) {
	if (!MatchesState(reading, State::Ready)
		|| reading.unlocked->files.size() != names.size()
		|| !std::ranges::equal(reading.unlocked->deviceKey.span(), deviceKey.span())) {
		return false;
	}
	const auto digest = QCryptographicHash::hash(source, QCryptographicHash::Sha256);
	return std::ranges::equal(reading.unlocked->files, names, [&](const auto &proof,
			const auto &name) {
		return proof.relativePath == name && proof.sha256 == digest;
	});
}

} // namespace

int main() {
	const auto fixture = QTemporaryDir();
	const auto root = QDir(fixture.path()).canonicalPath();
	const auto key = LegacyKey(gsl::byte(1));
	const auto otherKey = LegacyKey(gsl::byte(2));
	const auto open = PrepareVaultOpenWrap();
	auto ring = open ? RotateDeviceKeyring({}, {}, *open) : std::nullopt;
	if (!fixture.isValid() || !ring) {
		return 2;
	}
	const auto entry = SealDeviceKeyringEntry(
		ring->key,
		QByteArray(kVaultKeyIdSize, 'i'),
		42,
		SecureBytes(QByteArray(kVaultKeySize, 'k')));
	if (!entry) {
		return 2;
	}
	ring->keyring.entries.push_back(*entry);
	const auto serialized = SerializeDeviceKeyring(ring->keyring);
	const auto source = EncodeFixture(serialized, key);
	const auto modern = root + '/' + kRingName + 's';
	const auto first = root + '/' + kRingName + '0';
	const auto second = root + '/' + kRingName + '1';
	const auto read = [&](const SecureBytes *passcode = nullptr) {
		return ReadLegacyWalletProfileRing(root, kDataName, key, passcode);
	};
	auto checks = 0;
	auto failures = 0;
	const auto check = [&](bool passed, const char *label) {
		++checks;
		if (!passed) {
			++failures;
			std::fprintf(stderr, "Failed: %s\n", label);
		}
	};
	check(MatchesState(read(), State::Absent), "exact stem absent");
	check(MatchesState(ReadLegacyWalletProfileRing(root, kDataName, {}), State::InvalidSource),
		"authenticated legacy key is required");
	check(MatchesState(ReadLegacyWalletProfileRing(root, u"../fixture"_q, key),
		State::InvalidSource), "unsafe data name");
	check(MatchesState(ReadLegacyWalletProfileRing(root + u"/."_q, kDataName, key),
		State::InvalidSource), "noncanonical directory");
	check(WriteBytes(root + u"/wallet_keyring_other0"_q, QByteArray("unrelated"))
		&& MatchesState(read(), State::Absent), "unrelated stem preserved");
	check(WriteBytes(modern, source), "write synthetic open ring");
	const auto opened = read();
	check(MatchesProofs(opened, source, ring->key, { kRingName + 's' }),
		"authenticated Open ring and exact hash");
	check(opened.unlocked && SerializeDeviceKeyring(opened.unlocked->keyring) == serialized,
		"authenticated inner keyring returned unchanged");
	check(MatchesState(ReadLegacyWalletProfileRing(root, kDataName, otherKey),
		State::InvalidSource), "legacy outer key authentication required");
	check(QFile::rename(modern, first), "move synthetic primary to legacy suffix");
	check(MatchesProofs(read(), source, ring->key, { kRingName + '0' }),
		"single legacy suffix proof");
	check(QFile::copy(first, second), "create identical legacy fallback");
	check(MatchesProofs(read(), source, ring->key, { kRingName + '0', kRingName + '1' })
		&& ReadBytes(first) == source && ReadBytes(second) == source,
		"legacy variants authenticated and preserved");
	check(QFile::copy(first, modern), "create identical modern suffix");
	check(MatchesProofs(read(), source, ring->key,
		{ kRingName + 's', kRingName + '0', kRingName + '1' }),
		"all byte-identical variants proved");
	const auto alternate = RotateDeviceKeyring(ring->keyring, ring->key, *open);
	if (!alternate) {
		return 2;
	}
	const auto divergent = EncodeFixture(SerializeDeviceKeyring(alternate->keyring), key);
	check(WriteBytes(second, divergent) && MatchesState(read(), State::InvalidSource)
		&& ReadBytes(second) == divergent, "separately valid divergent alternate refused");
	check(QFile::remove(first) && QFile::remove(second), "remove synthetic alternates");
	check(WriteBytes(modern, EncodeFixture(serialized, key, false, true))
		&& MatchesState(read(), State::InvalidSource), "trailing bytes outside legacy envelope");
	check(WriteBytes(modern, EncodeFixture(serialized, key, true))
		&& MatchesState(read(), State::InvalidSource), "trailing bytes inside legacy envelope");
	auto badChecksum = source;
	badChecksum[badChecksum.size() - 1] ^= 1;
	check(WriteBytes(modern, badChecksum) && MatchesState(read(), State::InvalidSource),
		"bad TDF checksum");
	check(WriteBytes(modern, source), "restore synthetic Open ring");
	auto filesystemError = std::error_code();
	const auto modernPath = Storage::NativeFilePath(QFileInfo(modern).filePath());
	const auto secondPath = Storage::NativeFilePath(QFileInfo(second).filePath());
	std::filesystem::create_hard_link(modernPath, secondPath, filesystemError);
	check(!filesystemError && MatchesState(read(), State::InvalidSource), "hard links rejected");
	check(QFile::remove(second), "remove synthetic hard link");
#ifndef _WIN32
	std::filesystem::create_symlink(modernPath, secondPath, filesystemError);
	check(!filesystemError && MatchesState(read(), State::InvalidSource), "symlink variant rejected");
	check(QFile::remove(second), "remove synthetic symlink");
	const auto alias = root + u"/aliased-root"_q;
	std::filesystem::create_directory_symlink(Storage::NativeFilePath(QFileInfo(root).filePath()),
		Storage::NativeFilePath(QFileInfo(alias).filePath()), filesystemError);
	check(!filesystemError && MatchesState(ReadLegacyWalletProfileRing(alias, kDataName, key),
		State::InvalidSource), "symlink directory rejected");
#endif
	auto hardware = ring->keyring;
	hardware.wrap.kind = VaultKind::TouchId;
	check(WriteBytes(modern, EncodeFixture(SerializeDeviceKeyring(hardware), key))
		&& MatchesState(read(), State::Unsupported), "native factor unsupported in detached reader");
	const auto exact = u" wallet α "_q.toUtf8();
	const auto passcode = SecureBytes(exact);
	const auto wrong = SecureBytes(exact.trimmed());
	const auto password = PrepareVaultPasscodeWrap(exact);
	const auto protectedRing = password
		? RotateDeviceKeyring(ring->keyring, ring->key, *password)
		: std::nullopt;
	if (!protectedRing) {
		return 2;
	}
	const auto protectedBytes = EncodeFixture(SerializeDeviceKeyring(protectedRing->keyring), key);
	check(WriteBytes(modern, protectedBytes), "write synthetic Passcode ring");
	check(MatchesState(read(), State::WalletPasscodeRequired), "asks separate wallet passcode");
	check(MatchesState(read(&wrong), State::WalletPasscodeRejected), "wrong exact passcode rejected");
	check(MatchesProofs(read(&passcode), protectedBytes, protectedRing->key, { kRingName + 's' }),
		"exact UTF-8 wallet passcode authenticates ring");
	check(ReadBytes(modern) == protectedBytes, "source stable after detached authentication");
	std::printf("Passed %d of %d legacy wallet ring checks\n", checks - failures, checks);
	return failures ? 1 : 0;
}
