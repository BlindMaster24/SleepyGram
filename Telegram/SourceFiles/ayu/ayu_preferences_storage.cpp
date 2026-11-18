// This is the source code of AyuGram for Desktop.
#include "ayu/ayu_preferences_migration.h"

#include "base/basic_types.h"
#include "core/version.h"
#include "storage/details/storage_file_utilities.h"
#include "storage/serialize_common.h"

#include <QtCore/QDir>
#include <QtCore/QFileInfo>

#include <algorithm>
#include <filesystem>

namespace Ayu::Preferences {
namespace {

using namespace ::Storage::details;

const auto kAccountName = u"ayuprefs"_q;
const auto kGlobalName = u"sleepy-preferences"_q;
constexpr auto kMaximumFileBytes = 16 * 1024 * 1024 + 256;

bool ScopedAccountName(const QString &path) {
	const auto name = QFileInfo(path).fileName();
	return name.size() == 32 && std::ranges::all_of(name, [](QChar ch) {
		return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
	});
}

bool Present(const QFileInfo &info) {
	return info.exists() || info.isSymLink() || info.isJunction();
}

std::optional<QByteArray> ReadRecord(
		const QString &directory,
		const QString &name,
		const MTP::AuthKeyPtr &key) {
	const auto parent = QFileInfo(directory);
	if (!key || !parent.isDir() || parent.isSymLink() || parent.isJunction()
		|| parent.canonicalFilePath() != directory || !QDir(directory).isReadable()) {
		return std::nullopt;
	}
	const auto base = directory + '/' + name;
	if (Present(QFileInfo(base + '0')) || Present(QFileInfo(base + '1'))) {
		return std::nullopt;
	}
	const auto info = QFileInfo(base + 's');
	if (!Present(info)) {
		return QByteArray();
	}
	auto error = std::error_code();
	if (!info.isFile() || info.isSymLink() || info.isJunction()
		|| info.canonicalFilePath() != info.absoluteFilePath()
		|| info.size() <= 0 || info.size() > kMaximumFileBytes
		|| std::filesystem::hard_link_count(info.filesystemFilePath(), error) != 1
		|| error) {
		return std::nullopt;
	}
	auto file = FileReadDescriptor();
	if (!ReadEncryptedFile(file, name, directory + '/', key, LegacyBackupPolicy::Preserve)
		|| file.version <= 0) {
		return std::nullopt;
	}
	auto data = QByteArray();
	file.stream >> data;
	return (file.stream.status() == QDataStream::Ok && file.stream.atEnd()
		&& !data.isEmpty())
		? std::optional(std::move(data))
		: std::nullopt;
}

bool WriteRecord(
		const QString &directory,
		const QString &name,
		const MTP::AuthKeyPtr &key,
		const QByteArray &data) {
	auto encrypted = EncryptedDescriptor(Serialize::bytearraySize(data));
	encrypted.stream << data;
	auto file = FileWriteDescriptor(name, directory + '/');
	file.writeEncrypted(encrypted, key);
	return file.finishStaged(AppVersion) && ReadRecord(directory, name, key) == data;
}

} // namespace

std::optional<QByteArray> ReadScopedAccountPreferences(
		const QString &accountRoot,
		quint64 expectedUser,
		const MTP::AuthKeyPtr &key) {
	if (!expectedUser || !ScopedAccountName(accountRoot)) {
		return std::nullopt;
	}
	auto result = ReadRecord(accountRoot, kAccountName, key);
	return (result && (result->isEmpty() || DecodeAccountData(*result, expectedUser)))
		? std::move(result)
		: std::nullopt;
}

bool StageScopedAccountPreferences(
		const QString &accountRoot,
		quint64 expectedUser,
		const MTP::AuthKeyPtr &key,
		const QByteArray &payload) {
	if (!DecodeAccountData(payload, expectedUser)) {
		return false;
	}
	const auto existing = ReadScopedAccountPreferences(accountRoot, expectedUser, key);
	return existing && (*existing == payload
		|| (existing->isEmpty() && WriteRecord(accountRoot, kAccountName, key, payload)));
}

bool WriteScopedAccountPreferences(
		const QString &accountRoot,
		quint64 expectedUser,
		const MTP::AuthKeyPtr &key,
		const QByteArray &payload) {
	if (!DecodeAccountData(payload, expectedUser)) {
		return false;
	}
	const auto existing = ReadScopedAccountPreferences(accountRoot, expectedUser, key);
	return existing && (*existing == payload || WriteRecord(accountRoot, kAccountName, key, payload));
}

bool StageScopedGlobalPreferences(
		const QString &settingsDirectory,
		const MTP::AuthKeyPtr &key,
		const QByteArray &sanitizedGlobals) {
	if (!ValidateScopedGlobalPreferences(sanitizedGlobals)) {
		return false;
	}
	const auto existing = ReadRecord(settingsDirectory, kGlobalName, key);
	return existing && (*existing == sanitizedGlobals
		|| (existing->isEmpty() && WriteRecord(
			settingsDirectory, kGlobalName, key, sanitizedGlobals)));
}

} // namespace Ayu::Preferences
