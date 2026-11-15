/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/account_registry.h"

#include "base/basic_types.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>

#include <algorithm>
#include <initializer_list>
#include <limits>
#include <map>
#include <set>

namespace Ayu::ProfileSets {
namespace {

constexpr auto kMaximumEntries = 65'536;
constexpr auto kMaximumPayloadSize = 16 * 1024 * 1024;
constexpr auto kMaximumIdentityCount = 4;
constexpr auto kDigestSize = 32;

QString IdText(AccountId id) {
	return QString::number(id.high, 16).rightJustified(16, u'0')
		+ QString::number(id.low, 16).rightJustified(16, u'0');
}

bool ParseId(QStringView text, AccountId *id) {
	if (text.size() != 32) {
		return false;
	}
	bool highOk = false;
	bool lowOk = false;
	id->high = text.first(16).toULongLong(&highOk, 16);
	id->low = text.last(16).toULongLong(&lowOk, 16);
	return highOk && lowOk && bool(*id);
}

QString HexText(const QByteArray &bytes) {
	return QString::fromLatin1(bytes.toHex());
}

QByteArray ParseHex(QStringView text, qsizetype expectedSize) {
	if (text.size() != (2 * expectedSize)) {
		return QByteArray();
	}
	const auto encoded = text.toLatin1();
	const auto decoded = QByteArray::fromHex(encoded);
	return (decoded.size() == expectedSize)
		&& (decoded.toHex() == encoded.toLower())
		? decoded
		: QByteArray();
}

QByteArray HashDataName(const QString &dataName) {
	return QCryptographicHash::hash(
		dataName.toUtf8(),
		QCryptographicHash::Sha256);
}

bool ValidEnvironment(const QByteArray &environmentId) {
	return environmentId.size() >= 16 && environmentId.size() <= 64;
}

bool ValidIdentity(const VerifiedRegistryIdentity &identity) {
	switch (identity.kind) {
	case RegistryIdentityKind::ServerUserId:
		return identity.value.size() == 8
			&& std::any_of(identity.value.cbegin(), identity.value.cend(),
				[](char ch) { return ch != 0; });
	case RegistryIdentityKind::VerifiedLocator:
		return identity.value.size() == kDigestSize
			&& std::any_of(identity.value.cbegin(), identity.value.cend(),
				[](char ch) { return ch != 0; });
	}
	return false;
}

bool ValidDataName(const QString &dataName) {
	if (dataName.isEmpty() || dataName.size() > 256) {
		return false;
	}
	return std::none_of(dataName.cbegin(), dataName.cend(), [](QChar ch) {
		return ch.isNull() || ch.category() == QChar::Other_Control;
	});
}

void SetError(RegistryError *error, RegistryError value) {
	if (error) {
		*error = value;
	}
}

bool HasExactKeys(
		const QJsonObject &object,
		std::initializer_list<QString> expected) {
	if (object.size() != qsizetype(expected.size())) {
		return false;
	}
	return std::all_of(expected.begin(), expected.end(), [&](const QString &key) {
		return object.contains(key);
	});
}

QJsonObject EntryObject(const AccountRegistryEntry &entry) {
	auto identities = QJsonArray();
	for (const auto &fingerprint : entry.identityFingerprints) {
		identities.push_back(HexText(fingerprint));
	}
	return QJsonObject{
		{ u"id"_q, IdText(entry.id) },
		{ u"legacy_name_hash"_q, HexText(entry.legacyDataNameHash) },
		{ u"slot"_q, double(entry.slot) },
		{ u"identities"_q, identities },
		{ u"retired"_q, entry.retired },
	};
}

bool ReadUint32(const QJsonValue &value, quint32 *result) {
	if (!value.isDouble()) {
		return false;
	}
	const auto number = value.toDouble();
	if (number < 0
		|| number > std::numeric_limits<quint32>::max()
		|| number != double(quint32(number))) {
		return false;
	}
	*result = quint32(number);
	return true;
}

} // namespace

QByteArray RegistryIdentityFingerprint(
		const VerifiedRegistryIdentity &identity) {
	if (!ValidIdentity(identity)) {
		return QByteArray();
	}
	auto material = QByteArray(1, char(identity.kind));
	material += identity.value;
	return QCryptographicHash::hash(
		material,
		QCryptographicHash::Sha256);
}

QByteArray AccountRegistryDataNameHash(const QString &dataName) {
	return ValidDataName(dataName) ? HashDataName(dataName) : QByteArray();
}

std::optional<AccountRegistry> NewAccountRegistry(
		QByteArray environmentId,
		RegistryError *error) {
	if (!ValidEnvironment(environmentId)) {
		SetError(error, RegistryError::InvalidEnvironment);
		return std::nullopt;
	}
	SetError(error, RegistryError::None);
	return AccountRegistry{
		.version = kAccountRegistryVersion,
		.environmentId = std::move(environmentId),
	};
}

RegistryError ValidateAccountRegistry(const AccountRegistry &registry) {
	if (registry.version != kAccountRegistryVersion) {
		return RegistryError::UnsupportedVersion;
	} else if (!ValidEnvironment(registry.environmentId)) {
		return RegistryError::InvalidEnvironment;
	} else if (registry.entries.size() > kMaximumEntries) {
		return RegistryError::TooLarge;
	}
	auto ids = std::set<AccountId>();
	auto fingerprints = std::set<QByteArray>();
	for (const auto &entry : registry.entries) {
		if (!entry.id
			|| entry.legacyDataNameHash.size() != kDigestSize
			|| entry.identityFingerprints.empty()
			|| entry.identityFingerprints.size() > kMaximumIdentityCount) {
			return RegistryError::InvalidEntry;
		} else if (!ids.insert(entry.id).second) {
			return RegistryError::DuplicateAccountId;
		}
		auto localFingerprints = std::set<QByteArray>();
		for (const auto &fingerprint : entry.identityFingerprints) {
			if (fingerprint.size() != kDigestSize) {
				return RegistryError::InvalidEntry;
			} else if (!localFingerprints.insert(fingerprint).second
				|| !fingerprints.insert(fingerprint).second) {
				return RegistryError::DuplicateIdentityFingerprint;
			}
		}
	}
	return RegistryError::None;
}

QByteArray SerializeAccountRegistry(
		const AccountRegistry &registry,
		RegistryError *error) {
	const auto validation = ValidateAccountRegistry(registry);
	if (validation != RegistryError::None) {
		SetError(error, validation);
		return QByteArray();
	}
	auto entries = QJsonArray();
	for (const auto &entry : registry.entries) {
		entries.push_back(EntryObject(entry));
	}
	const auto object = QJsonObject{
		{ u"version"_q, int(registry.version) },
		{ u"environment_id"_q, HexText(registry.environmentId) },
		{ u"entries"_q, entries },
	};
	const auto result = QJsonDocument(object).toJson(QJsonDocument::Compact);
	if (result.size() > kMaximumPayloadSize) {
		SetError(error, RegistryError::TooLarge);
		return QByteArray();
	}
	SetError(error, RegistryError::None);
	return result;
}

std::optional<AccountRegistry> ParseAccountRegistry(
		const QByteArray &payload,
		RegistryError *error) {
	SetError(error, RegistryError::Malformed);
	if (payload.isEmpty() || payload.size() > kMaximumPayloadSize) {
		SetError(error, RegistryError::TooLarge);
		return std::nullopt;
	}
	QJsonParseError parseError;
	const auto document = QJsonDocument::fromJson(payload, &parseError);
	if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
		return std::nullopt;
	}
	const auto object = document.object();
	if (!HasExactKeys(object, {
		u"version"_q,
		u"environment_id"_q,
		u"entries"_q,
	})) {
		return std::nullopt;
	}
	const auto version = object.value(u"version"_q);
	const auto environmentText = object.value(u"environment_id"_q).toString();
	const auto entriesValue = object.value(u"entries"_q);
	if (!version.isDouble()
		|| environmentText.size() < 32
		|| environmentText.size() > 128
		|| (environmentText.size() % 2)
		|| !QByteArray::fromHex(environmentText.toLatin1()).size()
		|| QByteArray::fromHex(environmentText.toLatin1()).toHex()
			!= environmentText.toLatin1().toLower()
		|| !entriesValue.isArray()) {
		return std::nullopt;
	}
	const auto versionInt = version.toInt(-1);
	if (versionInt < 0 || version.toDouble() != versionInt) {
		return std::nullopt;
	}
	auto result = AccountRegistry();
	result.version = quint32(versionInt);
	result.environmentId = QByteArray::fromHex(environmentText.toLatin1());
	if (entriesValue.toArray().size() > kMaximumEntries) {
		SetError(error, RegistryError::TooLarge);
		return std::nullopt;
	}
	for (const auto &value : entriesValue.toArray()) {
		if (!value.isObject()) {
			return std::nullopt;
		}
		const auto entryObject = value.toObject();
		if (!HasExactKeys(entryObject, {
			u"id"_q,
			u"legacy_name_hash"_q,
			u"slot"_q,
			u"identities"_q,
			u"retired"_q,
		})) {
			return std::nullopt;
		}
		const auto idText = entryObject.value(u"id"_q).toString();
		const auto legacyHashText = entryObject.value(
			u"legacy_name_hash"_q).toString();
		const auto identitiesValue = entryObject.value(u"identities"_q);
		const auto retiredValue = entryObject.value(u"retired"_q);
		if (!identitiesValue.isArray() || !retiredValue.isBool()) {
			return std::nullopt;
		}
		auto entry = AccountRegistryEntry();
		if (!ParseId(idText, &entry.id)
			|| !ReadUint32(entryObject.value(u"slot"_q), &entry.slot)) {
			return std::nullopt;
		}
		entry.legacyDataNameHash = ParseHex(legacyHashText, kDigestSize);
		entry.retired = retiredValue.toBool();
		for (const auto &identityValue : identitiesValue.toArray()) {
			if (!identityValue.isString()) {
				return std::nullopt;
			}
			auto fingerprint = ParseHex(identityValue.toString(), kDigestSize);
			if (fingerprint.isEmpty()) {
				return std::nullopt;
			}
			entry.identityFingerprints.push_back(std::move(fingerprint));
		}
		result.entries.push_back(std::move(entry));
	}
	const auto validation = ValidateAccountRegistry(result);
	SetError(error, validation);
	return (validation == RegistryError::None)
		? std::optional<AccountRegistry>(std::move(result))
		: std::nullopt;
}

std::optional<AccountRegistry> ReconcileAccountRegistry(
		const AccountRegistry &registry,
		const QByteArray &environmentId,
		const std::vector<ObservedLegacyAccount> &observed,
		Fn<AccountId()> generateId,
		RegistryError *error) {
	const auto validation = ValidateAccountRegistry(registry);
	if (validation != RegistryError::None) {
		SetError(error, validation);
		return std::nullopt;
	} else if (environmentId != registry.environmentId) {
		SetError(error, RegistryError::EnvironmentMismatch);
		return std::nullopt;
	} else if (observed.size() > kMaximumEntries) {
		SetError(error, RegistryError::TooLarge);
		return std::nullopt;
	}
	auto fingerprints = std::vector<std::vector<QByteArray>>();
	auto identitiesSeen = std::set<QByteArray>();
	auto locatorsSeen = std::set<std::pair<QByteArray, quint32>>();
	fingerprints.reserve(observed.size());
	for (const auto &account : observed) {
		if (!ValidDataName(account.dataName)) {
			SetError(error, RegistryError::InvalidEntry);
			return std::nullopt;
		} else if (account.identities.empty()
			|| account.identities.size() > kMaximumIdentityCount) {
			SetError(error, RegistryError::InvalidIdentity);
			return std::nullopt;
		}
		const auto locator = std::pair(HashDataName(account.dataName), account.slot);
		if (!locatorsSeen.insert(locator).second) {
			SetError(error, RegistryError::DuplicateObservedLocator);
			return std::nullopt;
		}
		auto accountFingerprints = std::vector<QByteArray>();
		for (const auto &identity : account.identities) {
			auto fingerprint = RegistryIdentityFingerprint(identity);
			if (fingerprint.isEmpty()) {
				SetError(error, RegistryError::InvalidIdentity);
				return std::nullopt;
			} else if (!identitiesSeen.insert(fingerprint).second) {
				SetError(error, RegistryError::DuplicateObservedIdentity);
				return std::nullopt;
			}
			accountFingerprints.push_back(std::move(fingerprint));
		}
		fingerprints.push_back(std::move(accountFingerprints));
	}
	auto result = registry;
	auto existingIds = std::set<AccountId>();
	auto fingerprintToEntry = std::map<QByteArray, size_t>();
	for (auto &entry : result.entries) {
		entry.retired = true;
		existingIds.insert(entry.id);
		const auto index = size_t(&entry - result.entries.data());
		for (const auto &fingerprint : entry.identityFingerprints) {
			fingerprintToEntry.emplace(fingerprint, index);
		}
	}
	for (auto i = size_t(0); i != observed.size(); ++i) {
		const auto &account = observed[i];
		const auto legacyHash = HashDataName(account.dataName);
		auto matched = size_t(-1);
		for (const auto &fingerprint : fingerprints[i]) {
			if (const auto j = fingerprintToEntry.find(fingerprint);
				j != fingerprintToEntry.end()) {
				if (matched != size_t(-1) && matched != j->second) {
					SetError(error, RegistryError::DuplicateIdentityFingerprint);
					return std::nullopt;
				}
				matched = j->second;
			}
		}
		if (matched == size_t(-1)) {
			auto id = AccountId();
			for (auto attempt = 0; attempt != 16; ++attempt) {
				id = generateId();
				if (id && !existingIds.contains(id)) {
					break;
				}
				id = AccountId();
			}
			if (!id) {
				SetError(error, RegistryError::RandomFailure);
				return std::nullopt;
			}
			existingIds.insert(id);
			auto entry = AccountRegistryEntry{
				.id = id,
				.legacyDataNameHash = legacyHash,
				.slot = account.slot,
				.identityFingerprints = fingerprints[i],
				.retired = false,
			};
			const auto newIndex = result.entries.size();
			for (const auto &fingerprint : entry.identityFingerprints) {
				fingerprintToEntry.emplace(fingerprint, newIndex);
			}
			result.entries.push_back(std::move(entry));
		} else {
			auto &entry = result.entries[matched];
			for (const auto &fingerprint : fingerprints[i]) {
				if (std::find(entry.identityFingerprints.begin(),
					entry.identityFingerprints.end(), fingerprint)
					== entry.identityFingerprints.end()) {
					if (entry.identityFingerprints.size()
						== kMaximumIdentityCount) {
						SetError(error, RegistryError::InvalidIdentity);
						return std::nullopt;
					}
					entry.identityFingerprints.push_back(fingerprint);
					fingerprintToEntry.emplace(fingerprint, matched);
				}
			}
			entry.legacyDataNameHash = legacyHash;
			entry.slot = account.slot;
			entry.retired = false;
		}
	}
	const auto resultValidation = ValidateAccountRegistry(result);
	SetError(error, resultValidation);
	return (resultValidation == RegistryError::None)
		? std::optional<AccountRegistry>(std::move(result))
		: std::nullopt;
}

RegistryError BindRegistryIdentity(
		AccountRegistry *registry,
		AccountId accountId,
		const VerifiedRegistryIdentity &identity) {
	if (!registry) {
		return RegistryError::InvalidEntry;
	}
	if (const auto validation = ValidateAccountRegistry(*registry);
		validation != RegistryError::None) {
		return validation;
	}
	const auto fingerprint = RegistryIdentityFingerprint(identity);
	if (fingerprint.isEmpty()) {
		return RegistryError::InvalidIdentity;
	}
	auto entry = std::find_if(registry->entries.begin(), registry->entries.end(),
		[&](const AccountRegistryEntry &candidate) {
			return candidate.id == accountId;
		});
	if (entry == registry->entries.end()) {
		return RegistryError::InvalidEntry;
	}
	for (const auto &candidate : registry->entries) {
		if (std::find(candidate.identityFingerprints.cbegin(),
			candidate.identityFingerprints.cend(), fingerprint)
			!= candidate.identityFingerprints.cend()) {
			return (candidate.id == accountId)
				? RegistryError::None
				: RegistryError::DuplicateIdentityFingerprint;
		}
	}
	if (entry->identityFingerprints.size() == kMaximumIdentityCount) {
		return RegistryError::InvalidIdentity;
	}
	entry->identityFingerprints.push_back(fingerprint);
	return ValidateAccountRegistry(*registry);
}

} // namespace Ayu::ProfileSets
