#include "ayu/features/profile_sets/profile_sets.h"

#include "base/basic_types.h"
#include "base/random.h"

#include <openssl/crypto.h>

#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>

#include <algorithm>
#include <array>
#include <limits>
#include <set>

namespace Ayu::ProfileSets {
namespace {

constexpr auto kMaximumPayloadSize = 64 * 1024 * 1024;
constexpr auto kMaximumNameSize = 256;
constexpr auto kPasscodeKdfArgon2id = quint32(1);
constexpr auto kPasscodeKdfScrypt = quint32(2);
constexpr auto kMaximumArgonMemoryKiB = quint32(65'536);
constexpr auto kMaximumArgonTime = quint32(8);
constexpr auto kMaximumArgonLanes = quint32(1);
constexpr auto kMaximumScryptN = quint32(131'072);
constexpr auto kMaximumScryptR = quint32(8);
constexpr auto kMaximumScryptP = quint32(1);

QString IdText(quint64 high, quint64 low) {
	return QString::number(high, 16).rightJustified(16, u'0')
		+ QString::number(low, 16).rightJustified(16, u'0');
}

bool ParseId(QStringView text, quint64 *high, quint64 *low) {
	if (text.size() != 32) {
		return false;
	}
	bool highOk = false;
	bool lowOk = false;
	*high = text.first(16).toULongLong(&highOk, 16);
	*low = text.last(16).toULongLong(&lowOk, 16);
	return highOk && lowOk && (*high || *low);
}

QString VerifierText(const QByteArray &verifier) {
	return QString::fromLatin1(verifier.toHex());
}

QByteArray ParseVerifier(QStringView text) {
	if (text.size() != 2 * kVerifierSize) {
		return QByteArray();
	}
	const auto bytes = QByteArray::fromHex(text.toLatin1());
	return (bytes.size() == kVerifierSize)
		&& (bytes.toHex() == text.toLatin1().toLower())
		? bytes
		: QByteArray();
}

bool SameVerifier(const QByteArray &a, const QByteArray &b) {
	return (a.size() == kVerifierSize)
		&& (b.size() == kVerifierSize)
		&& !CRYPTO_memcmp(a.constData(), b.constData(), kVerifierSize);
}

void SetError(ValidationError *error, ValidationError value) {
	if (error) {
		*error = value;
	}
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

AccountId NewAccountId() {
	auto bytes = std::array<uchar, 16>();
	base::RandomFill(bytes.data(), bytes.size());
	auto result = AccountId();
	for (auto i = 0; i != 8; ++i) {
		result.high = (result.high << 8) | bytes[i];
		result.low = (result.low << 8) | bytes[i + 8];
	}
	return result ? result : AccountId{ 0, 1 };
}

SetId NewSetId() {
	auto bytes = std::array<uchar, 16>();
	base::RandomFill(bytes.data(), bytes.size());
	auto result = SetId();
	for (auto i = 0; i != 8; ++i) {
		result.high = (result.high << 8) | bytes[i];
		result.low = (result.low << 8) | bytes[i + 8];
	}
	return result ? result : SetId{ 0, 1 };
}

QByteArray NewVerifierSalt() {
	auto result = QByteArray(kVerifierSaltSize, Qt::Uninitialized);
	base::RandomFill(result.data(), result.size());
	return result;
}

ValidationError Validate(const Metadata &metadata) {
	if (metadata.version != kMetadataVersion) {
		return ValidationError::UnsupportedVersion;
	} else if (metadata.masterVerifier.size() != kVerifierSize) {
		return ValidationError::InvalidMasterVerifier;
	} else if (metadata.verifierSalt.size() < 8
		|| metadata.verifierSalt.size() > 64) {
		return ValidationError::InvalidVerifierSalt;
	} else if (!metadata.verifierKdf.time || !metadata.verifierKdf.parallel
		|| (metadata.verifierKdf.kind == kPasscodeKdfArgon2id
			&& (metadata.verifierKdf.memory
				< 8 * uint64(metadata.verifierKdf.parallel)
				|| metadata.verifierKdf.memory > kMaximumArgonMemoryKiB
				|| metadata.verifierKdf.time > kMaximumArgonTime
				|| metadata.verifierKdf.parallel > kMaximumArgonLanes))
		|| (metadata.verifierKdf.kind == kPasscodeKdfScrypt
			&& (metadata.verifierKdf.memory < 2
				|| (metadata.verifierKdf.memory
					& (metadata.verifierKdf.memory - 1))
				|| metadata.verifierKdf.memory > kMaximumScryptN
				|| metadata.verifierKdf.time > kMaximumScryptR
				|| metadata.verifierKdf.parallel > kMaximumScryptP))
		|| (metadata.verifierKdf.kind != kPasscodeKdfArgon2id
			&& metadata.verifierKdf.kind != kPasscodeKdfScrypt)) {
		return ValidationError::InvalidKdf;
	}
	auto setIds = std::set<SetId>();
	auto verifiers = std::set<QByteArray>{ metadata.masterVerifier };
	auto estimatedSize = qsizetype(512);
	for (const auto &set : metadata.sets) {
		if (!set.id) {
			return ValidationError::InvalidSetId;
		} else if (!setIds.insert(set.id).second) {
			return ValidationError::DuplicateSetId;
		} else if (set.name.trimmed().isEmpty()
			|| set.name.size() > kMaximumNameSize
			|| std::any_of(set.name.cbegin(), set.name.cend(), [](QChar ch) {
				return ch.isNull() || ch.category() == QChar::Other_Control;
			})) {
			return ValidationError::InvalidSetName;
		} else if (set.verifier.size() != kVerifierSize) {
			return ValidationError::InvalidSetVerifier;
		}
		if (!verifiers.insert(set.verifier).second) {
			return ValidationError::DuplicateVerifier;
		}
		auto accounts = std::set<AccountId>();
		for (const auto account : set.accounts) {
			if (!account) {
				return ValidationError::InvalidAccountId;
			} else if (!accounts.insert(account).second) {
				return ValidationError::DuplicateMembership;
			}
		}
		const auto nameSize = set.name.toUtf8().size();
		if (set.accounts.size() > (kMaximumPayloadSize - estimatedSize) / 32) {
			return ValidationError::TooLarge;
		}
		estimatedSize += 256 + nameSize + (set.accounts.size() * 32);
		if (estimatedSize > kMaximumPayloadSize) {
			return ValidationError::TooLarge;
		}
	}
	return ValidationError::None;
}

QByteArray SerializeMetadataPayload(const Metadata &metadata) {
	if (Validate(metadata) != ValidationError::None) {
		return QByteArray();
	}
	auto sets = QJsonArray();
	for (const auto &set : metadata.sets) {
		auto accounts = QJsonArray();
		for (const auto account : set.accounts) {
			accounts.push_back(IdText(account.high, account.low));
		}
		sets.push_back(QJsonObject{
			{ u"id"_q, IdText(set.id.high, set.id.low) },
			{ u"name"_q, set.name },
			{ u"verifier"_q, VerifierText(set.verifier) },
			{ u"accounts"_q, accounts },
		});
	}
	const auto object = QJsonObject{
		{ u"version"_q, int(metadata.version) },
		{ u"verifier_salt"_q, QString::fromLatin1(metadata.verifierSalt.toHex()) },
		{ u"kdf_kind"_q, int(metadata.verifierKdf.kind) },
		{ u"kdf_memory"_q, int(metadata.verifierKdf.memory) },
		{ u"kdf_time"_q, int(metadata.verifierKdf.time) },
		{ u"kdf_parallel"_q, int(metadata.verifierKdf.parallel) },
		{ u"master_verifier"_q, VerifierText(metadata.masterVerifier) },
		{ u"sets"_q, sets },
	};
	const auto result = QJsonDocument(object).toJson(QJsonDocument::Compact);
	return result.size() <= kMaximumPayloadSize ? result : QByteArray();
}

std::optional<Metadata> ParseMetadataPayload(
		const QByteArray &payload,
		ValidationError *error) {
	SetError(error, ValidationError::Malformed);
	if (payload.isEmpty() || payload.size() > kMaximumPayloadSize) {
		SetError(error, ValidationError::TooLarge);
		return std::nullopt;
	}
	QJsonParseError parseError;
	const auto document = QJsonDocument::fromJson(payload, &parseError);
	if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
		return std::nullopt;
	}
	const auto object = document.object();
	const auto version = object.value(u"version"_q);
	const auto saltText = object.value(u"verifier_salt"_q).toString();
	const auto salt = QByteArray::fromHex(saltText.toLatin1());
	const auto masterVerifier = ParseVerifier(
		object.value(u"master_verifier"_q).toString());
	const auto setsValue = object.value(u"sets"_q);
	const auto kdfKind = object.value(u"kdf_kind"_q);
	const auto kdfMemory = object.value(u"kdf_memory"_q);
	const auto kdfTime = object.value(u"kdf_time"_q);
	const auto kdfParallel = object.value(u"kdf_parallel"_q);
	if (!version.isDouble()
		|| !masterVerifier.size()
		|| salt.size() < 8
		|| salt.size() > 64
		|| salt.toHex() != saltText.toLatin1().toLower()
		|| !kdfKind.isDouble()
		|| !kdfMemory.isDouble()
		|| !kdfTime.isDouble()
		|| !kdfParallel.isDouble()
		|| !setsValue.isArray()) {
		return std::nullopt;
	}
	auto result = Metadata();
	const auto versionInt = version.toInt(-1);
	if (versionInt < 0 || version.toDouble() != versionInt) {
		return std::nullopt;
	}
	result.version = quint32(versionInt);
	result.verifierSalt = salt;
	if (!ReadUint32(kdfKind, &result.verifierKdf.kind)
		|| !ReadUint32(kdfMemory, &result.verifierKdf.memory)
		|| !ReadUint32(kdfTime, &result.verifierKdf.time)
		|| !ReadUint32(kdfParallel, &result.verifierKdf.parallel)) {
		return std::nullopt;
	}
	result.masterVerifier = masterVerifier;
	for (const auto &value : setsValue.toArray()) {
		if (!value.isObject()) {
			return std::nullopt;
		}
		const auto setObject = value.toObject();
		const auto idText = setObject.value(u"id"_q).toString();
		const auto verifier = ParseVerifier(
			setObject.value(u"verifier"_q).toString());
		const auto accountValues = setObject.value(u"accounts"_q);
		if (!accountValues.isArray() || !verifier.size()) {
			return std::nullopt;
		}
		auto set = AccountSet();
		if (!ParseId(idText, &set.id.high, &set.id.low)) {
			return std::nullopt;
		}
		set.name = setObject.value(u"name"_q).toString();
		set.verifier = verifier;
		for (const auto &accountValue : accountValues.toArray()) {
			if (!accountValue.isString()) {
				return std::nullopt;
			}
			auto account = AccountId();
			if (!ParseId(accountValue.toString(), &account.high, &account.low)) {
				return std::nullopt;
			}
			set.accounts.push_back(account);
		}
		result.sets.push_back(std::move(set));
	}
	const auto validation = Validate(result);
	SetError(error, validation);
	return (validation == ValidationError::None)
		? std::optional<Metadata>(std::move(result))
		: std::nullopt;
}

PasswordRoute RoutePasswordVerifier(
		const Metadata &metadata,
		const QByteArray &verifier) {
	if (Validate(metadata) != ValidationError::None
		|| verifier.size() != kVerifierSize) {
		return WrongPassword();
	} else if (SameVerifier(metadata.masterVerifier, verifier)) {
		return MasterAccess();
	}
	for (const auto &set : metadata.sets) {
		if (SameVerifier(set.verifier, verifier)) {
			return SetAccess{ set.id };
		}
	}
	return WrongPassword();
}

} // namespace Ayu::ProfileSets
