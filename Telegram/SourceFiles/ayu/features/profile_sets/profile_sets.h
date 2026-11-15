// This is the source code of AyuGram for Desktop.
#pragma once

#include "base/basic_types.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QStringView>
#include <QtCore/QtGlobal>

#include <optional>
#include <variant>
#include <vector>

namespace Ayu::ProfileSets {

inline constexpr auto kMetadataVersion = quint32(1);
inline constexpr auto kVerifierSize = 32;
inline constexpr auto kVerifierSaltSize = 16;

struct KdfParameters final {
	quint32 kind = 0;
	quint32 memory = 0;
	quint32 time = 0;
	quint32 parallel = 0;

	friend inline auto operator<=>(KdfParameters, KdfParameters) = default;
};

struct AccountId final {
	quint64 high = 0;
	quint64 low = 0;

	explicit operator bool() const noexcept {
		return high || low;
	}

	friend inline auto operator<=>(AccountId, AccountId) = default;
};

struct SetId final {
	quint64 high = 0;
	quint64 low = 0;

	explicit operator bool() const noexcept {
		return high || low;
	}

	friend inline auto operator<=>(SetId, SetId) = default;
};

struct AccountSet final {
	SetId id;
	QString name;
	QByteArray verifier;
	std::vector<AccountId> accounts;

	friend inline bool operator==(const AccountSet&, const AccountSet&) = default;
};

struct Metadata final {
	quint32 version = kMetadataVersion;
	QByteArray verifierSalt;
	KdfParameters verifierKdf;
	QByteArray masterVerifier;
	std::vector<AccountSet> sets;

	friend inline bool operator==(const Metadata&, const Metadata&) = default;
};

enum class ValidationError : uchar {
	None,
	UnsupportedVersion,
	InvalidMasterVerifier,
	InvalidVerifierSalt,
	InvalidKdf,
	InvalidSetId,
	DuplicateSetId,
	InvalidSetName,
	InvalidSetVerifier,
	DuplicateVerifier,
	InvalidAccountId,
	DuplicateMembership,
	TooLarge,
	Malformed,
};

struct WrongPassword final {
	friend inline auto operator<=>(WrongPassword, WrongPassword) = default;
};

struct MasterAccess final {
	friend inline auto operator<=>(MasterAccess, MasterAccess) = default;
};

struct SetAccess final {
	SetId id;
	friend inline auto operator<=>(SetAccess, SetAccess) = default;
};

using PasswordRoute = std::variant<WrongPassword, MasterAccess, SetAccess>;

[[nodiscard]] AccountId NewAccountId();
[[nodiscard]] SetId NewSetId();
[[nodiscard]] QByteArray NewVerifierSalt();

[[nodiscard]] ValidationError Validate(const Metadata &metadata);
// This plaintext payload must be wrapped before it is written to storage.
[[nodiscard]] QByteArray SerializeMetadataPayload(const Metadata &metadata);
[[nodiscard]] std::optional<Metadata> ParseMetadataPayload(
	const QByteArray &payload,
	ValidationError *error = nullptr);

[[nodiscard]] PasswordRoute RoutePasswordVerifier(
	const Metadata &metadata,
	const QByteArray &verifier);
void DerivePasswordVerifier(
	const Metadata &metadata,
	QString password,
	Fn<void(QByteArray)> done);
void RoutePassword(
	Metadata metadata,
	QString password,
	Fn<void(PasswordRoute)> done);

} // namespace Ayu::ProfileSets
