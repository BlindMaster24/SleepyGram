// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/features/profile_sets/account_keyring.h"

#include <map>
#include <span>
#include <variant>

namespace Ayu::ProfileSets {

inline constexpr auto kMaximumAccountGateRows = size_t(4096);

struct AccountGateBinding final {
	QByteArray installationId;
	AccountId id;
	QByteArray locator;

	friend bool operator==(
		const AccountGateBinding&,
		const AccountGateBinding&) = default;
};

struct AccountGateUnavailable final {};
struct AccountGateRevoked final {};

using AccountGateOpenResult = std::variant<
	AccountGateUnavailable,
	AccountGateRevoked,
	AccountKey>;

enum class AccountGateStatus : uchar {
	Unavailable,
	Active,
	Revoked,
};

class AccountGateTable;
class AccountGateRevocationPermit;
struct CreatedAccountGate;

class AccountGateHandle final {
public:
	static constexpr auto kSerializedSize = qsizetype(117);

	AccountGateHandle(AccountGateHandle &&other) noexcept;
	~AccountGateHandle();

	[[nodiscard]] const AccountGateBinding &binding() const;
	[[nodiscard]] bool matches(const AccountGateRevocationPermit &permit) const;
	[[nodiscard]] QByteArray serialize() const;
	[[nodiscard]] static std::optional<AccountGateHandle> Parse(QByteArrayView bytes);

private:
	friend std::optional<CreatedAccountGate> CreateAccountGate(
		const AccountGateTable&, const AccountKey&, QByteArrayView);
	friend AccountGateOpenResult OpenAccountGate(
		const AccountGateTable&, const AccountGateHandle&);
	friend AccountGateStatus InspectAccountGate(
		const AccountGateTable&, const AccountGateHandle&);

	AccountGateHandle(
		AccountGateBinding binding,
		QByteArray secret,
		QByteArray revokeCommitment);

	AccountGateBinding _binding;
	QByteArray _secret;
	QByteArray _revokeCommitment;

};

class AccountGateRevocationPermit final {
public:
	static constexpr auto kSerializedSize = qsizetype(85);

	AccountGateRevocationPermit(AccountGateRevocationPermit &&other) noexcept;
	~AccountGateRevocationPermit();

	[[nodiscard]] const AccountGateBinding &binding() const;
	[[nodiscard]] QByteArray serialize() const;
	[[nodiscard]] static std::optional<AccountGateRevocationPermit> Parse(
		QByteArrayView bytes);

private:
	friend class AccountGateHandle;
	friend std::optional<CreatedAccountGate> CreateAccountGate(
		const AccountGateTable&, const AccountKey&, QByteArrayView);
	friend std::optional<AccountGateTable> RevokeAccountGates(
		const AccountGateTable&, std::span<const AccountGateRevocationPermit>);

	AccountGateRevocationPermit(AccountGateBinding binding, QByteArray secret);

	AccountGateBinding _binding;
	QByteArray _secret;

};

class AccountGateTable final {
public:
	[[nodiscard]] static std::optional<AccountGateTable> Create(
		QByteArrayView installationId);
	[[nodiscard]] const QByteArray &installationId() const;
	[[nodiscard]] size_t size() const;
	[[nodiscard]] bool coversActiveBindings(std::span<const AccountGateBinding> expected) const;

private:
	friend std::optional<CreatedAccountGate> CreateAccountGate(
		const AccountGateTable&, const AccountKey&, QByteArrayView);
	friend AccountGateOpenResult OpenAccountGate(
		const AccountGateTable&, const AccountGateHandle&);
	friend AccountGateStatus InspectAccountGate(
		const AccountGateTable&, const AccountGateHandle&);
	friend std::optional<AccountGateTable> RevokeAccountGates(
		const AccountGateTable&, std::span<const AccountGateRevocationPermit>);
	friend std::optional<AccountGateTable> ParseAccountGateTable(
		QByteArrayView, QByteArrayView);
	friend QByteArray SerializeAccountGateTable(const AccountGateTable&);

	struct Row final {
		QByteArray locator;
		QByteArray readCommitment;
		QByteArray revokeCommitment;
		QByteArray payload;
		bool revoked = false;
	};

	explicit AccountGateTable(QByteArray installationId);

	QByteArray _installationId;
	std::map<AccountId, Row> _rows;

};

struct CreatedAccountGate final {
	AccountGateTable table;
	AccountGateHandle handle;
	AccountGateRevocationPermit permit;
};

[[nodiscard]] std::optional<CreatedAccountGate> CreateAccountGate(
	const AccountGateTable &table,
	const AccountKey &key,
	QByteArrayView locator);
[[nodiscard]] AccountGateOpenResult OpenAccountGate(
	const AccountGateTable &table,
	const AccountGateHandle &handle);
[[nodiscard]] AccountGateStatus InspectAccountGate(
	const AccountGateTable &table,
	const AccountGateHandle &handle);
[[nodiscard]] std::optional<AccountGateTable> RevokeAccountGates(
	const AccountGateTable &table,
	std::span<const AccountGateRevocationPermit> permits);

// Parse only after authenticating the table against the committed generation.
[[nodiscard]] std::optional<AccountGateTable> ParseAccountGateTable(
	QByteArrayView bytes,
	QByteArrayView expectedInstallationId);
[[nodiscard]] QByteArray SerializeAccountGateTable(const AccountGateTable &table);

} // namespace Ayu::ProfileSets
