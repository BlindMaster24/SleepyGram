// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/account_gate_table.h"

#include "base/openssl_help.h"
#include "storage/details/storage_hkdf.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QtEndian>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <algorithm>
#include <set>

namespace Ayu::ProfileSets {
namespace {

constexpr auto kTableMagic = QByteArrayView("SGGT1");
constexpr auto kHandleMagic = QByteArrayView("SGGH1");
constexpr auto kPermitMagic = QByteArrayView("SGGP1");
constexpr auto kReadContext = QByteArrayView("SleepyGram account gate read v1");
constexpr auto kRevokeContext = QByteArrayView("SleepyGram account gate revoke v1");
constexpr auto kWrapContext = QByteArrayView("SleepyGram account gate wrap v1");
constexpr auto kIdSize = qsizetype(16);
constexpr auto kSecretSize = qsizetype(32);
constexpr auto kCommitmentSize = qsizetype(32);
constexpr auto kBindingSize = 3 * kIdSize;
constexpr auto kTableHeaderSize = kTableMagic.size() + kIdSize + qsizetype(sizeof(quint16));
constexpr auto kRowHeaderSize = 1 + 2 * kIdSize + 2 * kCommitmentSize;
// The fixed payload size binds this format to one v1 keyring entry.
constexpr auto kKeyringMagic = QByteArrayView("SGAK");
constexpr auto kKeyringLengthOffset = kKeyringMagic.size() + 4 + 12;
constexpr auto kKeyringPayloadSize = 4 + 16 + kAccountKeySize + 16;
constexpr auto kSealedGateSize = kKeyringLengthOffset + 4 + kKeyringPayloadSize;
constexpr auto kMaximumTableSize = kTableHeaderSize
	+ qsizetype(kMaximumAccountGateRows) * (kRowHeaderSize + kSealedGateSize);
static_assert(AccountGateHandle::kSerializedSize
	== kHandleMagic.size() + kBindingSize + kSecretSize + kCommitmentSize);
static_assert(AccountGateRevocationPermit::kSerializedSize
	== kPermitMagic.size() + kBindingSize + kSecretSize);

void Wipe(QByteArray &secret) {
	if (!secret.isEmpty()) {
		OPENSSL_cleanse(secret.data(), size_t(secret.size()));
	}
}

bool ValidBytes(QByteArrayView bytes, qsizetype size) {
	return bytes.size() == size && std::ranges::any_of(bytes, [](char ch) {
		return ch != 0;
	});
}

bool Equal(QByteArrayView a, QByteArrayView b) {
	return a.size() == b.size()
		&& CRYPTO_memcmp(a.data(), b.data(), size_t(a.size())) == 0;
}

bool ValidSealedGate(QByteArrayView bytes) {
	return bytes.size() == kSealedGateSize
		&& bytes.startsWith(kKeyringMagic)
		&& qFromBigEndian<quint32>(bytes.data() + kKeyringMagic.size()) == 1
		&& qFromBigEndian<quint32>(bytes.data() + kKeyringLengthOffset) == kKeyringPayloadSize;
}

template <typename Int>
void AppendInt(QByteArray &bytes, Int value) {
	const auto encoded = qToBigEndian(value);
	bytes.append(reinterpret_cast<const char*>(&encoded), sizeof(encoded));
}

void AppendId(QByteArray &bytes, AccountId id) {
	AppendInt(bytes, id.high);
	AppendInt(bytes, id.low);
}

AccountId ReadId(const char *bytes) {
	return { qFromBigEndian<quint64>(bytes), qFromBigEndian<quint64>(bytes + 8) };
}

void AppendBinding(QByteArray &bytes, const AccountGateBinding &binding) {
	bytes.append(binding.installationId);
	AppendId(bytes, binding.id);
	bytes.append(binding.locator);
}

std::optional<AccountGateBinding> ReadBinding(QByteArrayView bytes) {
	const auto installation = bytes.first(kIdSize);
	const auto id = ReadId(bytes.data() + kIdSize);
	const auto locator = bytes.sliced(2 * kIdSize, kIdSize);
	if (!id || !ValidBytes(installation, kIdSize) || !ValidBytes(locator, kIdSize)) {
		return std::nullopt;
	}
	return AccountGateBinding{ installation.toByteArray(), id, locator.toByteArray() };
}

QByteArray Commitment(
		QByteArrayView context,
		const AccountGateBinding &binding,
		QByteArrayView secret) {
	auto encoded = QByteArray();
	encoded.reserve(kBindingSize);
	AppendBinding(encoded, binding);
	auto hash = QCryptographicHash(QCryptographicHash::Sha256);
	hash.addData(context);
	hash.addData(encoded);
	hash.addData(secret);
	return hash.result();
}

bool DeriveWrappingKey(
		const AccountGateBinding &binding,
		QByteArrayView revokeCommitment,
		QByteArrayView secret,
		QByteArray &output) {
	auto info = QByteArray();
	info.reserve(kWrapContext.size() + kBindingSize + kCommitmentSize);
	info.append(kWrapContext);
	AppendBinding(info, binding);
	info.append(revokeCommitment);
	return Storage::HkdfSha256(
		bytes::make_span(secret.data(), secret.size()),
		{},
		bytes::make_span(info.constData(), info.size()),
		bytes::make_span(output.data(), output.size()));
}

QByteArray RandomSecret() {
	auto result = QByteArray(kSecretSize, Qt::Uninitialized);
	if (RAND_bytes(reinterpret_cast<unsigned char*>(result.data()), int(result.size())) != 1
		|| !ValidBytes(result, kSecretSize)) {
		Wipe(result);
		return {};
	}
	return result;
}

} // namespace

AccountGateHandle::AccountGateHandle(
	AccountGateBinding binding,
	QByteArray secret,
	QByteArray revokeCommitment)
: _binding(std::move(binding))
, _secret(std::move(secret))
, _revokeCommitment(std::move(revokeCommitment)) {
}

AccountGateHandle::AccountGateHandle(AccountGateHandle &&other) noexcept = default;

AccountGateHandle::~AccountGateHandle() {
	Wipe(_secret);
}

const AccountGateBinding &AccountGateHandle::binding() const {
	return _binding;
}

bool AccountGateHandle::matches(const AccountGateRevocationPermit &permit) const {
	return _binding == permit._binding
		&& ValidBytes(_secret, kSecretSize)
		&& ValidBytes(permit._secret, kSecretSize)
		&& !Equal(_secret, permit._secret)
		&& Equal(_revokeCommitment, Commitment(kRevokeContext, _binding, permit._secret));
}

QByteArray AccountGateHandle::serialize() const {
	auto result = QByteArray();
	result.reserve(kSerializedSize);
	result.append(kHandleMagic);
	AppendBinding(result, _binding);
	result.append(_secret);
	result.append(_revokeCommitment);
	return result;
}

std::optional<AccountGateHandle> AccountGateHandle::Parse(QByteArrayView bytes) {
	if (bytes.size() != kSerializedSize || !bytes.startsWith(kHandleMagic)) {
		return std::nullopt;
	}
	auto binding = ReadBinding(bytes.sliced(kHandleMagic.size(), kBindingSize));
	const auto secret = bytes.sliced(kHandleMagic.size() + kBindingSize, kSecretSize);
	const auto commit = bytes.last(kCommitmentSize);
	if (!binding || !ValidBytes(secret, kSecretSize) || !ValidBytes(commit, kCommitmentSize)) {
		return std::nullopt;
	}
	return AccountGateHandle(std::move(*binding), secret.toByteArray(), commit.toByteArray());
}

AccountGateRevocationPermit::AccountGateRevocationPermit(
	AccountGateBinding binding,
	QByteArray secret)
: _binding(std::move(binding))
, _secret(std::move(secret)) {
}

AccountGateRevocationPermit::AccountGateRevocationPermit(
	AccountGateRevocationPermit &&other) noexcept = default;

AccountGateRevocationPermit::~AccountGateRevocationPermit() {
	Wipe(_secret);
}

const AccountGateBinding &AccountGateRevocationPermit::binding() const {
	return _binding;
}

QByteArray AccountGateRevocationPermit::serialize() const {
	auto result = QByteArray();
	result.reserve(kSerializedSize);
	result.append(kPermitMagic);
	AppendBinding(result, _binding);
	result.append(_secret);
	return result;
}

std::optional<AccountGateRevocationPermit> AccountGateRevocationPermit::Parse(
		QByteArrayView bytes) {
	if (bytes.size() != kSerializedSize || !bytes.startsWith(kPermitMagic)) {
		return std::nullopt;
	}
	auto binding = ReadBinding(bytes.sliced(kPermitMagic.size(), kBindingSize));
	const auto secret = bytes.last(kSecretSize);
	if (!binding || !ValidBytes(secret, kSecretSize)) {
		return std::nullopt;
	}
	return AccountGateRevocationPermit(std::move(*binding), secret.toByteArray());
}

AccountGateTable::AccountGateTable(QByteArray installationId)
: _installationId(std::move(installationId)) {
}

std::optional<AccountGateTable> AccountGateTable::Create(QByteArrayView installationId) {
	if (!ValidBytes(installationId, kIdSize)) {
		return std::nullopt;
	}
	return AccountGateTable(installationId.toByteArray());
}

const QByteArray &AccountGateTable::installationId() const {
	return _installationId;
}

bool AccountGateTable::coversActiveBindings(std::span<const AccountGateBinding> expected) const {
	const auto active = std::ranges::count_if(_rows, [](const auto &entry) {
		return !entry.second.revoked;
	});
	if (size_t(active) != expected.size()) {
		return false;
	}
	auto seen = std::set<AccountId>();
	return std::ranges::all_of(expected, [&](const auto &binding) {
		const auto row = _rows.find(binding.id);
		return binding.installationId == _installationId && row != end(_rows)
			&& !row->second.revoked && row->second.locator == binding.locator
			&& seen.insert(binding.id).second;
	});
}

size_t AccountGateTable::size() const {
	return _rows.size();
}

std::optional<CreatedAccountGate> CreateAccountGate(
		const AccountGateTable &table,
		const AccountKey &key,
		QByteArrayView locator) {
	if (!ValidBytes(table._installationId, kIdSize) || !key.id
		|| !ValidBytes(key.key, kAccountKeySize) || !ValidBytes(locator, kIdSize)
		|| table._rows.size() >= kMaximumAccountGateRows || table._rows.contains(key.id)
		|| std::ranges::any_of(table._rows, [&](const auto &entry) {
			return entry.second.locator == locator;
		})) {
		return std::nullopt;
	}
	auto binding = AccountGateBinding{ table._installationId, key.id, locator.toByteArray() };
	auto read = RandomSecret();
	auto revoke = RandomSecret();
	auto wrapping = QByteArray(kAccountKeyringWrappingKeySize, Qt::Uninitialized);
	const auto wipe = gsl::finally([&] { Wipe(read); Wipe(revoke); Wipe(wrapping); });
	if (read.isEmpty() || revoke.isEmpty() || Equal(read, revoke)) {
		return std::nullopt;
	}
	auto readCommitment = Commitment(kReadContext, binding, read);
	auto revokeCommitment = Commitment(kRevokeContext, binding, revoke);
	if (!DeriveWrappingKey(binding, revokeCommitment, read, wrapping)) {
		return std::nullopt;
	}
	auto sealed = SealAccountKeyring({ key }, wrapping);
	if (!ValidSealedGate(sealed)) {
		return std::nullopt;
	}
	auto result = table;
	result._rows.emplace(key.id, AccountGateTable::Row{
		.locator = binding.locator,
		.readCommitment = std::move(readCommitment),
		.revokeCommitment = revokeCommitment,
		.payload = std::move(sealed),
	});
	return CreatedAccountGate{
		.table = std::move(result),
		.handle = AccountGateHandle(binding, std::move(read), std::move(revokeCommitment)),
		.permit = AccountGateRevocationPermit(std::move(binding), std::move(revoke)),
	};
}

AccountGateStatus InspectAccountGate(
		const AccountGateTable &table,
		const AccountGateHandle &handle) {
	const auto &binding = handle._binding;
	const auto row = table._rows.find(binding.id);
	if (binding.installationId != table._installationId || row == end(table._rows)
		|| row->second.locator != binding.locator || !ValidBytes(handle._secret, kSecretSize)
		|| !Equal(row->second.revokeCommitment, handle._revokeCommitment)
		|| !Equal(row->second.readCommitment, Commitment(kReadContext, binding, handle._secret))) {
		return AccountGateStatus::Unavailable;
	}
	const auto &entry = row->second;
	if (!entry.revoked) {
		return AccountGateStatus::Active;
	}
	return Equal(entry.revokeCommitment, Commitment(kRevokeContext, binding, entry.payload))
		? AccountGateStatus::Revoked
		: AccountGateStatus::Unavailable;
}

AccountGateOpenResult OpenAccountGate(
		const AccountGateTable &table,
		const AccountGateHandle &handle) {
	const auto status = InspectAccountGate(table, handle);
	if (status == AccountGateStatus::Unavailable) {
		return AccountGateUnavailable();
	} else if (status == AccountGateStatus::Revoked) {
		return AccountGateRevoked();
	}
	const auto &binding = handle._binding;
	const auto &entry = table._rows.at(binding.id);
	auto wrapping = QByteArray(kAccountKeyringWrappingKeySize, Qt::Uninitialized);
	const auto wipeWrapping = gsl::finally([&] { Wipe(wrapping); });
	if (!DeriveWrappingKey(binding, entry.revokeCommitment, handle._secret, wrapping)) {
		return AccountGateUnavailable();
	}
	auto keys = OpenAccountKeyring(entry.payload, wrapping);
	if (!keys) {
		return AccountGateUnavailable();
	}
	const auto wipeKeys = gsl::finally([&] {
		for (auto &key : *keys) {
			Wipe(key.key);
		}
	});
	if (keys->size() != 1 || keys->front().id != binding.id) {
		return AccountGateUnavailable();
	}
	return std::move(keys->front());
}

std::optional<AccountGateTable> RevokeAccountGates(
		const AccountGateTable &table,
		std::span<const AccountGateRevocationPermit> permits) {
	if (permits.empty() || permits.size() > table._rows.size()) {
		return std::nullopt;
	}
	auto seen = std::set<AccountId>();
	for (const auto &permit : permits) {
		const auto &binding = permit._binding;
		const auto row = table._rows.find(binding.id);
		if (binding.installationId != table._installationId || row == end(table._rows)
			|| !seen.insert(binding.id).second || row->second.locator != binding.locator
			|| !ValidBytes(permit._secret, kSecretSize)
			|| !Equal(row->second.revokeCommitment, Commitment(kRevokeContext, binding, permit._secret))
			|| (row->second.revoked && !Equal(row->second.payload, permit._secret))) {
			return std::nullopt;
		}
	}
	auto result = table;
	for (const auto &permit : permits) {
		auto &row = result._rows.at(permit._binding.id);
		row.revoked = true;
		row.payload = permit._secret;
	}
	return result;
}

std::optional<AccountGateTable> ParseAccountGateTable(
		QByteArrayView bytes,
		QByteArrayView expectedInstallationId) {
	if (!ValidBytes(expectedInstallationId, kIdSize)
		|| bytes.size() < kTableHeaderSize || bytes.size() > kMaximumTableSize
		|| !bytes.startsWith(kTableMagic)
		|| bytes.sliced(kTableMagic.size(), kIdSize) != expectedInstallationId) {
		return std::nullopt;
	}
	const auto count = qFromBigEndian<quint16>(bytes.data() + kTableMagic.size() + kIdSize);
	if (count > kMaximumAccountGateRows) {
		return std::nullopt;
	}
	auto table = AccountGateTable(expectedInstallationId.toByteArray());
	bytes = bytes.sliced(kTableHeaderSize);
	auto previous = AccountId();
	auto locators = std::set<QByteArray>();
	for (auto i = 0; i != count; ++i) {
		if (bytes.size() < kRowHeaderSize || uchar(bytes[0]) > 1) {
			return std::nullopt;
		}
		const auto revoked = (bytes[0] != 0);
		const auto size = revoked ? kSecretSize : kSealedGateSize;
		if (bytes.size() < kRowHeaderSize + size) {
			return std::nullopt;
		}
		const auto id = ReadId(bytes.data() + 1);
		auto locator = bytes.sliced(1 + kIdSize, kIdSize).toByteArray();
		const auto read = bytes.sliced(1 + 2 * kIdSize, kCommitmentSize);
		const auto revoke = bytes.sliced(1 + 2 * kIdSize + kCommitmentSize, kCommitmentSize);
		const auto payload = bytes.sliced(kRowHeaderSize, size);
		const auto binding = AccountGateBinding{ table._installationId, id, locator };
		const auto validPayload = revoked
			? (ValidBytes(payload, kSecretSize)
				&& Equal(revoke, Commitment(kRevokeContext, binding, payload)))
			: ValidSealedGate(payload);
		if (id <= previous
			|| !ValidBytes(locator, kIdSize)
			|| !locators.insert(locator).second
			|| !ValidBytes(read, kCommitmentSize)
			|| !ValidBytes(revoke, kCommitmentSize)
			|| !validPayload) {
			return std::nullopt;
		}
		table._rows.emplace(id, AccountGateTable::Row{
			.locator = std::move(locator),
			.readCommitment = read.toByteArray(),
			.revokeCommitment = revoke.toByteArray(),
			.payload = payload.toByteArray(),
			.revoked = revoked,
		});
		previous = id;
		bytes = bytes.sliced(kRowHeaderSize + size);
	}
	return bytes.isEmpty() ? std::optional(std::move(table)) : std::nullopt;
}

QByteArray SerializeAccountGateTable(const AccountGateTable &table) {
	if (!ValidBytes(table._installationId, kIdSize)) {
		return {};
	}
	auto result = QByteArray();
	result.reserve(kTableHeaderSize
		+ qsizetype(table._rows.size()) * (kRowHeaderSize + kSealedGateSize));
	result.append(kTableMagic);
	result.append(table._installationId);
	AppendInt(result, quint16(table._rows.size()));
	for (const auto &[id, row] : table._rows) {
		result.append(char(row.revoked));
		AppendId(result, id);
		result.append(row.locator);
		result.append(row.readCommitment);
		result.append(row.revokeCommitment);
		result.append(row.payload);
	}
	return result;
}

} // namespace Ayu::ProfileSets
