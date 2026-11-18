// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_emergency_settings.h"

#include "ayu/features/emergency_actions/emergency_execution_capsule.h"
#include "ayu/features/profile_sets/profile_account_storage.h"
#include "ayu/features/profile_sets/profile_emergency_bundle.h"
#include "crl/crl_async.h"
#include "crl/crl_on_main.h"
#include "mtproto/mtproto_config.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <set>

namespace Ayu::ProfileSets {
namespace {

namespace EA = EmergencyActions;
using Result = Window::EmergencyRulesResult;

void Wipe(QByteArray &data) {
	OPENSSL_cleanse(data.data(), size_t(data.size()));
	data.clear();
}

void Wipe(DerivedCredential &credential) {
	Wipe(credential.verifier);
	Wipe(credential.key);
}

auto BytesOf(const QByteArray &data) {
	return std::span<const uint8_t>{
		reinterpret_cast<const uint8_t*>(data.constData()), size_t(data.size()) };
}

auto ByteArrayOf(std::span<const uint8_t> bytes) {
	return QByteArray(reinterpret_cast<const char*>(bytes.data()), qsizetype(bytes.size()));
}

template <typename Id>
std::string Identifier(Id id) {
	return u"%1%2"_q.arg(qulonglong(id.high), 16, 16, QChar('0'))
		.arg(qulonglong(id.low), 16, 16, QChar('0')).toStdString();
}

EA::CredentialVerifier Verifier(const QByteArray &data) {
	auto result = EA::CredentialVerifier{};
	if (size_t(data.size()) == result.size()) {
		std::memcpy(result.data(), data.constData(), result.size());
	}
	return result;
}

struct MasterAccess final {
	~MasterAccess() {
		Wipe(credential);
		for (auto &account : admin.accounts) Wipe(account.key);
	}
	CommittedMigration committed;
	ProfileVault vault;
	DerivedCredential credential;
	AdminVaultAccess admin;
	std::vector<EA::NamedEmergencyRule> rules;
};

std::unique_ptr<MasterAccess> OpenMaster(
		const MigrationController &workspace,
		const QByteArray &expected,
		QString &passcode,
		Result &error) {
	const auto wipePasscode = gsl::finally([&] { passcode.fill(QChar(0)); });
	error = Result::Unavailable;
	auto committed = workspace.LoadCommitted();
	if (!committed || workspace.isIsolatedFixture() || !committed->legacyRetirement.isEmpty()) {
		return nullptr;
	} else if (committed->transactionId != expected) {
		error = Result::Stale;
		return nullptr;
	}
	auto vault = ParseProfileVault(committed->profileVault);
	if (!vault || vault->version != kProfileVaultVersion) {
		return nullptr;
	}
	auto access = std::make_unique<MasterAccess>();
	access->committed = std::move(*committed);
	access->vault = std::move(*vault);
	access->credential = details::DeriveProfileVaultCredentialOnWorker(
		access->vault.salt, access->vault.kdf, passcode);
	if (!access->credential.valid()
		|| access->credential.verifier != access->vault.adminVerifier) {
		error = Result::WrongMaster;
		return nullptr;
	}
	auto opened = OpenProfileVault(access->vault, access->credential);
	const auto admin = std::get_if<AdminVaultAccess>(&opened);
	if (!admin) {
		return nullptr;
	}
	access->admin = std::move(*admin);
	if (!access->committed.emergencyRules.isEmpty()) {
		const auto bundle = ReadProfileEmergencyBundle(access->committed);
		auto rules = bundle ? EA::OpenEmergencyRulesForMaster(
			bundle->authority, BytesOf(bundle->rules), BytesOf(access->credential.key)) : std::nullopt;
		if (!rules) {
			return nullptr;
		}
		access->rules = std::move(*rules);
	}
	return access;
}

struct VerifiedAccount final {
	const AccountKey *key = nullptr;
	const AccountVaultLocator *locator = nullptr;
	EA::EmergencyScopedRemoteIdentity identity;
	bool canEndOtherSessions = false;
};

struct InstallationInventory final {
	EA::LiveInstallation live;
	std::map<EA::AccountId, VerifiedAccount> accounts;
};

std::optional<InstallationInventory> ReadInstallationInventory(
		const MigrationController &workspace,
		const MasterAccess &master) {
	const auto root = workspace.accountStorageRoot();
	auto result = InstallationInventory();
	result.live.id = EA::InstallationId(master.vault.id.toHex().toStdString());
	auto locators = std::map<AccountId, const AccountVaultLocator*>();
	for (const auto &locator : master.admin.locators) locators.emplace(locator.id, &locator);
	for (const auto &key : master.admin.accounts) {
		const auto locator = locators.find(key.id);
		if (locator == end(locators)) {
			return std::nullopt;
		}
		const auto paths = Storage::ScopedAccountPaths(root, AccountVaultDataName(*locator->second));
		const auto localKey = ProfileAccountStorageKey(key);
		auto config = std::unique_ptr<MTP::Config>();
		const auto identity = paths && localKey
			? Storage::ValidateScopedAccountForStartup(*paths, localKey, &config)
			: std::nullopt;
		if (!identity) {
			return std::nullopt;
		}
		const auto id = EA::AccountId(Identifier(key.id));
		const auto current = EA::SessionId("current");
		result.live.accounts.push_back({ id, current, { current } });
		result.accounts.emplace(id, VerifiedAccount{
			.key = &key,
			.locator = locator->second,
			.identity = {
				.userId = identity->userId.bare,
				.environment = identity->environment == MTP::Environment::Test
					? EA::EmergencyScopedEnvironment::Test : EA::EmergencyScopedEnvironment::Production,
			},
			.canEndOtherSessions = bool(config),
		});
	}
	for (const auto &set : master.admin.metadata.sets) {
		auto profile = EA::LiveProfile{ .id = EA::ProfileId(Identifier(set.id)) };
		for (const auto account : set.accounts) {
			profile.accountIds.emplace_back(Identifier(account));
		}
		result.live.profiles.push_back(std::move(profile));
	}
	return result;
}

std::optional<Window::EmergencyRulesSnapshot> LoadSettings(
		const MigrationController &workspace,
		const QByteArray &expected,
		QString &passcode,
		Result &error) {
	auto access = OpenMaster(workspace, expected, passcode, error);
	const auto inventory = access ? ReadInstallationInventory(workspace, *access) : std::nullopt;
	if (!inventory) {
		return std::nullopt;
	}
	auto result = Window::EmergencyRulesSnapshot{
		.transactionId = expected,
		.canSave = true,
		.canResetSelected = !inventory->accounts.empty(),
		.canResetAll = !inventory->accounts.empty(),
		.entries = std::move(access->rules),
	};
	for (const auto &[id, account] : inventory->accounts) {
		result.accounts.push_back({
			.id = id,
			.label = u"Account %1"_q.arg(qulonglong(account.identity.userId)),
			.canEndOtherSessions = account.canEndOtherSessions,
		});
	}
	for (auto i = size_t(0); i != access->admin.metadata.sets.size(); ++i) {
		const auto &set = access->admin.metadata.sets[i];
		const auto &profile = inventory->live.profiles[i];
		result.safeSets.push_back({ profile.id, set.name, profile.accountIds });
	}
	error = Result::Success;
	return result;
}

EA::RuleConfiguration RuleConfiguration(
		const MasterAccess &master,
		const EA::InstallationId &installation) {
	auto config = EA::RuleConfiguration{
		.activeInstallationId = installation,
		.masterVerifier = Verifier(master.admin.metadata.masterVerifier),
	};
	for (const auto &set : master.admin.metadata.sets) {
		config.normalCredentials.push_back({
			.id = EA::NormalPasscodeId(Identifier(set.id)),
			.verifier = Verifier(set.verifier),
		});
	}
	return config;
}

Result SaveSettings(
		const MigrationController &workspace,
		Window::EmergencyRulesSaveRequest &request) {
	if (!request.outcomesConfirmed || request.entries.size() > EA::kMaxSealedEmergencyRules) {
		return Result::CredentialsRejected;
	}
	auto error = Result::Unavailable;
	const auto access = OpenMaster(
		workspace, request.expectedTransactionId, request.masterPasscode, error);
	if (!access) {
		return error;
	}
	const auto inventory = ReadInstallationInventory(workspace, *access);
	if (!inventory) {
		return Result::Unavailable;
	}
	const auto next = MigrationController::NewTransactionId();
	if (next.isEmpty()) {
		return Result::Failed;
	}
	const auto generation = EA::EmergencyRuleGeneration{
		.installationId = inventory->live.id, .transactionId = next.toHex().toStdString() };
	auto config = RuleConfiguration(*access, generation.installationId);
	auto keys = std::vector<DerivedCredential>();
	keys.reserve(request.entries.size());
	const auto wipeKeys = gsl::finally([&] { for (auto &key : keys) Wipe(key); });
	auto inputs = std::vector<EA::EmergencyRuleSealInput>();
	auto capsules = std::map<QByteArray, QByteArray>();
	for (auto &entry : request.entries) {
		auto &rule = entry.rule;
		if (rule.action != EA::EmergencyAction::ResetAccountData
			|| rule.targetScope == EA::TargetScope::CurrentInstallation
			|| entry.name.trimmed().isEmpty()) {
			return Result::Unavailable;
		}
		const auto old = entry.existingId ? std::ranges::find(
			access->rules, *entry.existingId,
			[](const EA::NamedEmergencyRule &rule) { return rule.details.actionId; }) : end(access->rules);
		if (entry.existingId && old == end(access->rules)) {
			return Result::Stale;
		}
		const auto id = (old != end(access->rules)) ? old->details.actionId
			: EA::EmergencyActionId(MigrationController::NewTransactionId().toHex().toStdString());
		rule.id = (old != end(access->rules)) ? old->details.rule.id
			: EA::RuleId(MigrationController::NewTransactionId().toHex().toStdString());
		rule.installationId = generation.installationId;
		const auto operation = EA::OperationId(MigrationController::NewTransactionId().toHex().toStdString());
		keys.push_back(details::DeriveProfileVaultCredentialOnWorker(
			access->vault.salt, access->vault.kdf, entry.emergencyPasscode));
		const auto &credential = keys.back();
		if (!credential.valid()) {
			return Result::CredentialsRejected;
		}
		const auto verifier = Verifier(credential.verifier);
		config.emergencyRules.push_back({
			.id = id, .rule = rule, .verifier = verifier,
			.revision = (old != end(access->rules)) ? old->details.revision + 1 : 1,
		});
		if (EA::ValidateRuleConfiguration(config) != EA::RuleValidationError::None) {
			return Result::PasswordInUse;
		}
		const auto preview = EA::PreviewEmergencyRule(config, id, inventory->live, operation);
		if (!preview || !EA::ConfirmEmergencyRule(config, *preview, inventory->live, true)
			|| preview->plan.accounts.empty() || !preview->plan.selectedAccountIdsNotLive.empty()) {
			return Result::CredentialsRejected;
		}
		const auto &plan = preview->plan;
		auto targets = std::vector<EA::EmergencyExecutionAccount>();
		auto removed = std::vector<AccountId>();
		for (const auto &target : plan.accounts) {
			const auto account = inventory->accounts.find(target.accountId);
			if (account == end(inventory->accounts)
				|| target.remoteTarget == EA::RemoteSessionTargetKind::SelectedSessions
				|| (target.remoteTarget == EA::RemoteSessionTargetKind::AllOtherSessions
					&& !account->second.canEndOtherSessions)) {
				return Result::Unavailable;
			}
			const auto &grant = account->second;
			removed.push_back(grant.key->id);
			targets.push_back({
				.accountId = target.accountId,
				.locator = grant.locator->value.toHex().toStdString(),
				.scopedKey = BytesOf(grant.key->key),
				.remoteIdentity = grant.identity,
			});
		}
		const auto pruned = PruneProfileVaultAccounts(access->vault, access->credential, removed);
		if (!pruned) {
			return Result::Failed;
		}
		const auto vault = SerializeProfileVault(*pruned);
		auto remaining = access->admin.accounts;
		const auto wipeRemaining = gsl::finally([&] { for (auto &key : remaining) Wipe(key.key); });
		std::erase_if(remaining, [&](const AccountKey &key) { return std::ranges::contains(removed, key.id); });
		const auto keyring = SealAccountKeyring(remaining, access->credential.key);
		const auto successor = EA::EmergencyExecutionSuccessor{
			.transactionId = MigrationController::NewTransactionId().toHex().toStdString(),
			.sealedProfileVault = BytesOf(vault), .sealedAccountKeyring = BytesOf(keyring),
		};
		auto safe = std::optional<EA::EmergencyExecutionSafeDestination>();
		auto safeCredential = QByteArray();
		const auto wipeSafe = gsl::finally([&] { Wipe(safeCredential); });
		if (plan.safeDestination == EA::SafeDestinationKind::Profile) {
			auto derived = details::DeriveProfileVaultCredentialOnWorker(
				access->vault.salt, access->vault.kdf, entry.safeSetPasscode);
			const auto wipe = gsl::finally([&] { Wipe(derived); });
			auto opened = OpenProfileVault(*pruned, derived);
			const auto grant = std::get_if<SetVaultAccess>(&opened);
			if (!grant) {
				if (const auto admin = std::get_if<AdminVaultAccess>(&opened)) {
					for (auto &key : admin->accounts) Wipe(key.key);
				}
				return Result::CredentialsRejected;
			}
			const auto wipeGrant = gsl::finally([&] {
				for (auto &key : grant->accounts) Wipe(key.key);
				Wipe(grant->settingsKey);
			});
			if (EA::ProfileId(Identifier(grant->id)) != plan.safeProfileId) {
				return Result::CredentialsRejected;
			}
			safeCredential = derived.verifier + derived.key;
			safe = EA::EmergencyExecutionSafeDestination{
				.profileId = plan.safeProfileId, .sealedSetGrant = BytesOf(safeCredential) };
		} else if (rule.safeProfileId.valid()) {
			return Result::CredentialsRejected;
		}
		const auto capsule = EA::SealEmergencyExecutionCapsule(generation, {
			.actionId = id, .rule = rule, .operationId = operation,
			.revision = config.emergencyRules.back().revision,
		}, plan, targets, successor, safe, BytesOf(credential.key));
		if (!capsule || !capsules.emplace(ByteArrayOf(capsule->digest), ByteArrayOf(capsule->bytes)).second) {
			return Result::Failed;
		}
		inputs.push_back({
			.actionId = id, .name = entry.name.trimmed().toUtf8().toStdString(),
			.verifier = verifier, .key = BytesOf(credential.key),
			.executionCapsuleDigest = capsule->digest,
		});
	}
	auto artifacts = std::vector<MigrationInput>{
		{ MigrationArtifact::ProfileVault, access->committed.profileVault },
		{ MigrationArtifact::AccountKeyring, access->committed.accountKeyring },
	};
	auto bundle = QByteArray();
	if (!inputs.empty()) {
		const auto sealed = EA::SealEmergencyRules(
			generation, BytesOf(access->credential.key), config, inventory->live, inputs);
		bundle = sealed ? SerializeProfileEmergencyBundle(ByteArrayOf(sealed->bytes), capsules) : QByteArray();
		if (bundle.isEmpty()) {
			return Result::Failed;
		}
		artifacts.push_back({ MigrationArtifact::EmergencyRules, bundle });
	}
	auto migrationError = MigrationError::None;
	const auto published = workspace.ReplaceCommitted(request.expectedTransactionId, artifacts,
		[&](const CommittedMigration &candidate) {
			return candidate.transactionId == next
				&& candidate.profileVault == access->committed.profileVault
				&& candidate.accountKeyring == access->committed.accountKeyring
				&& candidate.emergencyRules == bundle;
		}, &migrationError, next);
	if (!published) {
		return (migrationError == MigrationError::StaleGeneration
			|| migrationError == MigrationError::PublicationUncertain) ? Result::Stale : Result::Failed;
	}
	return workspace.RetireInactiveGenerations(published->transactionId) ? Result::Success : Result::Stale;
}

} // namespace

void LoadProfileEmergencySettings(
		MigrationController workspace,
		QByteArray expectedTransactionId,
		QString masterPasscode,
		Window::EmergencyRulesLoadDone done) {
	crl::async([workspace = std::move(workspace), expected = std::move(expectedTransactionId),
		passcode = std::move(masterPasscode), done = std::move(done)]() mutable {
		auto result = Result::Unavailable;
		auto settings = LoadSettings(workspace, expected, passcode, result);
		crl::on_main([done = std::move(done), result, settings = std::move(settings)]() mutable {
			done(result, std::move(settings));
		});
	});
}

void SaveProfileEmergencySettings(
		MigrationController workspace,
		Window::EmergencyRulesSaveRequest request,
		Window::EmergencyRulesSaveDone done) {
	crl::async([workspace = std::move(workspace), request = std::move(request), done = std::move(done)]() mutable {
		const auto result = SaveSettings(workspace, request);
		request.masterPasscode.fill(QChar(0));
		for (auto &entry : request.entries) {
			entry.emergencyPasscode.fill(QChar(0));
			entry.safeSetPasscode.fill(QChar(0));
		}
		crl::on_main([done = std::move(done), result]() mutable { done(result); });
	});
}

} // namespace Ayu::ProfileSets
