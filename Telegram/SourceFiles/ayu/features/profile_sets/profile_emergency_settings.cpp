// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_emergency_settings.h"

#include "ayu/features/emergency_actions/emergency_execution_capsule.h"
#include "ayu/features/emergency_actions/mtproto_session_effect_transport.h"
#include "ayu/features/profile_sets/profile_account_storage.h"
#include "ayu/features/profile_sets/profile_emergency_bundle.h"
#include "ayu/features/profile_sets/profile_installation_removal.h"
#include "ayu/features/profile_sets/profile_revocable_emergency_bundle.h"
#include "ayu/features/profile_sets/profile_revocable_emergency_capability.h"
#include "ayu/features/profile_sets/profile_revocable_vault.h"
#include "crl/crl_async.h"
#include "crl/crl_on_main.h"
#include "mtproto/mtproto_config.h"

#include <QtCore/QFileInfo>

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

struct EmergencyMasterAccess final {
	~EmergencyMasterAccess() {
		Wipe(credential);
		for (auto &account : admin.accounts) Wipe(account.key);
	}
	CommittedMigration committed;
	ProfileVault vault;
	std::optional<RevocableProfileVault> revocable;
	std::optional<AccountGateTable> gates;
	std::optional<RevocableAdminVaultAccess> revocableAdmin;
	DerivedCredential credential;
	AdminVaultAccess admin;
	std::vector<EA::NamedEmergencyRule> rules;
};

bool OpenRevocableMaster(
		const MigrationController &workspace,
		EmergencyMasterAccess &access,
		QString &passcode,
		Result &error) {
	const auto &committed = access.committed;
	access.revocable = RevocableProfileVault::Parse(committed.profileVault);
	access.gates = ParseAccountGateTable(committed.accountGateTable, committed.installationId);
	if (!access.revocable || !access.gates || access.revocable->installationId() != committed.installationId
		|| !committed.revocableEmergencyRecovery.isEmpty() || committed.retirementPending) {
		return false;
	}
	const auto &vault = *access.revocable;
	access.vault.id = vault.installationId();
	access.vault.salt = vault.salt();
	access.vault.kdf = vault.kdf();
	access.credential = details::DeriveProfileVaultCredentialOnWorker(vault.salt(), vault.kdf(), passcode);
	if (!access.credential.valid()) {
		error = Result::WrongMaster;
		return false;
	}
	return workspace.WithCurrentRevocableGeneration(committed.proof(), [&](const auto&) {
		auto opened = vault.open(access.credential);
		const auto admin = std::get_if<RevocableAdminVaultAccess>(&opened);
		if (!admin) {
			error = Result::WrongMaster;
			return false;
		}
		access.revocableAdmin.emplace(std::move(*admin));
		access.admin.metadata = access.revocableAdmin->metadata;
		auto live = std::set<AccountId>();
		for (const auto &grant : access.revocableAdmin->accounts) {
			auto opened = OpenAccountGate(*access.gates, grant.handle);
			if (std::holds_alternative<AccountGateRevoked>(opened)) {
				continue;
			}
			const auto key = std::get_if<AccountKey>(&opened);
			if (!key || !live.emplace(key->id).second) {
				return false;
			}
			access.admin.locators.push_back({ key->id, grant.handle.binding().locator });
			access.admin.accounts.push_back(std::move(*key));
		}
		for (auto &set : access.admin.metadata.sets) {
			std::erase_if(set.accounts, [&](AccountId id) { return !live.contains(id); });
		}
		if (committed.revocableEmergencyRules.isEmpty()) {
			return true;
		}
		const auto bundle = ParseRevocableProfileEmergencyBundle(committed.installationId,
			committed.revocableEmergencyRules);
		auto rules = bundle ? EA::OpenEmergencyRulesForMaster(bundle->rules.authority,
			BytesOf(bundle->rules.rules), BytesOf(access.credential.key)) : std::nullopt;
		if (!rules) {
			return false;
		}
		std::erase_if(*rules, [&](const auto &entry) {
			return entry.details.executionCapsuleDigest
				&& bundle->consumed.contains(ByteArrayOf(*entry.details.executionCapsuleDigest));
		});
		access.rules = std::move(*rules);
		return true;
	});
}

std::unique_ptr<EmergencyMasterAccess> OpenMaster(
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
	if (committed->layout == MigrationGenerationLayout::RevocableGates) {
		auto access = std::make_unique<EmergencyMasterAccess>();
		access->committed = std::move(*committed);
		return OpenRevocableMaster(workspace, *access, passcode, error) ? std::move(access) : nullptr;
	}
	auto vault = ParseProfileVault(committed->profileVault);
	if (!vault || vault->version != kProfileVaultVersion) {
		return nullptr;
	}
	auto access = std::make_unique<EmergencyMasterAccess>();
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
	std::vector<Window::EmergencyDeviceChoice> devices;
};

struct InstallationInventory final {
	EA::LiveInstallation live;
	std::map<EA::AccountId, VerifiedAccount> accounts;
};

std::optional<InstallationInventory> ReadInstallationInventory(
		const MigrationController &workspace,
		const EmergencyMasterAccess &master,
		const std::set<EA::AccountId> *selectedAccounts = nullptr) {
	const auto root = workspace.accountStorageRoot();
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
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
		auto verified = VerifiedAccount{
			.key = &key,
			.locator = locator->second,
			.identity = {
				.userId = identity->userId.bare,
				.environment = identity->environment == MTP::Environment::Test
					? EA::EmergencyScopedEnvironment::Test : EA::EmergencyScopedEnvironment::Production,
			},
			.canEndOtherSessions = bool(config),
		};
		auto live = EA::LiveAccount{ id, current, { current } };
		if (config && (!selectedAccounts || selectedAccounts->contains(id))) {
			const auto devices = EA::ReadMtprotoDeviceInventory(workspace, master.admin, key.id,
				verified.identity.userId, verified.identity.environment == EA::EmergencyScopedEnvironment::Test,
				deadline);
			if (devices) {
				for (const auto &device : *devices) {
					if (!device.current) {
						live.sessionIds.push_back(device.id);
						verified.devices.push_back({ device.id, device.label });
					}
				}
			}
		}
		result.live.accounts.push_back(std::move(live));
		result.accounts.emplace(id, std::move(verified));
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
		.canRemoveInstallation = ReadRemovalPackage(workspace, inventory->live.id).has_value(),
		.entries = std::move(access->rules),
	};
	for (const auto &[id, account] : inventory->accounts) {
		result.accounts.push_back({
			.id = id,
			.label = u"Account %1"_q.arg(qulonglong(account.identity.userId)),
			.canEndOtherSessions = account.canEndOtherSessions,
			.devices = account.devices,
		});
	}
	for (auto i = size_t(0); i != access->admin.metadata.sets.size(); ++i) {
		const auto &set = access->admin.metadata.sets[i];
		const auto &profile = inventory->live.profiles[i];
		result.safeSets.push_back({ profile.id, set.name, profile.accountIds });
	}
	const auto journalDirectory = workspace.emergencyJournalDirectory();
	if (!journalDirectory.isEmpty()) {
		const auto log = EA::FileJournalStore(QFileInfo(journalDirectory).filesystemFilePath());
		if (const auto latest = log.latestReset(inventory->live.id)) {
			const auto unconfirmed = [](const EA::JournalEffectState &effect) {
				return effect.state != EA::EffectState::NotRequested && effect.state != EA::EffectState::Succeeded;
			};
			auto summary = Window::EmergencyResetSummary();
			summary.installationRemovalRefused = (latest->installationRemoval.state == EA::EffectState::Refused);
			for (const auto &account : latest->accounts) {
				summary.clearedAccounts += (account.localDataClear.state == EA::EffectState::Succeeded);
				summary.unconfirmedDeviceRevokes += unconfirmed(account.remoteSessionRevoke);
				summary.unconfirmedLogouts += unconfirmed(account.currentSessionLogout);
			}
			result.lastReset = summary;
		}
	}
	error = Result::Success;
	return result;
}

EA::RuleConfiguration RuleConfiguration(
		const EmergencyMasterAccess &master,
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

std::optional<ProfileVault> AddFallbackEnrollmentSet(
		const ProfileVault &pruned,
		const DerivedCredential &admin,
		const DerivedCredential &emergency) {
	auto access = OpenProfileVault(pruned, admin);
	const auto master = std::get_if<AdminVaultAccess>(&access);
	if (!master) {
		return std::nullopt;
	}
	const auto wipe = gsl::finally([&] { for (auto &account : master->accounts) Wipe(account.key); });
	const auto id = NewSetId();
	if (!id) {
		return std::nullopt;
	}
	master->metadata.sets.push_back({
		.id = id,
		.name = u"New account"_q,
		.verifier = emergency.verifier,
	});
	auto replacement = std::vector<SetGrantCredential>{ { id, emergency } };
	const auto wipeReplacement = gsl::finally([&] { Wipe(replacement.front().credential); });
	return UpdateProfileVault(pruned, admin, master->metadata, replacement);
}

std::optional<EA::EmergencyExecutionCapsuleDigest> PackageDigest(const ApprovedRemovalPackage *package) {
	if (!package || package->digest.size() != qsizetype(EA::kEmergencyInstallationDigestBytes)) {
		return std::nullopt;
	}
	auto result = EA::EmergencyExecutionCapsuleDigest();
	std::ranges::copy(BytesOf(package->digest), result.begin());
	return result;
}

std::optional<EA::SealedEmergencyExecutionCapsule> SealRevocableRule(
		const EmergencyMasterAccess &master,
		const EA::EmergencyRuleGeneration &generation,
		const EA::EmergencyRuleDetails &details,
		const EA::LiveInstallation &live,
		const EA::DryRunPlan &plan,
		std::span<const AccountId> targetIds,
		std::span<const EA::EmergencyExecutionAccount> targets,
		const ApprovedRemovalPackage *package,
		QString &safePasscode,
		const DerivedCredential &emergency) {
	auto accounts = std::vector<RevocableEmergencyAccount>();
	accounts.reserve(targetIds.size());
	for (auto i = size_t(0); i != targetIds.size(); ++i) {
		const auto &grants = master.revocableAdmin->accounts;
		const auto grant = std::ranges::find(grants, targetIds[i], [](const auto &entry) {
			return entry.handle.binding().id;
		});
		if (grant == grants.end()) {
			return std::nullopt;
		}
		auto handleBytes = grant->handle.serialize();
		auto permitBytes = grant->permit.serialize();
		const auto wipe = gsl::finally([&] { Wipe(handleBytes); Wipe(permitBytes); });
		auto handle = AccountGateHandle::Parse(handleBytes);
		auto permit = AccountGateRevocationPermit::Parse(permitBytes);
		if (!handle || !permit) {
			return std::nullopt;
		}
		accounts.push_back({ std::move(*handle), std::move(*permit), targets[i].remoteIdentity });
	}
	auto safe = std::optional<RevocableEmergencySafeSetView>();
	auto safeCredential = DerivedCredential();
	const auto wipe = gsl::finally([&] { Wipe(safeCredential); });
	if (plan.safeDestination == EA::SafeDestinationKind::Profile) {
		safeCredential = details::DeriveProfileVaultCredentialOnWorker(
			master.vault.salt, master.vault.kdf, safePasscode);
		const auto opened = master.revocable->open(safeCredential);
		const auto access = std::get_if<RevocableSetVaultAccess>(&opened);
		if (!access || EA::ProfileId(Identifier(access->id())) != plan.safeProfileId) {
			return std::nullopt;
		}
		safe = RevocableEmergencySafeSetView{ access->id(), safeCredential.verifier, safeCredential.key };
	}
	return SealRevocableEmergencyCapability(generation, details, live, *master.gates,
		accounts, safe, PackageDigest(package), BytesOf(emergency.key));
}

Result PublishRevocableRules(
		const MigrationController &workspace,
		const EmergencyMasterAccess &master,
		const QByteArray &transaction,
		const QByteArray &bundle) {
	const auto &current = master.committed;
	auto artifacts = std::vector<MigrationInput>{
		{ MigrationArtifact::ProfileVault, current.profileVault },
		{ MigrationArtifact::AccountGateTable, current.accountGateTable },
	};
	if (!bundle.isEmpty()) {
		artifacts.push_back({ MigrationArtifact::RevocableEmergencyRules, bundle });
	}
	auto error = MigrationError::None;
	const auto published = workspace.ReplaceRevocableCommitted(current.proof(), current.installationId,
		artifacts, [&](const auto &candidate) {
			return candidate.transactionId == transaction && candidate.profileVault == current.profileVault
				&& candidate.accountGateTable == current.accountGateTable
				&& candidate.revocableEmergencyRules == bundle && candidate.revocableEmergencyRecovery.isEmpty();
		}, &error, transaction);
	if (!published) {
		return (error == MigrationError::StaleGeneration
			|| error == MigrationError::PublicationUncertain) ? Result::Stale : Result::Failed;
	}
	return workspace.RetireRevocableGenerations(published->proof()) ? Result::Success : Result::Stale;
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
	auto selectedAccounts = std::set<EA::AccountId>();
	for (const auto &entry : request.entries) {
		for (const auto &policy : entry.rule.remoteSessionPolicies) {
			if (policy.kind == EA::RemoteSessionTargetKind::SelectedSessions) {
				selectedAccounts.insert(policy.accountId);
			}
		}
	}
	const auto inventory = ReadInstallationInventory(workspace, *access, &selectedAccounts);
	if (!inventory) {
		return Result::Unavailable;
	}
	const auto removesInstallation = std::ranges::any_of(request.entries, [](const auto &entry) {
		return entry.rule.action == EA::EmergencyAction::RemoveInstallation;
	});
	const auto package = removesInstallation ? ReadRemovalPackage(workspace, inventory->live.id) : std::nullopt;
	if (removesInstallation && !package) {
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
		const auto uninstall = rule.action == EA::EmergencyAction::RemoveInstallation;
		if (uninstall != (rule.targetScope == EA::TargetScope::CurrentInstallation)
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
			|| (!uninstall && preview->plan.accounts.empty()) || !preview->plan.selectedAccountIdsNotLive.empty()) {
			return Result::CredentialsRejected;
		}
		const auto &plan = preview->plan;
		auto targets = std::vector<EA::EmergencyExecutionAccount>();
		auto removed = std::vector<AccountId>();
		for (const auto &target : plan.accounts) {
			const auto account = inventory->accounts.find(target.accountId);
			if (account == end(inventory->accounts)
				|| (target.remoteTarget == EA::RemoteSessionTargetKind::SelectedSessions
					&& (target.sessionIdsForRevokeRequest.empty() || !target.selectedSessionIdsNotLive.empty()))
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
		if (access->revocable) {
			const auto sealed = SealRevocableRule(*access, generation, {
				.actionId = id, .rule = rule, .operationId = operation,
				.revision = config.emergencyRules.back().revision,
			}, inventory->live, plan, removed, targets, uninstall ? &*package : nullptr,
				entry.safeSetPasscode, credential);
			if (!sealed || !capsules.emplace(ByteArrayOf(sealed->digest), ByteArrayOf(sealed->bytes)).second) {
				return Result::CredentialsRejected;
			}
			inputs.push_back({
				.actionId = id, .name = entry.name.trimmed().toUtf8().toStdString(),
				.verifier = verifier, .key = BytesOf(credential.key),
				.executionCapsuleDigest = sealed->digest,
			});
			continue;
		}
		auto pruned = (uninstall && removed.empty())
			? std::optional(access->vault)
			: PruneProfileVaultAccounts(access->vault, access->credential, removed);
		if (pruned && plan.safeDestination == EA::SafeDestinationKind::AddAccount) {
			pruned = AddFallbackEnrollmentSet(*pruned, access->credential, credential);
		}
		if (!pruned) {
			return Result::Failed;
		}
		const auto vault = SerializeProfileVault(*pruned);
		auto remaining = access->admin.accounts;
		const auto wipeRemaining = gsl::finally([&] { for (auto &key : remaining) Wipe(key.key); });
		std::erase_if(remaining, [&](const AccountKey &key) {
			return std::ranges::find(removed, key.id) != removed.end();
		});
		const auto keyring = SealAccountKeyring(remaining, access->credential.key);
		const auto successor = EA::EmergencyExecutionSuccessor{
			.transactionId = MigrationController::NewTransactionId().toHex().toStdString(),
			.sealedProfileVault = BytesOf(vault), .sealedAccountKeyring = BytesOf(keyring),
			.installationDigest = uninstall ? BytesOf(package->digest) : std::span<const uint8_t>(),
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
	if (access->revocable) {
		if (inputs.empty()) {
			return PublishRevocableRules(workspace, *access, next, {});
		}
		const auto sealed = EA::SealEmergencyRules(generation, BytesOf(access->credential.key), config,
			inventory->live, inputs);
		if (!sealed) {
			return Result::Failed;
		}
		const auto bundle = SerializeRevocableProfileEmergencyBundle({ .rules = {
			sealed->authority, ByteArrayOf(sealed->bytes), capsules,
		} });
		const auto restored = ParseRevocableProfileEmergencyBundle(access->committed.installationId, bundle);
		if (!restored) {
			return Result::Failed;
		}
		for (const auto &input : inputs) {
			const auto authenticated = EA::AuthenticateEmergencyRule(restored->rules.authority,
				BytesOf(restored->rules.rules), input.key);
			const auto ticket = std::get_if<EA::EmergencyRuleTicket>(&authenticated);
			if (!ticket || ticket->details().actionId != input.actionId
				|| ticket->details().executionCapsuleDigest != input.executionCapsuleDigest) {
				return Result::Failed;
			}
			const auto blob = restored->rules.capsules.find(ByteArrayOf(*input.executionCapsuleDigest));
			const auto removing = (ticket->details().rule.action == EA::EmergencyAction::RemoveInstallation);
			if (blob == restored->rules.capsules.end()
				|| !std::holds_alternative<OpenedRevocableEmergencyCapability>(OpenRevocableEmergencyCapability(
					restored->rules.authority.generation, *ticket, *access->gates, BytesOf(blob->second),
					PackageDigest(removing ? &*package : nullptr), input.key))) {
				return Result::Failed;
			}
		}
		return PublishRevocableRules(workspace, *access, next, bundle);
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
		const auto proof = ReadProfileEmergencyBundle({
			.transactionId = next,
			.profileVault = access->committed.profileVault,
			.emergencyRules = bundle,
		});
		if (!proof) {
			return Result::Failed;
		}
		for (auto i = size_t(0); i != inputs.size(); ++i) {
			const auto &input = inputs[i];
			const auto &rule = config.emergencyRules[i];
			const auto matched = EA::AuthenticateEmergencyRule(proof->authority, BytesOf(proof->rules), input.key);
			const auto ticket = std::get_if<EA::EmergencyRuleTicket>(&matched);
			if (!ticket || ticket->details().actionId != rule.id || ticket->details().rule != rule.rule
				|| !ticket->reviewedLive() || ticket->details().executionCapsuleDigest != input.executionCapsuleDigest) {
				return Result::Failed;
			}
			const auto capsule = proof->capsules.find(ByteArrayOf(*input.executionCapsuleDigest));
			const auto plan = EA::BuildDryRunPlan(ticket->details().operationId, rule.rule, *ticket->reviewedLive());
			if (capsule == proof->capsules.end() || !EA::OpenEmergencyExecutionCapsule(
					*ticket, plan, BytesOf(capsule->second), input.key)) {
				return Result::Failed;
			}
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

std::optional<QByteArray> RebindProfileEmergencyRulesOnWorker(
		const MigrationController &workspace,
		const CommittedMigration &previous,
		const ProfileVault &nextVault,
		const QByteArray &nextTransaction,
		const DerivedCredential &master,
		std::span<const SetGrantCredential> replacements) {
	if (previous.emergencyRules.isEmpty()) {
		return QByteArray();
	}
	const auto bundle = ReadProfileEmergencyBundle(previous);
	auto oldVault = ParseProfileVault(previous.profileVault);
	if (!bundle || !oldVault || oldVault->id != nextVault.id || oldVault->salt != nextVault.salt
		|| oldVault->kdf != nextVault.kdf || nextTransaction.size() != 16) {
		return std::nullopt;
	}
	auto masterAccess = EmergencyMasterAccess();
	masterAccess.credential = master;
	masterAccess.vault = nextVault;
	auto opened = OpenProfileVault(nextVault, master);
	const auto nextAdmin = std::get_if<AdminVaultAccess>(&opened);
	if (!nextAdmin) {
		return std::nullopt;
	}
	masterAccess.admin = std::move(*nextAdmin);
	const auto noNetwork = std::set<EA::AccountId>();
	auto inventory = ReadInstallationInventory(workspace, masterAccess, &noNetwork);
	const auto rules = EA::OpenEmergencyRulesForMaster(bundle->authority, BytesOf(bundle->rules), BytesOf(master.key));
	if (!inventory || !rules) {
		return std::nullopt;
	}
	for (const auto &rule : *rules) {
		for (const auto &policy : rule.details.rule.remoteSessionPolicies) {
			const auto account = std::ranges::find(inventory->live.accounts, policy.accountId, &EA::LiveAccount::id);
			if (account != end(inventory->live.accounts)) {
				for (const auto &device : policy.selectedSessionIds) {
					if (std::ranges::find(account->sessionIds, device) == account->sessionIds.end()) {
						account->sessionIds.push_back(device);
					}
				}
			}
		}
	}
	const auto generation = EA::EmergencyRuleGeneration{
		.installationId = inventory->live.id, .transactionId = nextTransaction.toHex().toStdString() };
	const auto configuration = RuleConfiguration(masterAccess, generation.installationId);
	auto capsules = std::map<QByteArray, QByteArray>();
	const auto rebound = EA::RebindEmergencyRulesForMaster(bundle->authority, BytesOf(bundle->rules), BytesOf(master.key),
		generation, inventory->live, { BytesOf(master.key), configuration.masterVerifier, configuration.normalCredentials },
		[&](const EA::EmergencyRuleTicket &prior, const EA::EmergencyRuleDetails &next,
				const EA::DryRunPlan &plan, EA::EmergencyExecutionCapsuleKey key)
				-> std::optional<EA::EmergencyExecutionCapsuleDigest> {
			const auto source = bundle->capsules.find(ByteArrayOf(*prior.details().executionCapsuleDigest));
			const auto oldCapsule = source != bundle->capsules.end()
				? EA::OpenEmergencyExecutionCapsuleForRebind(prior, BytesOf(source->second), key) : std::nullopt;
			if (!oldCapsule) {
				return std::nullopt;
			}
			if (next.rule.action == EA::EmergencyAction::RemoveInstallation) {
				const auto package = ReadRemovalPackage(workspace, generation.installationId);
				if (!package || package->digest != ByteArrayOf(oldCapsule->successor().installationDigest)) {
					return std::nullopt;
				}
			}
			const auto oldPlan = EA::BuildDryRunPlan(
				prior.details().operationId, prior.details().rule, *prior.reviewedLive());
			auto targets = std::vector<EA::EmergencyExecutionAccount>();
			auto removed = std::vector<AccountId>();
			for (const auto &target : plan.accounts) {
				const auto grant = inventory->accounts.find(target.accountId);
				if (grant == inventory->accounts.end()) {
					return std::nullopt;
				}
				const auto &account = grant->second;
				const auto oldAccounts = oldCapsule->accounts();
				const auto previous = std::ranges::find(oldAccounts, target.accountId, &EA::EmergencyExecutionAccount::accountId);
				const auto original = std::ranges::find(oldPlan.accounts, target.accountId, &EA::AccountDryRun::accountId);
				const auto locator = account.locator->value.toHex().toStdString();
				const auto scopedKey = BytesOf(account.key->key);
				if (previous != end(oldAccounts)
					&& (previous->locator != locator || previous->scopedKey.size() != scopedKey.size()
						|| CRYPTO_memcmp(previous->scopedKey.data(), scopedKey.data(), scopedKey.size())
						|| !previous->remoteIdentity || previous->remoteIdentity->userId != account.identity.userId
						|| previous->remoteIdentity->environment != account.identity.environment)) {
					return std::nullopt;
				} else if (target.remoteTarget != EA::RemoteSessionTargetKind::None
					&& (!account.canEndOtherSessions || previous == end(oldAccounts) || original == end(oldPlan.accounts)
						|| original->remoteTarget != target.remoteTarget
						|| (target.remoteTarget == EA::RemoteSessionTargetKind::SelectedSessions
							&& original->sessionIdsForRevokeRequest != target.sessionIdsForRevokeRequest))) {
					return std::nullopt;
				}
				removed.push_back(account.key->id);
				targets.push_back({ target.accountId, locator, scopedKey, account.identity });
			}
			auto pruned = removed.empty() ? std::optional(nextVault) : PruneProfileVaultAccounts(nextVault, master, removed);
			if (pruned && plan.safeDestination == EA::SafeDestinationKind::AddAccount) {
				const auto sourceVault = ParseProfileVault(ByteArrayOf(oldCapsule->successor().sealedProfileVault));
				if (!sourceVault) return std::nullopt;
				auto fallback = SetId();
				for (const auto &grant : sourceVault->grants) {
					if (std::ranges::find(oldVault->grants, grant.id, &SealedSetGrant::id) == end(oldVault->grants)) {
						if (fallback) return std::nullopt;
						fallback = grant.id;
					}
				}
				pruned = CopyEmptyProfileVaultSet(*pruned, *sourceVault, master, fallback);
			}
			if (!pruned) return std::nullopt;
			const auto sealedVault = SerializeProfileVault(*pruned);
			auto remaining = masterAccess.admin.accounts;
			const auto wipeRemaining = gsl::finally([&] { for (auto &account : remaining) Wipe(account.key); });
			std::erase_if(remaining, [&](AccountKey &account) {
				const auto remove = std::ranges::find(removed, account.id) != removed.end();
				if (remove) Wipe(account.key);
				return remove;
			});
			const auto keyring = SealAccountKeyring(remaining, master.key);
			const auto successor = EA::EmergencyExecutionSuccessor{
				.transactionId = MigrationController::NewTransactionId().toHex().toStdString(),
				.sealedProfileVault = BytesOf(sealedVault), .sealedAccountKeyring = BytesOf(keyring),
				.installationDigest = oldCapsule->successor().installationDigest,
			};
			auto safe = oldCapsule->safeDestination();
			auto replacementKey = QByteArray();
			const auto wipeReplacement = gsl::finally([&] { Wipe(replacementKey); });
			if (plan.safeDestination == EA::SafeDestinationKind::Profile) {
				if (!safe || safe->profileId != plan.safeProfileId || safe->sealedSetGrant.size() != 64) return std::nullopt;
				for (const auto &replacement : replacements) {
					if (EA::ProfileId(Identifier(replacement.id)) == plan.safeProfileId) {
						replacementKey = replacement.credential.verifier + replacement.credential.key;
						safe->sealedSetGrant = BytesOf(replacementKey);
						break;
					}
				}
				auto derived = DerivedCredential{ ByteArrayOf(safe->sealedSetGrant.first(32)), ByteArrayOf(safe->sealedSetGrant.last(32)) };
				const auto wipe = gsl::finally([&] { Wipe(derived); });
				auto opened = OpenProfileVault(*pruned, derived);
				const auto grant = std::get_if<SetVaultAccess>(&opened);
				if (!grant) {
					if (const auto openedMaster = std::get_if<AdminVaultAccess>(&opened)) {
						for (auto &account : openedMaster->accounts) Wipe(account.key);
					}
					return std::nullopt;
				}
				const auto correct = EA::ProfileId(Identifier(grant->id)) == plan.safeProfileId;
				Wipe(grant->settingsKey);
				for (auto &account : grant->accounts) Wipe(account.key);
				if (!correct) return std::nullopt;
			}
			const auto sealed = EA::SealEmergencyExecutionCapsuleForRebind(generation, next, plan,
				targets, successor, safe, key);
			if (!sealed || !capsules.emplace(ByteArrayOf(sealed->digest), ByteArrayOf(sealed->bytes)).second) return std::nullopt;
			return sealed->digest;
		});
	const auto result = rebound ? SerializeProfileEmergencyBundle(ByteArrayOf(rebound->bytes), capsules) : QByteArray();
	return result.isEmpty() ? std::nullopt : std::optional(result);
}

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
