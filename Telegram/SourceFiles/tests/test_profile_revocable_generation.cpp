// This is the source code of AyuGram for Desktop.
#include "ayu/features/profile_sets/profile_generation.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QCryptographicHash>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QProcess>
#include <QtCore/QTemporaryDir>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>

namespace {

using namespace Ayu::ProfileSets;

constexpr auto kChildCrashCode = 41;
constexpr auto kFixturePrefix = "sleepygram-revocable-generation-fixture-";

struct Fixture final {
	DerivedCredential admin = { QByteArray(32, 'a'), QByteArray(32, 'A') };
	DerivedCredential set = { QByteArray(32, 's'), QByteArray(32, 'S') };
	DerivedCredential onlyA = { QByteArray(32, 't'), QByteArray(32, 'T') };
	DerivedCredential empty = { QByteArray(32, 'u'), QByteArray(32, 'U') };
	AccountKey a = { { 1, 1 }, QByteArray(kAccountKeySize, '1') };
	AccountKey b = { { 1, 2 }, QByteArray(kAccountKeySize, '2') };
	AccountVaultLocator locatorA = { a.id, QByteArray(16, 'x') };
	AccountVaultLocator locatorB = { b.id, QByteArray(16, 'y') };
	SetId setId = { 2, 1 };
	SetId onlyAId = { 2, 2 };
	SetId emptyId = { 2, 3 };

	Metadata metadata() const {
		return {
			.verifierSalt = QByteArray(kVerifierSaltSize, 'p'),
			.verifierKdf = { .kind = 1, .memory = 8192, .time = 1, .parallel = 1 },
			.masterVerifier = admin.verifier,
			.sets = {
				{ setId, u"Both"_q, set.verifier, { a.id, b.id } },
				{ onlyAId, u"Only A"_q, onlyA.verifier, { a.id } },
				{ emptyId, u"Empty"_q, empty.verifier, {} },
			},
		};
	}

	std::vector<SetGrantCredential> credentials() const {
		return { { setId, set }, { onlyAId, onlyA }, { emptyId, empty } };
	}

};

struct Candidate final {
	RevocableProfileVault vault;
	AccountGateTable gates;
};

std::optional<Candidate> Prepare(
		const Fixture &fixture,
		QByteArrayView installationId,
		const AccountKey &keyB) {
	const auto empty = AccountGateTable::Create(installationId);
	auto a = empty
		? CreateAccountGate(*empty, fixture.a, fixture.locatorA.value)
		: std::nullopt;
	auto b = a ? CreateAccountGate(a->table, keyB, fixture.locatorB.value) : std::nullopt;
	if (!a || !b) {
		return std::nullopt;
	}
	const auto accounts = std::array{
		RevocableAccountGrant{ std::move(a->handle), std::move(a->permit) },
		RevocableAccountGrant{ std::move(b->handle), std::move(b->permit) },
	};
	auto vault = RevocableProfileVault::Seal(installationId, fixture.metadata(),
		accounts, fixture.admin, fixture.credentials());
	return vault ? std::optional(Candidate{ std::move(*vault), std::move(b->table) }) : std::nullopt;
}

QByteArray Read(const QString &path) {
	auto file = QFile(path);
	return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
}

bool Write(const QString &path, const QByteArray &bytes) {
	auto file = QFile(path);
	return file.open(QIODevice::WriteOnly)
		&& file.write(bytes) == bytes.size()
		&& file.flush();
}

bool HardLink(const QString &source, const QString &target) {
	auto error = std::error_code();
	std::filesystem::create_hard_link(
		QFileInfo(source).filesystemFilePath(), QFileInfo(target).filesystemFilePath(), error);
	return !error;
}

QByteArray Checkpoint(
		const QByteArray &installation,
		const QByteArray &transaction,
		const QByteArray &gates,
		const QByteArray &rules) {
	return QByteArray("SGER3") + installation + transaction
		+ QCryptographicHash::hash(gates, QCryptographicHash::Sha256)
		+ QCryptographicHash::hash(rules, QCryptographicHash::Sha256)
		+ QByteArray("\0\0\0\0\1J", 6);
}

QString GenerationDirectory(const MigrationController &workspace, const QByteArray &id) {
	return QDir(workspace.workspacePath()).filePath(u"generations/"_q + QString::fromLatin1(id.toHex()));
}

bool MatchesKey(const AccountGateOpenResult &opened, const AccountKey &expected) {
	const auto key = std::get_if<AccountKey>(&opened);
	return key && *key == expected;
}

int EndAroundPublication(const QString &dataDirectory, bool after, bool pendingOnly = false) {
	const auto parent = QFileInfo(dataDirectory).dir();
	if (!parent.dirName().startsWith(QLatin1StringView(kFixturePrefix))
		|| QFileInfo(parent.path()).dir().canonicalPath() != QDir(QDir::tempPath()).canonicalPath()) {
		return 1;
	}
	const auto workspace = MigrationController::OpenProfileWorkspace(dataDirectory);
	const auto current = workspace ? workspace->LoadCommitted() : std::nullopt;
	const auto legacy = current ? ParseProfileVault(current->profileVault) : std::nullopt;
	if (!legacy) {
		return 2;
	}
	const auto fixture = Fixture();
	const auto candidate = Prepare(fixture, legacy->id, fixture.b);
	if (!candidate) {
		return 3;
	}
	const auto root = QDir(workspace->workspacePath());
	const auto activePath = root.filePath(u"migration.manifest.committed"_q);
	const auto oldManifest = Read(activePath);
	if (pendingOnly) {
		qputenv("SLEEPYGRAM_FIXTURE_STOP_BEFORE_ACTIVE_RENAME", QByteArray("1"));
	}
	const auto promoted = PromoteCommittedRevocableProfileGeneration(
		*workspace, current->proof(), candidate->vault, candidate->gates, fixture.admin,
		[&](const CommittedRevocableProfileGeneration &verified) {
			if (!after) {
				std::_Exit(kChildCrashCode);
			}
			return verified.retirementPending && verified.proof.manifestDigest.size() == 32;
		});
	if (after && promoted) {
		if (pendingOnly) {
			const auto temporary = root.filePath(u"generations/.manifest-"_q
				+ QString::fromLatin1(promoted->transactionId.toHex()));
			const auto marker = QByteArray("SGRH1P") + legacy->id
				+ current->transactionId + current->manifestDigest
				+ promoted->transactionId + promoted->manifestDigest;
			if (!Write(temporary, Read(activePath)) || !Write(activePath, oldManifest)
				|| !QFile::remove(root.filePath(u".revocable-floor"_q))
				|| !Write(root.filePath(u".revocable-head"_q), marker)) {
				return 5;
			}
		}
		std::_Exit(kChildCrashCode);
	}
	return 4;
}

bool Crash(const QString &dataDirectory, const QString &position) {
	auto process = QProcess();
	process.start(QCoreApplication::applicationFilePath(), { position, dataDirectory });
	return process.waitForFinished(10000) && process.exitStatus() == QProcess::NormalExit
		&& process.exitCode() == kChildCrashCode;
}

int RunChecks() {
	auto total = 0;
	auto passed = 0;
	const auto check = [&](const char *name, bool condition) {
		++total;
		passed += int(condition);
		std::printf("%s %s\n", condition ? "PASS" : "FAIL", name);
	};

	const auto temporary = QTemporaryDir(QDir::temp().filePath(
		QString::fromLatin1(kFixturePrefix) + u"XXXXXX"_q));
	if (!temporary.isValid() || !QDir(temporary.path()).mkdir(u"tdata"_q)) {
		return 1;
	}
	const auto fixture = Fixture();
	const auto dataDirectory = QDir(temporary.path()).filePath(u"tdata"_q);
	const auto workspace = MigrationController::CreateProfileWorkspace(dataDirectory);
	const auto legacyVault = SealProfileVault(fixture.metadata(), { fixture.a, fixture.b },
		{ fixture.locatorA, fixture.locatorB }, fixture.admin, fixture.credentials());
	const auto legacyKeyring = SealAccountKeyring({ fixture.a, fixture.b }, fixture.admin.key);
	if (!workspace || !legacyVault || legacyKeyring.isEmpty()) {
		return 1;
	}
	const auto legacyInputs = std::vector<MigrationInput>{
		{ MigrationArtifact::ProfileVault, SerializeProfileVault(*legacyVault) },
		{ MigrationArtifact::AccountKeyring, legacyKeyring },
	};
	auto modernRuleInLegacy = legacyInputs;
	const auto rules = QByteArray("SGEB3") + QByteArray(16, 'e') + QByteArray(8, '\0');
	modernRuleInLegacy.push_back({ MigrationArtifact::RevocableEmergencyRules, rules });
	check("the v1 pending writer does not accept revocable emergency artifacts",
		!workspace->Stage(modernRuleInLegacy));
	if (!workspace->Stage(legacyInputs)) {
		return 1;
	}
	const auto root = QDir(workspace->workspacePath());
	const auto linked = QDir(temporary.path()).filePath(u"outside-link.bin"_q);
	auto error = MigrationError::None;
	check("linked staged keyring cannot be committed",
		HardLink(root.filePath(u"stage/account-keyring.bin"_q), linked)
		&& !workspace->CommitVerified([](const auto&) { return true; }, &error)
		&& error == MigrationError::ReadbackFailed && QFile::remove(linked));
	const auto initial = workspace->CommitVerified([&](const CommittedMigration &candidate) {
		return candidate.profileVault == legacyInputs[0].encryptedBytes
			&& candidate.accountKeyring == legacyInputs[1].encryptedBytes;
	});
	if (!initial || initial->manifestDigest.size() != 32) {
		return 1;
	}
	check("the v2 generation writer does not accept revocable emergency artifacts",
		!workspace->ReplaceCommitted(initial->transactionId, modernRuleInLegacy,
			[](const auto&) { return true; }));
	check("linked active vault fails closed until the external link is removed",
		HardLink(root.filePath(u"stage/profile-vault.bin"_q), linked)
		&& !workspace->LoadCommitted(&error) && error == MigrationError::ReadbackFailed
		&& QFile::remove(linked) && workspace->LoadCommitted());
	const auto active = root.filePath(u"migration.manifest.committed"_q);
	const auto head = root.filePath(u".revocable-head"_q);
	const auto floor = root.filePath(u".revocable-floor"_q);
	const auto legacyManifest = Read(active);
	const auto accountWitness = QDir(workspace->accountStorageRoot()).filePath(u"fixture-data"_q);
	if (!Write(accountWitness, QByteArray("untouched account files"))) {
		return 1;
	}
	const auto candidate = Prepare(fixture, legacyVault->id, fixture.b);
	const auto wrongCandidate = Prepare(fixture, legacyVault->id,
		{ fixture.b.id, QByteArray(kAccountKeySize, 'w') });
	if (!candidate || !wrongCandidate) {
		return 1;
	}
	const auto verify = [](const CommittedRevocableProfileGeneration&) { return true; };
	auto wrongProof = initial->proof();
	wrongProof.manifestDigest[0] = char(wrongProof.manifestDigest.at(0) ^ 1);
	const auto inputs = std::vector<MigrationInput>{
		{ MigrationArtifact::ProfileVault, candidate->vault.serialize() },
		{ MigrationArtifact::AccountGateTable, SerializeAccountGateTable(candidate->gates) },
	};
	auto oldCapsule = inputs;
	oldCapsule.push_back({ MigrationArtifact::EmergencyRules, QByteArray("legacy-capsule") });
	check("only explicit typed CAS accepts v3 layout and exact current manifest proof",
		!workspace->ReplaceCommitted(initial->transactionId, inputs, [](const auto&) { return true; })
		&& !workspace->ReplaceRevocableCommitted(initial->proof(), legacyVault->id,
			oldCapsule, [](const auto&) { return true; })
		&& !PromoteCommittedRevocableProfileGeneration(*workspace, wrongProof,
			candidate->vault, candidate->gates, fixture.admin, verify, &error)
		&& error == MigrationError::StaleGeneration);
	check("promotion refuses a substituted DEK and verifier rejection",
		!PromoteCommittedRevocableProfileGeneration(*workspace, initial->proof(),
			wrongCandidate->vault, wrongCandidate->gates, fixture.admin, verify, &error)
		&& error == MigrationError::VerificationFailed
		&& !PromoteCommittedRevocableProfileGeneration(*workspace, initial->proof(),
			candidate->vault, candidate->gates, fixture.admin, [](const auto&) { return false; })
		&& Read(active) == legacyManifest);
	auto linkedInVerifier = false;
	check("link added to a verified candidate gate table blocks publication",
		!PromoteCommittedRevocableProfileGeneration(*workspace, initial->proof(), candidate->vault,
			candidate->gates, fixture.admin, [&](const auto &staged) {
				const auto directory = QDir(GenerationDirectory(*workspace, staged.proof.transactionId));
				linkedInVerifier = HardLink(directory.filePath(u"account-gate-table.bin"_q), linked);
				return linkedInVerifier;
			}, &error)
		&& linkedInVerifier && error == MigrationError::ReadbackFailed
		&& Read(active) == legacyManifest && QFile::remove(linked));
	check("abrupt exit before publication keeps the original authenticated generation",
		Crash(dataDirectory, u"--crash-before-publication"_q)
		&& workspace->LoadCommitted() && workspace->LoadCommitted()->proof() == initial->proof()
		&& Read(active) == legacyManifest && !QFileInfo::exists(head));
	const auto unaffected = GenerationDirectory(*workspace, QByteArray(16, 'j'));
	const auto untouched = QDir(unaffected).filePath(u"profile-vault.bin"_q);
	if (!QDir().mkdir(unaffected) || !Write(untouched, "unrelated generation")) {
		return 1;
	}
	check("pending promotion crash restores only the still-authentic v2 generation",
		Crash(dataDirectory, u"--crash-before-active-manifest"_q)
		&& QFileInfo::exists(head) && !QFileInfo::exists(floor)
		&& workspace->LoadCommitted() && workspace->LoadCommitted()->proof() == initial->proof()
		&& !workspace->RetireInactiveGenerations(QByteArray(16, 'n'), &error)
		&& error == MigrationError::StaleGeneration && QFileInfo::exists(head)
		&& workspace->RetireInactiveGenerations(initial->transactionId, &error)
		&& error == MigrationError::None && !QFileInfo::exists(head)
		&& Read(active) == legacyManifest && Read(untouched) == "unrelated generation");
	check("abrupt exit after publication reopens typed recovery and suppresses both startup leases",
		Crash(dataDirectory, u"--crash-after-publication"_q)
		&& workspace->LoadCommitted() && workspace->LoadCommitted()->retirementPending
		&& MigrationController::ProbeProfileStartup(dataDirectory) == ProfileStartupMode::Committed
		&& !workspace->WithCurrentGeneration(initial->transactionId, [] { return true; }));
	const auto typedAfterCrash = LoadRevocableProfileGeneration(*workspace);
	if (!typedAfterCrash) {
		return 1;
	}
	const auto liveProof = typedAfterCrash->proof;
	auto unlockError = ProfileGenerationError::None;
	const auto pendingSnapshot = workspace->LoadCommitted();
	check("the unlock worker rejects a retiring generation before reading its KDF",
		pendingSnapshot && !ReadCommittedProfileUnlockParameters(*pendingSnapshot, &unlockError)
		&& unlockError == ProfileGenerationError::RevocableRetirementRequired);
	const auto typedManifest = Read(active);
	const auto typedHead = Read(head);
	auto pendingHead = QByteArray("SGRH1P") + legacyVault->id
		+ initial->transactionId + initial->manifestDigest
		+ liveProof.transactionId + liveProof.manifestDigest;
	check("crash between head and manifest publication recognizes only the exact old or candidate",
		QFile::remove(floor) && Write(head, pendingHead) && Write(active, legacyManifest)
		&& workspace->LoadCommitted() && workspace->LoadCommitted()->proof() == initial->proof()
		&& !workspace->ReplaceCommitted(initial->transactionId, legacyInputs,
			[](const auto&) { return true; })
		&& Write(active, typedManifest) && workspace->LoadCommitted()
		&& workspace->LoadCommitted()->proof() == liveProof
		&& workspace->LoadCommitted()->retirementPending);
	check("typed startup lease requires exact proof and completed retirement",
		!WithCurrentRevocableProfileGeneration(*workspace, liveProof, verify, &error)
		&& error == MigrationError::RevocableRetirementRequired
		&& !workspace->RetireInactiveGenerations(liveProof.transactionId)
		&& !workspace->RetireRevocableGenerations(initial->proof()));
	const auto unknown = root.filePath(u"stage/foreign.bin"_q);
	check("retirement stays retryable and preserves unrelated files",
		Write(unknown, QByteArray("outside artifact inventory"))
		&& !workspace->RetireRevocableGenerations(liveProof, &error)
		&& error == MigrationError::RetirementFailed
		&& Read(unknown) == "outside artifact inventory"
		&& Read(accountWitness) == "untouched account files"
		&& workspace->LoadCommitted() && workspace->LoadCommitted()->retirementPending
		&& QFile::remove(unknown));
	check("retirement proves legacy artifacts are gone and enables the exact lease",
		workspace->RetireRevocableGenerations(liveProof)
		&& QFileInfo::exists(floor)
		&& !QFileInfo::exists(root.filePath(u"stage"_q))
		&& !QFileInfo::exists(root.filePath(u"migration.manifest.pending"_q))
		&& !QFileInfo::exists(root.filePath(u"profile-setup.bin"_q))
		&& WithCurrentRevocableProfileGeneration(*workspace, liveProof, verify)
		&& Read(accountWitness) == "untouched account files");
	const auto typed = LoadRevocableProfileGeneration(*workspace);
	if (!typed || typed->retirementPending) {
		return 1;
	}
	const auto readySnapshot = workspace->LoadCommitted();
	const auto parameters = readySnapshot
		? ReadCommittedProfileUnlockParameters(*readySnapshot)
		: std::nullopt;
	auto preRevocation = AuthenticateCommittedRevocableProfileGeneration(
		*workspace, fixture.set, liveProof);
	const auto legacySetResult = OpenProfileVault(*legacyVault, fixture.set);
	const auto legacySet = std::get_if<SetVaultAccess>(&legacySetResult);
	check("v3 KDF discovery and scoped preparation preserve the existing settings key",
		parameters && parameters->salt == legacyVault->salt && parameters->kdf == legacyVault->kdf
		&& preRevocation && preRevocation->revocableProof() && *preRevocation->revocableProof() == liveProof
		&& preRevocation->plan().targets().size() == 2
		&& legacySet && preRevocation->settingsKey() == legacySet->settingsKey);
	const auto set = typed->vault.open(fixture.set);
	const auto master = typed->vault.open(fixture.admin);
	const auto scope = std::get_if<RevocableSetVaultAccess>(&set);
	const auto admin = std::get_if<RevocableAdminVaultAccess>(&master);
	if (!scope || !admin || scope->handles().size() != 2 || admin->accounts.size() != 2) {
		return 1;
	}
	const auto livePath = QDir(GenerationDirectory(*workspace, liveProof.transactionId));
	const auto oldVaultBytes = Read(livePath.filePath(u"profile-vault.bin"_q));
	const auto oldGateBytes = Read(livePath.filePath(u"account-gate-table.bin"_q));
	const auto permitA = std::span(&admin->accounts[0].permit, 1);
	const auto permitB = std::span(&admin->accounts[1].permit, 1);
	const auto next = RevokeCommittedRevocableAccounts(*workspace, liveProof, permitA);
	if (!next) {
		return 1;
	}
	const auto afterA = LoadRevocableProfileGeneration(*workspace);
	const auto expectedA = RevokeAccountGates(typed->gates, permitA);
	check("the exact permit changes only its gate and leaves the vault and B unchanged",
		afterA && expectedA && afterA->retirementPending
		&& SerializeAccountGateTable(afterA->gates) == SerializeAccountGateTable(*expectedA)
		&& afterA->vault.serialize() == oldVaultBytes
		&& std::holds_alternative<AccountGateRevoked>(
			OpenAccountGate(afterA->gates, scope->handles()[0]))
		&& MatchesKey(OpenAccountGate(afterA->gates, scope->handles()[1]), fixture.b)
		&& !WithCurrentRevocableProfileGeneration(*workspace, liveProof, verify)
		&& !RevokeCommittedRevocableAccounts(*workspace, *next, permitB, &error)
		&& error == MigrationError::RevocableRetirementRequired);
	check("an externally linked old gate table blocks claimed retirement",
		HardLink(livePath.filePath(u"account-gate-table.bin"_q), linked)
		&& !workspace->RetireRevocableGenerations(*next, &error)
		&& error == MigrationError::RetirementFailed
		&& !WithCurrentRevocableProfileGeneration(*workspace, *next, verify)
		&& QFile::remove(linked));
	auto unexpectedStarts = 0;
	check("a prepared v3 grant cannot start an account after its exact generation is replaced",
		preRevocation && !preRevocation->Start(*workspace, [&](const auto&, const auto&) {
			++unexpectedStarts;
			return std::optional(Fn<void()>([] {}));
		}, &unlockError)
		&& unexpectedStarts == 0 && unlockError == ProfileGenerationError::StaleGeneration);
	if (!workspace->RetireRevocableGenerations(*next)) {
		return 1;
	}
	auto survivingScope = AuthenticateCommittedRevocableProfileGeneration(*workspace, fixture.set, *next);
	const auto revokedOnlyScope = AuthenticateCommittedRevocableProfileGeneration(
		*workspace, fixture.onlyA, *next);
	auto adminScope = AuthenticateCommittedRevocableProfileGeneration(*workspace, fixture.admin, *next);
	const auto metadata = adminScope ? adminScope->adminMetadata() : nullptr;
	auto validationCount = 0;
	auto starts = 0;
	auto closes = 0;
	const auto validate = [&](const AccountStorageTarget &target, const AccountKey &key) {
		++validationCount;
		return key == fixture.b && target.id == fixture.b.id
			&& target.dataName == AccountVaultDataName(fixture.locatorB)
			&& target.paths.mode == Storage::AccountStorageMode::Scoped
			&& target.paths.basePath.startsWith(workspace->accountStorageRoot());
	};
	const auto start = [&](const AccountStorageTarget &target, const AccountKey &key)
			-> std::optional<Fn<void()>> {
		++starts;
		return (target.id == fixture.b.id && key == fixture.b && validationCount == 1)
			? std::optional(Fn<void()>([&] { ++closes; }))
			: std::nullopt;
	};
	check("v3 startup validates and starts only the surviving scoped account",
		survivingScope && !survivingScope->plan().keyFor(fixture.a.id)
		&& survivingScope->Start(*workspace, validate, start)
		&& validationCount == 1 && starts == 1
		&& revokedOnlyScope && revokedOnlyScope->plan().targets().empty()
		&& revokedOnlyScope->access().setId == fixture.onlyAId);
	check("master view removes revoked memberships and never resolves storage keys",
		adminScope && adminScope->plan().targets().empty()
		&& !adminScope->plan().keyFor(fixture.b.id)
		&& adminScope->adminAccountIds() == std::vector{ fixture.b.id }
		&& metadata && metadata->sets[0].accounts == std::vector{ fixture.b.id }
		&& metadata->sets[1].accounts.empty() && metadata->sets[2].accounts.empty()
		&& adminScope->Start(*workspace, start) && starts == 1);
	if (!survivingScope) {
		return 1;
	}
	survivingScope->Close();
	auto wrongSettingsProof = *next;
	wrongSettingsProof.manifestDigest[0] = char(wrongSettingsProof.manifestDigest.at(0) ^ 1);
	auto withCurrentCalled = false;
	check("v3 settings and activation use the exact manifest proof and close releases adapters",
		closes == 1
		&& !workspace->PrepareScopedSettingsDirectory(next->transactionId, fixture.setId)
		&& !workspace->PrepareRevocableScopedSettingsDirectory(wrongSettingsProof, fixture.setId)
		&& workspace->PrepareRevocableScopedSettingsDirectory(*next, fixture.setId)
		&& adminScope && adminScope->WithCurrent(*workspace, [&] {
			withCurrentCalled = true;
			return true;
		}) && withCurrentCalled);
	const auto retiredManifest = Read(active);
	const auto retiredHead = Read(head);
	const auto retiredFloor = Read(floor);
	const auto retryA = RevokeCommittedRevocableAccounts(*workspace, *next, permitA);
	check("retired older typed grants cannot reopen even when their files and manifest reappear",
		retryA == next && !QDir(livePath.path()).exists()
		&& QDir().mkdir(livePath.path())
		&& Write(livePath.filePath(u"profile-vault.bin"_q), oldVaultBytes)
		&& Write(livePath.filePath(u"account-gate-table.bin"_q), oldGateBytes)
		&& Write(active, typedManifest)
		&& !workspace->LoadCommitted() && !LoadRevocableProfileGeneration(*workspace)
		&& Write(active, retiredManifest)
		&& workspace->LoadCommitted() && workspace->LoadCommitted()->retirementPending
		&& !WithCurrentRevocableProfileGeneration(*workspace, *next, verify)
		&& workspace->RetireRevocableGenerations(*next));
	check("retired legacy grants cannot reopen even when their stage files reappear",
		QDir(root).mkdir(u"stage"_q)
		&& Write(root.filePath(u"stage/profile-vault.bin"_q), legacyInputs[0].encryptedBytes)
		&& Write(root.filePath(u"stage/account-keyring.bin"_q), legacyKeyring)
		&& Write(active, legacyManifest) && !workspace->LoadCommitted()
		&& QFile::remove(head) && !workspace->LoadCommitted()
		&& Write(head, retiredHead)
		&& Write(active, retiredManifest) && workspace->RetireRevocableGenerations(*next));
	check("missing, damaged or extra head or format floor fails closed",
		!typedHead.isEmpty() && QFile::remove(head)
		&& !workspace->LoadCommitted() && Write(head, retiredHead + 'z')
		&& !workspace->LoadCommitted()
		&& Write(head, retiredHead) && workspace->LoadCommitted()
		&& QFile::remove(floor) && !workspace->LoadCommitted()
		&& Write(floor, retiredFloor + 'z') && !workspace->LoadCommitted()
		&& Write(floor, retiredFloor) && workspace->LoadCommitted());
	const auto gatesBeforeEdits = workspace->LoadCommitted();
	const auto rename = ProfileSetChange{
		.kind = ProfileSetChangeKind::Edit,
		.id = fixture.setId,
		.name = u" Renamed "_q,
		.accounts = { fixture.b.id },
	};
	auto staleEdit = *next;
	staleEdit.manifestDigest[0] = char(staleEdit.manifestDigest.at(0) ^ 1);
	auto revokedAssignment = rename;
	revokedAssignment.accounts = { fixture.a.id };
	check("v3 set edits require exact manifest digest, master and live assigned accounts",
		CommitRevocableProfileSetChange(*workspace, staleEdit, rename, fixture.admin, {})
			== ProfileGenerationError::StaleGeneration
		&& CommitRevocableProfileSetChange(*workspace, *next, rename, fixture.set, {})
			== ProfileGenerationError::WrongPassword
		&& CommitRevocableProfileSetChange(*workspace, *next, revokedAssignment, fixture.admin, {})
			== ProfileGenerationError::SettingsRejected
		&& !UpdateCommittedRevocableProfileSets(
			*workspace, *next, fixture.metadata(), fixture.admin, {}, &error)
		&& error == MigrationError::VerificationFailed
		&& workspace->LoadCommitted() && workspace->LoadCommitted()->proof() == *next);
	const auto addedCredential = DerivedCredential{ QByteArray(32, 'v'), QByteArray(32, 'V') };
	const auto rotatedCredential = DerivedCredential{ QByteArray(32, 'w'), QByteArray(32, 'W') };
	const auto add = ProfileSetChange{
		.kind = ProfileSetChangeKind::Add,
		.name = u"Extra"_q,
		.accounts = { fixture.b.id },
	};
	check("v3 insert rejects duplicate passcodes and publishes an overlapping set",
		CommitRevocableProfileSetChange(*workspace, *next, add, fixture.admin, fixture.set)
			== ProfileGenerationError::PasswordInUse
		&& CommitRevocableProfileSetChange(*workspace, *next, add, fixture.admin, addedCredential)
			== ProfileGenerationError::None);
	const auto afterAdd = workspace->LoadCommitted();
	const auto extra = afterAdd
		? AuthenticateCommittedRevocableProfileGeneration(
			*workspace, addedCredential, afterAdd->proof())
		: std::nullopt;
	if (!afterAdd || !extra || !extra->access().setId) {
		return 1;
	}
	check("v3 rename keeps set identity and existing settings key",
		!afterAdd->retirementPending && extra->plan().keyFor(fixture.b.id)
		&& CommitRevocableProfileSetChange(*workspace, afterAdd->proof(), rename, fixture.admin, {})
			== ProfileGenerationError::None);
	const auto afterRename = workspace->LoadCommitted();
	const auto renamed = afterRename
		? AuthenticateCommittedRevocableProfileGeneration(*workspace, fixture.set, afterRename->proof())
		: std::nullopt;
	if (!afterRename || !renamed || !revokedOnlyScope) {
		return 1;
	}
	const auto reassign = ProfileSetChange{
		.kind = ProfileSetChangeKind::Edit,
		.id = fixture.onlyAId,
		.name = u"Reassigned"_q,
		.accounts = { fixture.b.id },
	};
	check("v3 can reassign a live account and rotate one credential",
		legacySet && renamed->access().setId == fixture.setId
		&& renamed->settingsKey() == legacySet->settingsKey
		&& CommitRevocableProfileSetChange(
			*workspace, afterRename->proof(), reassign, fixture.admin, rotatedCredential)
			== ProfileGenerationError::None);
	const auto afterRotation = workspace->LoadCommitted();
	const auto rotated = afterRotation
		? AuthenticateCommittedRevocableProfileGeneration(
			*workspace, rotatedCredential, afterRotation->proof())
		: std::nullopt;
	if (!afterRotation || !rotated) {
		return 1;
	}
	const auto remove = ProfileSetChange{
		.kind = ProfileSetChangeKind::Remove,
		.id = extra->access().setId,
	};
	check("v3 rotation preserves settings and deletion retires the old passcode",
		rotated->plan().keyFor(fixture.b.id)
		&& rotated->settingsKey() == revokedOnlyScope->settingsKey()
		&& !AuthenticateCommittedRevocableProfileGeneration(
			*workspace, fixture.onlyA, afterRotation->proof(), &unlockError)
		&& unlockError == ProfileGenerationError::WrongPassword
		&& CommitRevocableProfileSetChange(
			*workspace, afterRotation->proof(), remove, fixture.admin, {})
			== ProfileGenerationError::None);
	const auto afterEdits = workspace->LoadCommitted();
	if (!afterEdits) {
		return 1;
	}
	const auto editedAdmin = AuthenticateCommittedRevocableProfileGeneration(
		*workspace, fixture.admin, afterEdits->proof());
	check("v3 edits keep the exact gate table and retire the preceding generations",
		gatesBeforeEdits && afterEdits->accountGateTable == gatesBeforeEdits->accountGateTable
		&& !afterEdits->retirementPending
		&& !AuthenticateCommittedRevocableProfileGeneration(
			*workspace, addedCredential, afterEdits->proof(), &unlockError)
		&& unlockError == ProfileGenerationError::WrongPassword
		&& editedAdmin && editedAdmin->adminMetadata()
		&& editedAdmin->adminMetadata()->sets[0].name == u"Renamed"
		&& editedAdmin->adminMetadata()->sets[1].accounts == std::vector{ fixture.b.id }
		&& Read(accountWitness) == "untouched account files");

	const auto afterB = RevokeCommittedRevocableAccounts(*workspace, afterEdits->proof(), permitB);
	if (!afterB || !workspace->RetireRevocableGenerations(*afterB)) {
		return 1;
	}
	const auto afterRevokeMaster = AuthenticateCommittedRevocableProfileGeneration(
		*workspace, fixture.admin, *afterB);
	if (!afterRevokeMaster || !afterRevokeMaster->adminMetadata()) {
		return 1;
	}
	auto edited = *afterRevokeMaster->adminMetadata();
	edited.sets[0].name = u"Empty after both revoked"_q;
	const auto final = UpdateCommittedRevocableProfileSets(
		*workspace, *afterB, edited, fixture.admin, {});
	const auto beforeFinal = GenerationDirectory(*workspace, afterB->transactionId);
	const auto finalGate = final ? QDir(GenerationDirectory(*workspace, final->transactionId))
		.filePath(u"account-gate-table.bin"_q) : QString();
	check("disjoint second revoke survives subsequent master rewrite without importing old gate bytes",
		final && final != afterB
		&& Read(finalGate) == Read(QDir(beforeFinal).filePath(u"account-gate-table.bin"_q))
		&& workspace->RetireRevocableGenerations(*final)
		&& WithCurrentRevocableProfileGeneration(*workspace, *final, [&](const auto &reopened) {
			auto access = reopened.vault.open(fixture.set);
			const auto set = std::get_if<RevocableSetVaultAccess>(&access);
			return set && set->handles().empty()
				&& std::holds_alternative<AccountGateRevoked>(
					OpenAccountGate(reopened.gates, scope->handles()[0]))
				&& std::holds_alternative<AccountGateRevoked>(
					OpenAccountGate(reopened.gates, scope->handles()[1]));
		})
		&& Read(accountWitness) == "untouched account files");

	const auto ready = workspace->LoadCommitted();
	if (!ready) {
		return 1;
	}
	const auto admissionId = MigrationController::NewTransactionId();
	const auto outerCheckpoint = Checkpoint(
		ready->installationId, admissionId, ready->accountGateTable, rules);
	const auto cleanInputs = std::vector<MigrationInput>{
		{ MigrationArtifact::ProfileVault, ready->profileVault },
		{ MigrationArtifact::AccountGateTable, ready->accountGateTable },
		{ MigrationArtifact::RevocableEmergencyRules, rules },
	};
	auto pendingInputs = cleanInputs;
	pendingInputs.push_back({ MigrationArtifact::RevocableEmergencyRecovery, outerCheckpoint });
	const auto replace = [&](const std::vector<MigrationInput> &artifacts) {
		return workspace->ReplaceRevocableCommitted(ready->proof(), ready->installationId,
			artifacts, [](const auto&) { return true; }, &error, admissionId);
	};
	auto noRules = pendingInputs;
	noRules.erase(noRules.begin() + 2);
	auto badRules = pendingInputs;
	badRules[2].encryptedBytes[4] = '1';
	auto badCheckpoint = pendingInputs;
	badCheckpoint[3].encryptedBytes[4] = '2';
	auto oversized = pendingInputs;
	oversized[2].encryptedBytes = QByteArray(4 * 1024 * 1024 + 1, 'x');
	check("v3 rejects missing companion rules, old prefixes and oversized emergency data",
		!replace(noRules) && !replace(badRules)
		&& !replace(badCheckpoint) && !replace(oversized)
		&& workspace->LoadCommitted() && workspace->LoadCommitted()->proof() == ready->proof());
	auto wrongScope = pendingInputs;
	auto &receipt = wrongScope[3].encryptedBytes;
	const auto failsAt = [&](qsizetype offset) {
		const auto original = receipt.at(offset);
		receipt[offset] = char(original ^ 1);
		const auto refused = !replace(wrongScope);
		receipt[offset] = original;
		return refused;
	};
	check("the checkpoint binds installation, candidate transaction, table and rules separately",
		failsAt(5) && failsAt(21) && failsAt(37) && failsAt(69));
	const auto pending = replace(pendingInputs);
	if (!pending) {
		return 1;
	}
	const auto inspectCheckpoint = [&](const CommittedMigration &active) {
		return active.proof() == pending->proof()
			&& active.revocableEmergencyRecovery == outerCheckpoint
			&& active.revocableEmergencyRules == rules
			&& active.emergencyRules.isEmpty() && active.emergencyRecovery.isEmpty();
	};
	check("admission publishes both artifacts and blocks startup immediately",
		inspectCheckpoint(*pending) && pending->retirementPending
		&& MigrationController::ProbeProfileStartup(dataDirectory) == ProfileStartupMode::Committed
		&& !ReadCommittedProfileUnlockParameters(*pending, &unlockError)
		&& unlockError == ProfileGenerationError::EmergencyRecoveryRequired
		&& !WithCurrentRevocableProfileGeneration(*workspace, pending->proof(), verify, &error)
		&& error == MigrationError::RevocableRecoveryRequired
		&& !workspace->PrepareRevocableScopedSettingsDirectory(pending->proof(), fixture.setId));
	check("dedicated recovery waits for retirement and verifies the exact active manifest",
		!workspace->WithCurrentRevocableRecovery(pending->proof(), inspectCheckpoint, &error)
		&& error == MigrationError::RevocableRetirementRequired
		&& workspace->RetireRevocableGenerations(pending->proof())
		&& MigrationController::ProbeProfileStartup(dataDirectory) == ProfileStartupMode::Committed
		&& !workspace->WithCurrentRevocableRecovery(ready->proof(), inspectCheckpoint, &error)
		&& error == MigrationError::StaleGeneration
		&& workspace->WithCurrentRevocableRecovery(pending->proof(), inspectCheckpoint));
	const auto checkpointPath = QDir(GenerationDirectory(*workspace, pending->transactionId))
		.filePath(u"revocable-emergency-recovery.bin"_q);
	auto corrupted = outerCheckpoint;
	corrupted[corrupted.size() - 1] = '!';
	check("on-disk checkpoint tamper rejects reopen without fallback",
		Write(checkpointPath, corrupted) && !workspace->LoadCommitted(&error)
		&& error == MigrationError::ReadbackFailed
		&& Write(checkpointPath, outerCheckpoint)
		&& workspace->WithCurrentRevocableRecovery(pending->proof(), inspectCheckpoint));

	const auto secondId = MigrationController::NewTransactionId();
	auto secondAdmission = pendingInputs;
	secondAdmission[3].encryptedBytes = Checkpoint(
		ready->installationId, secondId, ready->accountGateTable, rules);
	auto changedRules = cleanInputs;
	changedRules[2].encryptedBytes.append('x');
	auto changedVault = cleanInputs;
	changedVault[0].encryptedBytes.append('x');
	check("active recovery blocks second admission and completion cannot alter other artifacts",
		!workspace->ReplaceRevocableCommitted(pending->proof(), ready->installationId,
			secondAdmission, [](const auto&) { return true; }, &error, secondId)
		&& error == MigrationError::RevocableRecoveryRequired
		&& !workspace->ReplaceRevocableCommitted(pending->proof(), ready->installationId,
			changedRules, [](const auto&) { return true; }, &error)
		&& error == MigrationError::RevocableRecoveryRequired
		&& !workspace->ReplaceRevocableCommitted(pending->proof(), ready->installationId,
			changedVault, [](const auto&) { return true; }, &error)
		&& error == MigrationError::RevocableRecoveryRequired
		&& !workspace->ReplaceRevocableCommitted(pending->proof(), ready->installationId,
			cleanInputs, [](const auto&) { return false; }, &error)
		&& error == MigrationError::VerificationFailed);
	const auto completed = workspace->ReplaceRevocableCommitted(
		pending->proof(), ready->installationId, cleanInputs, [&](const auto &candidate) {
			return candidate.profileVault == pending->profileVault
				&& candidate.accountGateTable == pending->accountGateTable
				&& candidate.revocableEmergencyRules == pending->revocableEmergencyRules
				&& candidate.revocableEmergencyRecovery.isEmpty();
		});
	check("verified completion removes only recovery and restores normal startup after retirement",
		completed && workspace->RetireRevocableGenerations(completed->proof())
		&& !workspace->WithCurrentRevocableRecovery(completed->proof(), [](const auto&) { return true; })
		&& AuthenticateCommittedRevocableProfileGeneration(*workspace, fixture.empty, completed->proof())
		&& !UpdateCommittedRevocableProfileSets(*workspace, completed->proof(),
			edited, fixture.admin, {}, &error)
		&& error == MigrationError::VerificationRequired
		&& !RevokeCommittedRevocableAccounts(*workspace, completed->proof(), permitB, &error)
		&& error == MigrationError::VerificationRequired);

	const auto current = workspace->LoadCommitted();
	const auto noRows = AccountGateTable::Create(legacyVault->id);
	if (!current || !noRows) {
		return 1;
	}
	const auto missingRow = workspace->ReplaceRevocableCommitted(
		current->proof(), legacyVault->id, {
			{ MigrationArtifact::ProfileVault, oldVaultBytes },
			{ MigrationArtifact::AccountGateTable, SerializeAccountGateTable(*noRows) },
		}, [](const auto&) { return true; });
	check("a missing row cannot pretend to be a revoked gate",
		missingRow && workspace->RetireRevocableGenerations(missingRow->proof())
		&& !AuthenticateCommittedRevocableProfileGeneration(
			*workspace, fixture.onlyA, missingRow->proof(), &unlockError)
		&& unlockError == ProfileGenerationError::KeyMismatch
		&& !AuthenticateCommittedRevocableProfileGeneration(
			*workspace, fixture.admin, missingRow->proof(), &unlockError)
		&& unlockError == ProfileGenerationError::KeyMismatch
		&& AuthenticateCommittedRevocableProfileGeneration(
			*workspace, fixture.empty, missingRow->proof(), &unlockError));

	const auto freshDirectory = QTemporaryDir();
	const auto freshRoot = QFileInfo(freshDirectory.path()).canonicalFilePath();
	const auto fresh = MigrationController::CreateProfileWorkspace(freshRoot);
	auto freshMetadata = fixture.metadata();
	freshMetadata.sets.resize(1);
	const auto freshVault = SealProfileVault(freshMetadata, { fixture.a, fixture.b },
		{ fixture.locatorA, fixture.locatorB }, fixture.admin, { { fixture.setId, fixture.set } });
	if (!fresh || !freshVault) {
		return 1;
	}
	const auto freshInputs = std::vector<MigrationInput>{
		{ MigrationArtifact::ProfileVault, SerializeProfileVault(*freshVault) },
		{ MigrationArtifact::AccountKeyring, legacyKeyring },
	};
	auto withLegacyRetirement = freshInputs;
	withLegacyRetirement.push_back({ MigrationArtifact::LegacyRetirement, "pending legacy retirement" });
	if (!fresh->Stage(withLegacyRetirement)) {
		return 1;
	}
	const auto unretired = fresh->CommitVerified([](const auto&) { return true; });
	if (!unretired) {
		return 1;
	}
	check("fresh opt-in promotion requires the first exact retirement to finish",
		!PromoteFreshRevocableProfileSetup(*fresh, unretired->proof(),
			fixture.admin, fixture.set, verify, &error)
		&& error == MigrationError::VerificationFailed
		&& fresh->LoadCommitted() && fresh->LoadCommitted()->proof() == unretired->proof());
	const auto freshReady = fresh->ReplaceCommitted(
		unretired->transactionId, freshInputs, [](const auto&) { return true; });
	if (!freshReady || !fresh->RetireInactiveGenerations(freshReady->transactionId)) {
		return 1;
	}
	const auto accountFile = QDir(fresh->accountStorageRoot()).filePath(u"fresh-wallet-witness"_q);
	const auto settingsPath = fresh->PrepareScopedSettingsDirectory(freshReady->transactionId, fixture.setId);
	if (!settingsPath || !Write(accountFile, "verified wallet and account bytes")) {
		return 1;
	}
	const auto settingsFile = QDir(*settingsPath).filePath(u"settings-witness"_q);
	if (!Write(settingsFile, "verified scoped settings bytes")) {
		return 1;
	}
	const auto expectedV2 = OpenProfileVault(*freshVault, fixture.set);
	const auto v2Set = std::get_if<SetVaultAccess>(&expectedV2);
	auto changedProof = freshReady->proof();
	changedProof.manifestDigest[0] = char(changedProof.manifestDigest.at(0) ^ 1);
	check("wrong credentials or stale proof keep the freshly retired v2 usable",
		v2Set && !PromoteFreshRevocableProfileSetup(*fresh, freshReady->proof(),
			fixture.admin, fixture.onlyA, verify, &error)
		&& error == MigrationError::VerificationFailed
		&& !PromoteFreshRevocableProfileSetup(*fresh, changedProof,
			fixture.admin, fixture.set, verify, &error)
		&& error == MigrationError::StaleGeneration
		&& AuthenticateCommittedProfileGeneration(*fresh, {}, fixture.set, {}, {}, {}, {},
			freshReady->transactionId));
	check("failed fresh candidate verification leaves exactly the old v2 active",
		!PromoteFreshRevocableProfileSetup(*fresh, freshReady->proof(),
			fixture.admin, fixture.set, [](const auto&) { return false; }, &error)
		&& error == MigrationError::VerificationFailed
		&& fresh->LoadCommitted() && fresh->LoadCommitted()->proof() == freshReady->proof());

	const auto freshV3 = PromoteFreshRevocableProfileSetup(
		*fresh, freshReady->proof(), fixture.admin, fixture.set, [&](const auto &candidate) {
			return candidate.vault.installationId() == freshVault->id && candidate.gates.size() == 2
				&& Read(accountFile) == "verified wallet and account bytes"
				&& Read(settingsFile) == "verified scoped settings bytes";
		});
	const auto restarted = MigrationController::OpenProfileWorkspace(freshRoot);
	check("an accepted fresh v3 can resume exact retirement on restart",
		freshV3 && restarted
		&& MigrationController::ProbeProfileStartup(freshRoot) == ProfileStartupMode::Committed
		&& restarted->LoadCommitted() && restarted->LoadCommitted()->proof() == *freshV3
		&& !WithCurrentRevocableProfileGeneration(*restarted, *freshV3, verify, &error)
		&& error == MigrationError::RevocableRetirementRequired
		&& restarted->RetireRevocableGenerations(*freshV3));
	const auto freshScope = (freshV3 && restarted)
		? AuthenticateCommittedRevocableProfileGeneration(*restarted, fixture.set, *freshV3)
		: std::nullopt;
	const auto storedV3 = restarted ? restarted->LoadCommitted() : std::nullopt;
	check("fresh setup keeps first SetId, exact storage keys, locators and settings",
		freshScope && v2Set && storedV3 && storedV3->accountKeyring.isEmpty()
		&& freshScope->access().setId == fixture.setId && freshScope->settingsKey() == v2Set->settingsKey
		&& freshScope->plan().keyFor(fixture.a.id) && *freshScope->plan().keyFor(fixture.a.id) == fixture.a
		&& freshScope->plan().targetFor(fixture.a.id)->dataName == AccountVaultDataName(fixture.locatorA)
		&& Read(accountFile) == "verified wallet and account bytes"
		&& Read(settingsFile) == "verified scoped settings bytes"
		&& !QDir(GenerationDirectory(*fresh, freshReady->transactionId)).exists());

	std::printf("%d of %d checks passed.\n", passed, total);
	return (passed == total) ? 0 : 1;
}

} // namespace

int main(int argc, char *argv[]) {
	const auto application = QCoreApplication(argc, argv);
	const auto arguments = application.arguments();
	if (arguments.size() == 3 && arguments[1] == u"--crash-before-publication") {
		return EndAroundPublication(arguments[2], false);
	} else if (arguments.size() == 3 && arguments[1] == u"--crash-after-publication") {
		return EndAroundPublication(arguments[2], true);
	} else if (arguments.size() == 3 && arguments[1] == u"--crash-before-active-manifest") {
		return EndAroundPublication(arguments[2], true, true);
	}
	return RunChecks();
}
