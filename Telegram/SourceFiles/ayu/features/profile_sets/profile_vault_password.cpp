/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/profile_vault.h"

#include "ayu/features/profile_sets/profile_generation.h"
#include "ayu/features/profile_sets/profile_emergency.h"
#include "ayu/features/profile_sets/profile_emergency_settings.h"
#include "crl/crl_async.h"
#include "crl/crl_on_main.h"
#include "mtproto/mtproto_auth_key.h"
#include "storage/details/storage_file_utilities.h"

#include <openssl/crypto.h>

#include <utility>

namespace Ayu::ProfileSets {
namespace {

bool ValidUnlockInput(
		const QByteArray &salt,
		KdfParameters parameters,
		const QString &password) {
	return details::ValidProfileVaultSalt(salt)
		&& ValidProfileVaultKdf(parameters)
		&& !password.isEmpty()
		&& password.size() <= 1024;
}

DerivedCredential DeriveCredential(
		const QByteArray &salt,
		KdfParameters parameters,
		QString &password) {
	auto passwordBytes = password.toUtf8();
	password.fill(QChar(0));
	const auto wipe = gsl::finally([&] {
		OPENSSL_cleanse(passwordBytes.data(), passwordBytes.size());
	});
	const auto key = Storage::details::CreatePasscodeKey(
		passwordBytes,
		salt,
		{
			.kind = parameters.kind,
			.memory = parameters.memory,
			.time = parameters.time,
			.parallel = parameters.parallel,
		});
	if (!key) {
		return {};
	}
	const auto material = key->data();
	return details::ProfileVaultCredentialFromKdfOutput(QByteArrayView(
		reinterpret_cast<const char*>(material.data()),
		qsizetype(material.size())));
}

std::optional<OpenedProfileGeneration> AuthenticateScopedOnWorker(
		const MigrationController &sidecar,
		QString &passcode,
		bool fromLockScreen,
		ProfileGenerationError &error) {
	const auto committed = !sidecar.isIsolatedFixture()
		? sidecar.LoadCommitted()
		: std::nullopt;
	if (!committed) {
		error = ProfileGenerationError::InvalidSidecar;
		return std::nullopt;
	}
	const auto parameters = ReadCommittedProfileUnlockParameters(*committed, &error);
	if (!parameters) {
		return std::nullopt;
	}
	if (!ValidUnlockInput(parameters->salt, parameters->kdf, passcode)) {
		error = ProfileGenerationError::WrongPassword;
		return std::nullopt;
	}
	auto derived = DeriveCredential(parameters->salt, parameters->kdf, passcode);
	const auto wipeDerived = gsl::finally([&] {
		OPENSSL_cleanse(derived.verifier.data(), size_t(derived.verifier.size()));
		OPENSSL_cleanse(derived.key.data(), size_t(derived.key.size()));
	});
	if (!derived.valid()) {
		error = ProfileGenerationError::DerivationFailed;
		return std::nullopt;
	}
	auto result = (committed->layout == MigrationGenerationLayout::RevocableGates)
		? AuthenticateCommittedRevocableProfileGeneration(
			sidecar, derived, committed->proof(), &error)
		: AuthenticateCommittedProfileGeneration(
			sidecar, {}, derived, {}, {}, {}, {},
			committed->transactionId, &error);
	if (fromLockScreen && !result && error == ProfileGenerationError::WrongPassword) {
		return SubmitProfileEmergencyOnWorker(sidecar, *committed, derived, error);
	}
	return result;
}

ProfileGenerationError SaveSetOnWorker(
		const MigrationController &sidecar,
		const MigrationGenerationProof &expected,
		const ProfileSetChange &change,
		QString &masterPasscode,
		QString &setPasscode) {
	using Error = ProfileGenerationError;
	const auto wipe = gsl::finally([&] {
		masterPasscode.fill(QChar(0));
		setPasscode.fill(QChar(0));
	});
	const auto committed = !sidecar.isIsolatedFixture()
		? sidecar.LoadCommitted()
		: std::nullopt;
	if (!committed) {
		return Error::InvalidSidecar;
	} else if (committed->transactionId != expected.transactionId) {
		return Error::StaleGeneration;
	}
	const auto revocable = (committed->layout == MigrationGenerationLayout::RevocableGates);
	if ((revocable && committed->proof() != expected)
		|| (!revocable && !expected.manifestDigest.isEmpty())) {
		return Error::StaleGeneration;
	}
	const auto legacy = revocable ? std::nullopt : ParseProfileVault(committed->profileVault);
	auto parameterError = Error::InvalidVault;
	const auto parameters = revocable
		? ReadCommittedProfileUnlockParameters(*committed, &parameterError)
		: (legacy && legacy->version == kProfileVaultVersion)
		? std::optional(ProfileGenerationUnlockParameters{ legacy->salt, legacy->kdf })
		: std::nullopt;
	if (!parameters) {
		return parameterError;
	} else if (!ValidUnlockInput(parameters->salt, parameters->kdf, masterPasscode)) {
		return Error::WrongPassword;
	} else if (!setPasscode.isEmpty()
		&& !ValidUnlockInput(parameters->salt, parameters->kdf, setPasscode)) {
		return Error::SettingsRejected;
	}
	auto master = DeriveCredential(parameters->salt, parameters->kdf, masterPasscode);
	const auto wipeMaster = gsl::finally([&] {
		OPENSSL_cleanse(master.key.data(), master.key.size());
		OPENSSL_cleanse(master.verifier.data(), master.verifier.size());
	});
	if (!master.valid()) {
		return Error::DerivationFailed;
	} else if (legacy && CRYPTO_memcmp(
		master.verifier.constData(),
		legacy->adminVerifier.constData(),
		kVerifierSize)) {
		return Error::WrongPassword;
	}
	auto replacement = std::optional<DerivedCredential>();
	const auto wipeReplacement = gsl::finally([&] {
		if (replacement) {
			OPENSSL_cleanse(replacement->key.data(), replacement->key.size());
			OPENSSL_cleanse(
				replacement->verifier.data(),
				replacement->verifier.size());
		}
	});
	if (!setPasscode.isEmpty()) {
		replacement = DeriveCredential(parameters->salt, parameters->kdf, setPasscode);
		if (!replacement->valid()) {
			return Error::DerivationFailed;
		}
	}
	if (revocable) {
		return CommitRevocableProfileSetChange(
			sidecar, expected, change, std::move(master), std::move(replacement));
	}
	return CommitProfileSetChange(
		sidecar,
		expected.transactionId,
		change,
		std::move(master),
		std::move(replacement),
		RebindProfileEmergencyRulesOnWorker);
}

} // namespace

DerivedCredential details::DeriveProfileVaultCredentialOnWorker(
		const QByteArray &salt,
		KdfParameters parameters,
		QString &password) {
	if (!ValidUnlockInput(salt, parameters, password)) {
		password.fill(QChar(0));
		return {};
	}
	return DeriveCredential(salt, parameters, password);
}

void DeriveProfileVaultCredential(
		QByteArray salt,
		KdfParameters parameters,
		QString password,
		Fn<void(DerivedCredential)> done) {
	if (!ValidUnlockInput(salt, parameters, password)) {
		password.fill(QChar(0));
		done({});
		return;
	}
	crl::async([
			password = std::move(password),
			salt = std::move(salt),
			parameters,
			done = std::move(done)]() mutable {
		auto credential = DeriveCredential(salt, parameters, password);
		crl::on_main([
				credential = std::move(credential),
				done = std::move(done)]() mutable {
			done(std::move(credential));
		});
	});
}

namespace {

void PostScopedAuthentication(
		MigrationController sidecar,
		QString passcode,
		bool fromLockScreen,
		ProfilePasswordDone done) {
	Expects(done != nullptr);

	crl::async([
			sidecar = std::move(sidecar),
			passcode = std::move(passcode),
			fromLockScreen,
			done = std::move(done)]() mutable {
		auto error = ProfileGenerationError::None;
		auto authenticated = AuthenticateScopedOnWorker(sidecar, passcode, fromLockScreen, error);
		passcode.fill(QChar(0));
		crl::on_main([
				authenticated = std::move(authenticated),
				error,
				done = std::move(done)]() mutable {
			done(std::move(authenticated), error);
		});
	});
}

} // namespace

void AuthenticateScopedProfilePasscode(
		MigrationController sidecar,
		QString passcode,
		ProfilePasswordDone done) {
	PostScopedAuthentication(std::move(sidecar), std::move(passcode), false, std::move(done));
}

void SubmitScopedProfileLockPasscode(
		MigrationController sidecar,
		QString passcode,
		ProfilePasswordDone done) {
	PostScopedAuthentication(std::move(sidecar), std::move(passcode), true, std::move(done));
}

void SaveProfileSetChange(
		MigrationController sidecar,
		QByteArray expectedTransactionId,
		ProfileSetChange change,
		QString masterPasscode,
		QString setPasscode,
		Fn<void(ProfileGenerationError)> done) {
	SaveProfileSetChange(
		std::move(sidecar),
		MigrationGenerationProof{ std::move(expectedTransactionId), {} },
		std::move(change),
		std::move(masterPasscode),
		std::move(setPasscode),
		std::move(done));
}

void SaveProfileSetChange(
		MigrationController sidecar,
		MigrationGenerationProof expected,
		ProfileSetChange change,
		QString masterPasscode,
		QString setPasscode,
		Fn<void(ProfileGenerationError)> done) {
	Expects(done != nullptr);

	crl::async([
			sidecar = std::move(sidecar),
			expected = std::move(expected),
			change = std::move(change),
			masterPasscode = std::move(masterPasscode),
			setPasscode = std::move(setPasscode),
			done = std::move(done)]() mutable {
		const auto error = SaveSetOnWorker(
			sidecar,
			expected,
			change,
			masterPasscode,
			setPasscode);
		crl::on_main([error, done = std::move(done)] { done(error); });
	});
}

} // namespace Ayu::ProfileSets
