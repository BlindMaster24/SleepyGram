/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/profile_vault.h"

#include "ayu/features/profile_sets/profile_generation.h"
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
		ProfileGenerationError &error) {
	const auto committed = !sidecar.isIsolatedFixture()
		? sidecar.LoadCommitted()
		: std::nullopt;
	if (!committed) {
		error = ProfileGenerationError::InvalidSidecar;
		return std::nullopt;
	}
	const auto vault = ParseProfileVault(committed->profileVault);
	if (!vault || vault->version != kProfileVaultVersion) {
		error = ProfileGenerationError::InvalidVault;
		return std::nullopt;
	}
	if (!ValidUnlockInput(vault->salt, vault->kdf, passcode)) {
		error = ProfileGenerationError::WrongPassword;
		return std::nullopt;
	}
	auto derived = DeriveCredential(vault->salt, vault->kdf, passcode);
	if (!derived.valid()) {
		error = ProfileGenerationError::DerivationFailed;
		return std::nullopt;
	}
	return AuthenticateCommittedProfileGeneration(
		sidecar, {}, std::move(derived), {}, {}, {}, {},
		committed->transactionId, &error);
}

ProfileGenerationError SaveSetOnWorker(
		const MigrationController &sidecar,
		const QByteArray &expectedTransactionId,
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
	} else if (committed->transactionId != expectedTransactionId) {
		return Error::StaleGeneration;
	}
	const auto vault = ParseProfileVault(committed->profileVault);
	if (!vault || vault->version != kProfileVaultVersion) {
		return Error::InvalidVault;
	} else if (!ValidUnlockInput(vault->salt, vault->kdf, masterPasscode)) {
		return Error::WrongPassword;
	} else if (!setPasscode.isEmpty()
		&& !ValidUnlockInput(vault->salt, vault->kdf, setPasscode)) {
		return Error::SettingsRejected;
	}
	auto master = DeriveCredential(vault->salt, vault->kdf, masterPasscode);
	const auto wipeMaster = gsl::finally([&] {
		OPENSSL_cleanse(master.key.data(), master.key.size());
		OPENSSL_cleanse(master.verifier.data(), master.verifier.size());
	});
	if (!master.valid()) {
		return Error::DerivationFailed;
	} else if (CRYPTO_memcmp(
		master.verifier.constData(),
		vault->adminVerifier.constData(),
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
		replacement = DeriveCredential(vault->salt, vault->kdf, setPasscode);
		if (!replacement->valid()) {
			return Error::DerivationFailed;
		}
	}
	return CommitProfileSetChange(
		sidecar,
		expectedTransactionId,
		change,
		std::move(master),
		std::move(replacement));
}

} // namespace

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

void AuthenticateScopedProfilePasscode(
		MigrationController sidecar,
		QString passcode,
		ProfilePasswordDone done) {
	Expects(done != nullptr);

	crl::async([
			sidecar = std::move(sidecar),
			passcode = std::move(passcode),
			done = std::move(done)]() mutable {
		auto error = ProfileGenerationError::None;
		auto authenticated = AuthenticateScopedOnWorker(sidecar, passcode, error);
		passcode.fill(QChar(0));
		crl::on_main([
				authenticated = std::move(authenticated),
				error,
				done = std::move(done)]() mutable {
			done(std::move(authenticated), error);
		});
	});
}

void SaveProfileSetChange(
		MigrationController sidecar,
		QByteArray expectedTransactionId,
		ProfileSetChange change,
		QString masterPasscode,
		QString setPasscode,
		Fn<void(ProfileGenerationError)> done) {
	Expects(done != nullptr);

	crl::async([
			sidecar = std::move(sidecar),
			expectedTransactionId = std::move(expectedTransactionId),
			change = std::move(change),
			masterPasscode = std::move(masterPasscode),
			setPasscode = std::move(setPasscode),
			done = std::move(done)]() mutable {
		const auto error = SaveSetOnWorker(
			sidecar,
			expectedTransactionId,
			change,
			masterPasscode,
			setPasscode);
		crl::on_main([error, done = std::move(done)] { done(error); });
	});
}

} // namespace Ayu::ProfileSets
