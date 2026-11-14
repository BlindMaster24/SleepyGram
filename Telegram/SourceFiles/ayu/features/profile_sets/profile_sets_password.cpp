#include "ayu/features/profile_sets/profile_sets.h"

#include "crl/crl_async.h"
#include "storage/details/storage_file_utilities.h"

#include <openssl/crypto.h>

#include <QtCore/QCryptographicHash>

#include <memory>

namespace Ayu::ProfileSets {
namespace {

QByteArray ComputeVerifier(
		const QByteArray &password,
		const QByteArray &salt,
		KdfParameters parameters) {
	const auto kdf = Storage::details::PasscodeKdf{
		.kind = parameters.kind,
		.memory = parameters.memory,
		.time = parameters.time,
		.parallel = parameters.parallel,
	};
	if (password.isEmpty() || !kdf.valid() || !kdf.costWithinLimits()) {
		return QByteArray();
	}
	const auto key = Storage::details::CreatePasscodeKey(password, salt, kdf);
	if (!key) {
		return QByteArray();
	}
	const auto data = key->data();
	constexpr auto kContext = "SleepyGram account-set credential v1";
	auto hash = QCryptographicHash(QCryptographicHash::Sha256);
	hash.addData(kContext, sizeof(kContext) - 1);
	hash.addData(
		reinterpret_cast<const char*>(data.data()),
		data.size());
	return hash.result();
}

} // namespace

void DerivePasswordVerifier(
		const Metadata &metadata,
		QString password,
		Fn<void(QByteArray)> done) {
	if (Validate(metadata) != ValidationError::None
		|| password.isEmpty()
		|| password.size() > 1024) {
		password.fill(QChar(0));
		done(QByteArray());
		return;
	}
	auto passwordBytes = password.toUtf8();
	password.fill(QChar(0));
	if (passwordBytes.size() > 4096) {
		OPENSSL_cleanse(passwordBytes.data(), passwordBytes.size());
		done(QByteArray());
		return;
	}
	const auto salt = metadata.verifierSalt;
	const auto parameters = metadata.verifierKdf;
	crl::async([
			passwordBytes = std::move(passwordBytes),
			salt,
			parameters,
			done = std::move(done)]() mutable {
		const auto verifier = ComputeVerifier(passwordBytes, salt, parameters);
		if (!passwordBytes.isEmpty()) {
			OPENSSL_cleanse(passwordBytes.data(), passwordBytes.size());
		}
		crl::on_main([verifier, done = std::move(done)]() mutable {
			done(verifier);
		});
	});
}

void RoutePassword(
		Metadata metadata,
		QString password,
		Fn<void(PasswordRoute)> done) {
	if (Validate(metadata) != ValidationError::None) {
		password.fill(QChar(0));
		done(WrongPassword());
		return;
	}
	const auto routeMetadata = std::make_shared<Metadata>(std::move(metadata));
	DerivePasswordVerifier(
		*routeMetadata,
		std::move(password),
		[routeMetadata, done = std::move(done)](
				QByteArray verifier) mutable {
			done(RoutePasswordVerifier(*routeMetadata, verifier));
		});
}

} // namespace Ayu::ProfileSets
