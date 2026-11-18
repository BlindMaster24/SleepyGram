/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ayu/features/profile_sets/profile_vault.h"

#include "crl/crl_async.h"
#include "mtproto/mtproto_auth_key.h"
#include "storage/details/storage_file_utilities.h"

#include <openssl/crypto.h>

#include <utility>

namespace Ayu::ProfileSets {

void DeriveProfileVaultCredential(
		QByteArray salt,
		KdfParameters parameters,
		QString password,
		Fn<void(DerivedCredential)> done) {
	if (!details::ValidProfileVaultSalt(salt) || !ValidProfileVaultKdf(parameters)
		|| password.isEmpty() || password.size() > 1024) {
		password.fill(QChar(0));
		done({});
		return;
	}
	auto passwordBytes = password.toUtf8();
	password.fill(QChar(0));
	if (passwordBytes.size() > 4096) {
		OPENSSL_cleanse(passwordBytes.data(), passwordBytes.size());
		done({});
		return;
	}
	crl::async([
			passwordBytes = std::move(passwordBytes),
			salt = std::move(salt),
			parameters,
			done = std::move(done)]() mutable {
		auto credential = DerivedCredential();
		const auto kdf = Storage::details::PasscodeKdf{
			.kind = parameters.kind,
			.memory = parameters.memory,
			.time = parameters.time,
			.parallel = parameters.parallel,
		};
		const auto key = Storage::details::CreatePasscodeKey(
			passwordBytes,
			salt,
			kdf);
		if (key) {
			const auto material = key->data();
			credential = details::ProfileVaultCredentialFromKdfOutput(
				QByteArrayView(
					reinterpret_cast<const char*>(material.data()),
					qsizetype(material.size())));
		}
		if (!passwordBytes.isEmpty()) {
			OPENSSL_cleanse(passwordBytes.data(), passwordBytes.size());
		}
		crl::on_main([
				credential = std::move(credential),
				done = std::move(done)]() mutable {
			done(std::move(credential));
		});
	});
}

} // namespace Ayu::ProfileSets
