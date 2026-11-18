/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/bytes.h"

#include <openssl/crypto.h>
#include <openssl/kdf.h>

#include <limits>
#include <memory>

namespace Storage {

[[nodiscard]] inline bool HkdfSha256(
		bytes::const_span input,
		bytes::const_span salt,
		bytes::const_span info,
		bytes::span output) {
	constexpr auto limit = size_t(std::numeric_limits<int>::max());
	if (input.empty() || input.size() > limit || salt.size() > limit
		|| info.size() > limit || output.empty() || output.size() > 255 * 32) {
		return false;
	}
	const auto context = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(
		EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr),
		&EVP_PKEY_CTX_free);
	if (!context) {
		return false;
	}
	const auto asUnsigned = [](bytes::const_span data) {
		return reinterpret_cast<const unsigned char*>(data.data());
	};
	auto length = output.size();
	const auto ctx = context.get();
	const auto ok = (EVP_PKEY_derive_init(ctx) > 0)
		&& (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0)
		&& (salt.empty() || (EVP_PKEY_CTX_set1_hkdf_salt(
			ctx, asUnsigned(salt), int(salt.size())) > 0))
		&& (EVP_PKEY_CTX_set1_hkdf_key(
			ctx, asUnsigned(input), int(input.size())) > 0)
		&& (info.empty() || (EVP_PKEY_CTX_add1_hkdf_info(
			ctx, asUnsigned(info), int(info.size())) > 0))
		&& (EVP_PKEY_derive(
			ctx, reinterpret_cast<unsigned char*>(output.data()), &length) > 0)
		&& (length == output.size());
	if (!ok) {
		OPENSSL_cleanse(output.data(), output.size());
	}
	return ok;
}

} // namespace Storage
