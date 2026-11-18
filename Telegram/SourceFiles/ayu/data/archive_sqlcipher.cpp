// This is the source code of AyuGram for Desktop.
#include "ayu/data/archive_sqlcipher.h"

#include "ayu/libs/sqlite/sqlite3.h"

#include <algorithm>
#include <array>
#include <openssl/crypto.h>

namespace Ayu::ArchiveSqlCipher {
namespace {

bool ValidKey(Key key) {
	return std::ranges::any_of(key, [](std::byte value) {
		return value != std::byte(0);
	});
}

bool CipherActive(sqlite3 &connection) {
	auto statement = static_cast<sqlite3_stmt*>(nullptr);
	const auto prepared = sqlite3_prepare_v2(
		&connection,
		"PRAGMA cipher_status",
		-1,
		&statement,
		nullptr);
	const auto rows = std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>(
		statement,
		&sqlite3_finalize);
	return prepared == SQLITE_OK
		&& sqlite3_step(rows.get()) == SQLITE_ROW
		&& sqlite3_column_int(rows.get(), 0) == 1;
}

bool ApplyKey(sqlite3 &connection, Key key) {
	constexpr auto kHex = "0123456789abcdef";
	auto raw = std::array<char, 2 * kKeySize + 3>();
	raw[0] = 'x';
	raw[1] = '\'';
	for (auto i = size_t(0); i != key.size(); ++i) {
		const auto value = std::to_integer<unsigned int>(key[i]);
		raw[2 * i + 2] = kHex[value >> 4];
		raw[2 * i + 3] = kHex[value & 0x0F];
	}
	raw.back() = '\'';
	const auto result = sqlite3_key_v2(&connection, "main", raw.data(), int(raw.size()));
	OPENSSL_cleanse(raw.data(), raw.size());
	return result == SQLITE_OK;
}

int AccessFlags(OpenMode mode) {
	switch (mode) {
	case OpenMode::ReadOnly: return SQLITE_OPEN_READONLY;
	case OpenMode::ReadWrite: return SQLITE_OPEN_READWRITE;
	case OpenMode::ReadWriteOrCreate: return SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
	}
	return 0;
}

} // namespace

void CloseConnection::operator()(sqlite3 *connection) const {
	sqlite3_close_v2(connection);
}

bool Configure(sqlite3 &connection, Key key) {
	return sqlite3_compileoption_used("TEMP_STORE=3")
		&& ValidKey(key)
		&& ApplyKey(connection, key)
		&& CipherActive(connection)
		&& sqlite3_exec(
			&connection,
			"SELECT count(*) FROM sqlite_master; PRAGMA mmap_size=0;",
			nullptr,
			nullptr,
			nullptr) == SQLITE_OK;
}

Connection Open(const std::filesystem::path &path, OpenMode mode, Key key) {
	const auto access = AccessFlags(mode);
	if (!access || !path.is_absolute() || !path.has_filename() || !ValidKey(key)) {
		return nullptr;
	}
	const auto filename = path.u8string();
	if (filename.find(char8_t(0)) != std::u8string::npos) {
		return nullptr;
	}
	const auto flags = access
		| SQLITE_OPEN_NOFOLLOW | SQLITE_OPEN_PRIVATECACHE | SQLITE_OPEN_FULLMUTEX;
	auto opened = static_cast<sqlite3*>(nullptr);
	const auto result = sqlite3_open_v2(
		reinterpret_cast<const char*>(filename.c_str()),
		&opened,
		flags,
		nullptr);
	auto connection = Connection(opened);
	if (result != SQLITE_OK || !connection || !Configure(*connection, key)) {
		return nullptr;
	}
	return connection;
}

} // namespace Ayu::ArchiveSqlCipher
