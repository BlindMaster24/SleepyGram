// This is the source code of AyuGram for Desktop.
#pragma once

#include <cstddef>
#include <filesystem>
#include <memory>
#include <span>

struct sqlite3;

namespace Ayu::ArchiveSqlCipher {

inline constexpr auto kKeySize = size_t(32);
using Key = std::span<const std::byte, kKeySize>;

enum class OpenMode {
	ReadOnly,
	ReadWrite,
	ReadWriteOrCreate,
};

struct CloseConnection final {
	void operator()(sqlite3 *connection) const;
};

using Connection = std::unique_ptr<sqlite3, CloseConnection>;

// SQLCipher needs the key before SQLite reads its first page.
[[nodiscard]] bool Configure(sqlite3 &connection, Key key);

[[nodiscard]] Connection Open(
	const std::filesystem::path &path,
	OpenMode mode,
	Key key);

} // namespace Ayu::ArchiveSqlCipher
