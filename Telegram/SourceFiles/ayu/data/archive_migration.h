// This is the source code of AyuGram for Desktop.
#pragma once

#include "ayu/data/archive_partition.h"
#include "ayu/data/archive_sqlcipher.h"

#include <string>

namespace Ayu {

struct LegacyArchiveFileTarget final {
	int64_t userId = 0;
	std::string locator;
	ArchiveSqlCipher::Key key;
};

// The caller holds the workspace lease and has authenticated the account locators.
[[nodiscard]] ArchivePartitionResult StageLegacyArchiveFiles(
	const std::filesystem::path &dataDirectory,
	std::span<const LegacyArchiveFileTarget> targets,
	const std::string &schemaSql);

[[nodiscard]] ArchiveSqlCipher::Connection OpenVerifiedScopedArchive(
	const std::filesystem::path &path,
	int64_t userId,
	ArchiveSqlCipher::Key key,
	const std::string &schemaSql);

} // namespace Ayu
