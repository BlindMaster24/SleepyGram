// This is the source code of AyuGram for Desktop.
#pragma once

#include <cstdint>
#include <span>

struct sqlite3;

namespace Ayu {

struct ArchivePartitionTarget final {
	int64_t userId = 0;
	sqlite3 *database = nullptr;
};

enum class ArchivePartitionResult {
	Success,
	InvalidSource,
	InvalidTarget,
	UnassignedRows,
	UnassignedFilters,
	ReadWriteFailed,
};

// Destinations are keyed, private staging databases with the archive schema.
[[nodiscard]] ArchivePartitionResult StageLegacyArchivePartitions(
	sqlite3 &legacy,
	std::span<const ArchivePartitionTarget> targets);

} // namespace Ayu
