#ifndef PROJECT_INCLUDE_DEF_H_
#define PROJECT_INCLUDE_DEF_H_

#include <filesystem>
#include <string>
#include <unordered_set>

namespace suspicious {
    namespace ffinder {
        using PathType = std::filesystem::path;
    }

    using StringType = std::string;
    using ExtensionType = StringType;
    using SuspiciousEntryType = StringType;
    using SuspiciousEntrySequence = std::unordered_set<SuspiciousEntryType>;
}  // namespace suspicious

#endif  // PROJECT_INCLUDE_DEF_H_
