#ifndef SUSPICIOUSSEARCHUTIL_DEF_H
#define SUSPICIOUSSEARCHUTIL_DEF_H

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
}

#endif //SUSPICIOUSSEARCHUTIL_DEF_H
