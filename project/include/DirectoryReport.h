#ifndef SUSPICIOUSSEARCHUTIL_DIRECTORYREPORT_H
#define SUSPICIOUSSEARCHUTIL_DIRECTORYREPORT_H

#include <unordered_map>
#include <ostream>

#include "Def.h"
#include "FileFinder.h"
#include "SuspiciousEntryStorage.h"

namespace suspicious {
    /**
     * Alias for unordered_map. Contains extension as key and extension label,
     * that would store in report as value. Example {".js", "JS"}, {".exe", "Executable"}, {".dll", "Lib"}
     */
    using Filter = std::unordered_map<StringType, StringType>;

    struct Report {
        using ReportTable = std::unordered_map<StringType, size_t>;

        Report() : processed_files(0), table(), errors(0) {}

        size_t processed_files;
        ReportTable table;
        size_t errors;
    };

    Report
    AnalyzeDirectory(const ffinder::FileList &file_list, const SuspiciousEntryStorage &storage, const Filter &filter);

    std::ostream &operator<<(std::ostream &os, const suspicious::Report &report);
}

#endif //SUSPICIOUSSEARCHUTIL_DIRECTORYREPORT_H
