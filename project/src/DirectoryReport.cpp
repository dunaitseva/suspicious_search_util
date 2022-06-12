#include "DirectoryReport.h"

#include <algorithm>
#include <sstream>

#include "Analyzer.h"

namespace suspicious {
    Report AnalyzeDirectory(const ffinder::FileList &file_list, const SuspiciousEntryStorage &storage,
                            const Filter &filter) {
        if (file_list.empty()) {
            return {};
        }

        Report result_report;

        // Copy labels to report table
        std::for_each(filter.begin(), filter.end(),
                      [&result_report](auto &pair) { result_report.table.insert_or_assign(pair.second, 0); });

        StorageAccessor accessor(storage);
        for (const auto &file : file_list) {
            StringType extension_repr = file.extension.string();
            if (filter.count(extension_repr)) {
                ++result_report.processed_files;
                auto analyzer = CreateAnalyzerByExtension(file, accessor);
                bool verdict = analyzer->AnalyzeFile();
                if (analyzer->IsError())
                    ++result_report.errors;
                else
                    result_report.table[filter.at(extension_repr)] += static_cast<size_t>(verdict);
            }
        }
        return result_report;
    }

    std::ostream &operator<<(std::ostream &os, const suspicious::Report &report) {
        os << "Processed files: " << report.processed_files << std::endl;
        for (const auto &[label, count] : report.table) {
            os << label << " detects: " << count << std::endl;
        }
        os << "Errors: " << report.errors;
        return os;
    }

    TimePoint GetTimePoint() { return std::chrono::steady_clock::now(); }

    StringType GetFormattedTime(Duration dur) {
        using Hours = std::chrono::hours;
        using Minutes = std::chrono::minutes;
        using Seconds = std::chrono::seconds;
        std::ostringstream ss;
        ss << std::chrono::duration_cast<Hours>(dur).count() << ':' << std::chrono::duration_cast<Minutes>(dur).count()
           << ':' << std::chrono::duration_cast<Seconds>(dur).count();
        return ss.str();
    }
}  // namespace suspicious