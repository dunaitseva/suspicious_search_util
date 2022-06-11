#include "DirectoryReport.h"

#include "Analyzer.h"

namespace suspicious {
    Report
    AnalyzeDirectory(const ffinder::FileList &file_list, const SuspiciousEntryStorage &storage, const Filter &filter) {
        if (file_list.empty()) {
            return {};
        }

        Report result_report;

        StorageAccessor accessor(storage);
        for (const auto &file: file_list) {
            StringType extension_repr = file.extension.string();
            if (filter.count(extension_repr)) {
                ++result_report.processed_files;
                auto analyzer = CreateAnalyzerByExtension(file, accessor);
                bool verdict = analyzer->AnalyzeFile();
                if (analyzer->IsError()) ++result_report.errors;
                else result_report.table[filter.at(extension_repr)] += static_cast<size_t>(verdict);
            }
        }
        return result_report;
    }

    std::ostream &operator<<(std::ostream &os, const suspicious::Report &report) {
        os << "Processed files: " << report.processed_files << std::endl;
        for (const auto &[label, count]: report.table) {
            os << label << " detects: " << count << std::endl;
        }
        os << "Errors: " << report.errors << std::endl;
        return os;
    }
}