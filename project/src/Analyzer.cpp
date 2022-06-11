#include "Analyzer.h"

#include <filesystem>
#include <thread>
#include <iostream>

#include "Match.h"
#include "Def.h"
#include "FileFinder.h"

namespace suspicious {
    using FileStreamType = std::ifstream;
    using ThreadType = std::jthread;
    using ThreadsPoolType = std::vector<ThreadType>;
    using StreamPoolType = std::vector<FileStreamType>;

    static void
    SearchRoutine(FileStreamType &fs, size_t seek, size_t chunk_size, const SuspiciousEntrySequence &seq,
                  bool &decision) {
        // Just run KMP algorithm for all suspicious entries in seq
        for (const auto &susp_entry: seq) {
            fs.seekg(seek, std::ios_base::beg);
            if (algorithm::KMPFindMatch(fs, chunk_size + susp_entry.size(), susp_entry)) {
                // If match was found, return from function
                decision = true;
                return;
            }
        }
    }

    bool FileScanner::SearchSuspiciousEntries() {
        // Calculate max thread, that we can use
        size_t max_threads = ThreadType::hardware_concurrency();
        StreamPoolType stream_pool{max_threads};
        ThreadsPoolType threads_pool{max_threads};

        size_t chunk_size = m_file.file_size / max_threads;
        bool decision = false;
        for (size_t i = 0; i < max_threads; ++i) {
            // Open file for every thread
            stream_pool[i].open(m_file.absolute_path, std::ios::in | std::ios::binary);
            if (!stream_pool[i].is_open()) {
                // Return from function and set error flag if
                // file was not open
                m_error_indicator = true;
                break;
            }

            // Calculates seek in file for every thread
            size_t seek = chunk_size * i;
            threads_pool[i] = ThreadType(SearchRoutine, std::ref(stream_pool[i]), seek, chunk_size, std::ref(m_seq),
                                         std::ref(decision));
        }

        // Join the threads so that the decision value is valid,
        // and the thread destructors complete without errors
        for (auto &thread: threads_pool) {
            thread.join();
        }

        return decision;
    }

    bool JsFileAnalyzer::AnalyzeFile() {
        JsFileAnalyzer::ScannerShPtr scanner = CreateScanner();
        bool verdict = scanner->ScanFile();
        m_error_indicator = scanner->IsError();
        return verdict;
    }

    JsFileAnalyzer::ScannerShPtr JsFileAnalyzer::CreateScanner() {
        return std::make_unique<JsFileScanner>(m_file,
                                               m_accessor.GetSuspiciousSequence(JsFileScanner::extension.data()));
    }

    bool BatFileAnalyzer::AnalyzeFile() {
        JsFileAnalyzer::ScannerShPtr scanner = CreateScanner();
        bool verdict = scanner->ScanFile();
        m_error_indicator = scanner->IsError();
        return verdict;
    }

    BatFileAnalyzer::ScannerShPtr BatFileAnalyzer::CreateScanner() {
        return std::make_unique<BatFileScanner>(m_file,
                                               m_accessor.GetSuspiciousSequence(JsFileScanner::extension.data()));
    }

    bool ExeFileAnalyzer::AnalyzeFile() {
        ExeFileAnalyzer::ScannerShPtr scanner = CreateScanner();
        bool verdict = scanner->ScanFile();
        m_error_indicator = scanner->IsError();
        return verdict;
    }

    ExeFileAnalyzer::ScannerShPtr ExeFileAnalyzer::CreateScanner() {
        return std::make_unique<ExeFileScanner>(m_file,
                                               m_accessor.GetSuspiciousSequence(JsFileScanner::extension.data()));
    }

    FileAnalyzer::AnalyzerShPtr CreateAnalyzerByExtension(const ffinder::File &file, StorageAccessor &accessor) {
        if (file.extension == JsFileAnalyzer::extension) {
            return std::make_unique<JsFileAnalyzer>(file, accessor);
        }

        if (file.extension == BatFileAnalyzer::extension_bat || file.extension == BatFileAnalyzer::extension_cmd) {
            return std::make_unique<BatFileAnalyzer>(file, accessor);
        }

        if (file.extension == ExeFileAnalyzer::extension_dll || file.extension == ExeFileAnalyzer::extension_exe) {
            return std::make_unique<ExeFileAnalyzer>(file, accessor);
        }

        return std::make_unique<DefaultFileAnalyzer>(file, accessor);
    }

}