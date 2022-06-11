#ifndef SUSPICIOUSSEARCHUTIL_ANALYZER_H
#define SUSPICIOUSSEARCHUTIL_ANALYZER_H

#include <fstream>
#include <filesystem>
#include <memory>
#include <exception>
#include <vector>

#include "FileFinder.h"
#include "SuspiciousEntryStorage.h"

namespace suspicious {
    namespace exceptions {
        class FileScannerExceptions : public std::exception {
        public:
            const char *what() const noexcept override {
                return "FileScannerExceptions occur";
            }
        };

        class FileWrongExtension : public FileScannerExceptions {
        public:
            const char *what() const noexcept override {
                return "FileWrongExtension occur";
            }
        };

        class FileAccessError : public FileScannerExceptions {
        public:
            const char *what() const noexcept override {
                return "FileAccessError occur";
            }
        };
    }

    /**
     * Implements a common interface for a file scanner. The task of the file scanner
     * is to directly scan the file for occurrences of suspicious sequences. This
     * interface contains a general multi-threaded algorithm that allows you to determine
     * whether the contents of a file are suspicious.
     */
    class FileScanner {
    public:
        using FileType = ffinder::FileType;
        using FileScannerShPtr = std::shared_ptr<FileScanner>;
        using FileScannerWkPtr = std::weak_ptr<FileScanner>;

        FileScanner() = delete;

        FileScanner(const FileType &file, const SuspiciousEntrySequence &seq) : m_file(file), m_seq(seq),
                                                                                m_error_indicator(false) {}

        /**
         * Scans a file and decides if the file is suspicious or not.
         *
         * @return Decision is file suspicious or not.
         *
         * @note Deciding that a file is suspicious generally depends on the file type, so the
         * ScanFile implementation depends on the file type. By default ScanFile wrap SearchSuspiciousEntries.
         */
        virtual bool ScanFile() { return SearchSuspiciousEntries(); };

        virtual ~FileScanner() = default;

        bool IsError() const { return m_error_indicator; }

    protected:
        /**
         * The implementation of the algorithm for searching for suspicious lines in a file is in this
         * function. Since, in general, it is rather suboptimal to load a file into memory, since it
         * can be huge, the algorithm works without loading a file into memory. Since streams in C++
         * are rather slow, it was decided to use a multi-threaded version of the algorithm. However,
         * in this case more file descriptors are required.
         *
         * @return Decision is file suspicious or not.
         */
        bool SearchSuspiciousEntries();

        const FileType m_file;
        SuspiciousEntrySequence m_seq;
        bool m_error_indicator;
    };

    class JsFileScanner final : public FileScanner {
    public:
        static constexpr std::string_view extension = ".js";

        JsFileScanner(const FileType &file, const SuspiciousEntrySequence &seq) : FileScanner(file, seq) {
            if (m_file.extension != extension) {
                throw exceptions::FileWrongExtension();
            }
        }
    };

    class BatFileScanner final : public FileScanner {
    public:
        static constexpr std::string_view extension_bat = ".bat";
        static constexpr std::string_view extension_cmd = ".cmd";

        BatFileScanner(const FileType &file, const SuspiciousEntrySequence &seq) : FileScanner(file, seq) {
            if (m_file.extension != extension_bat && m_file.extension != extension_cmd) {
                throw exceptions::FileWrongExtension();
            }
        }
    };

    class ExeFileScanner final : public FileScanner {
    public:
        static constexpr std::string_view extension_exe = ".exe";
        static constexpr std::string_view extension_dll = ".dll";

        ExeFileScanner(const FileType &file, const SuspiciousEntrySequence &seq) : FileScanner(file, seq) {
            if (m_file.extension != extension_exe && m_file.extension != extension_dll) {
                throw exceptions::FileWrongExtension();
            }
        }
    };

    /**
     * The FileAnalyzer class implements a factory method. It has a method for creating a
     * polymorphic file scanner class. The class itself is necessary in order to analyze the
     * file without looking into its contents directly. Content analysis work is delegated
     * to the FileScanner class.
     */
    class FileAnalyzer {
    public:
        using AnalyzerShPtr = std::shared_ptr<FileAnalyzer>;
        using AnalyzerWkPtr = std::weak_ptr<FileAnalyzer>;
        using ScannerShPtr = FileScanner::FileScannerShPtr;
        using ScannerWkPtr = FileScanner::FileScannerWkPtr;
        using FileType = ffinder::File;

        FileAnalyzer(const FileType &file, StorageAccessor &accessor) : m_file(file), m_accessor(accessor),
                                                                        m_error_indicator(false) {}

        /**
         * This function performs a complete analysis on the file.
         * @return Decision if file suspicious.
         */
        virtual bool AnalyzeFile() = 0;

        bool IsError() const { return m_error_indicator; }

        virtual ~FileAnalyzer() = default;

    protected:
        /**
         * Creates file scanned class, specific for instance of analyzer.
         * @return shared pointer to scanner.
         */
        virtual ScannerShPtr CreateScanner() = 0;

        const ffinder::File m_file;
        StorageAccessor &m_accessor;
        bool m_error_indicator;
    };

    class JsFileAnalyzer : public FileAnalyzer {
    public:
        static constexpr std::string_view extension = ".js";

        JsFileAnalyzer(const FileType &file, StorageAccessor &accessor) : FileAnalyzer(file, accessor) {
            if (m_file.extension != extension) {
                throw exceptions::FileWrongExtension();
            }
        }

        bool AnalyzeFile() override;

    protected:
        ScannerShPtr CreateScanner() override;
    };

    class BatFileAnalyzer : public FileAnalyzer {
    public:
        static constexpr std::string_view extension_bat = ".bat";
        static constexpr std::string_view extension_cmd = ".cmd";

        BatFileAnalyzer(const FileType &file, StorageAccessor &accessor) : FileAnalyzer(file, accessor) {
            if (m_file.extension != extension_bat && m_file.extension != extension_cmd) {
                throw exceptions::FileWrongExtension();
            }
        }

        bool AnalyzeFile() override;

    protected:
        ScannerShPtr CreateScanner() override;
    };

    class ExeFileAnalyzer : public FileAnalyzer {
    public:
        static constexpr std::string_view extension_exe = ".exe";
        static constexpr std::string_view extension_dll = ".dll";

        ExeFileAnalyzer(const FileType &file, StorageAccessor &accessor) : FileAnalyzer(file, accessor) {
            if (m_file.extension != extension_exe && m_file.extension != extension_dll) {
                throw exceptions::FileWrongExtension();
            }
        }

        bool AnalyzeFile() override;

    protected:
        ScannerShPtr CreateScanner() override;
    };

    class DefaultFileAnalyzer : public FileAnalyzer {
    public:
        bool AnalyzeFile() override { return false; }

        DefaultFileAnalyzer(const FileType &file, StorageAccessor &accessor) : FileAnalyzer(file, accessor) {}

    protected:
        ScannerShPtr CreateScanner() override { return {}; }
    };

    FileAnalyzer::AnalyzerShPtr CreateAnalyzerByExtension(const ffinder::File &file, StorageAccessor &accessor);
}

#endif //SUSPICIOUSSEARCHUTIL_ANALYZER_H
