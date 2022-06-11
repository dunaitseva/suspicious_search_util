#ifndef SUSPICIOUSSEARCHUTIL_ANALYZER_H
#define SUSPICIOUSSEARCHUTIL_ANALYZER_H

#include <fstream>
#include <memory>
#include <exception>
#include <vector>

#include "FileFinder.hpp"
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
        using FileType = ffinder::File;
        using SuspEntrySeq = suspicious::SuspiciousEntryStorage::SuspiciousEntrySequence;
//        using FileScannerShPtr = std::shared_ptr<FileScanner>;
//        using FileScannerWkPtr = std::weak_ptr<FileScanner>;

        FileScanner() = delete;

        FileScanner(const FileType &file, const SuspEntrySeq &seq) : m_file(file), m_seq(seq),
                                                                     m_error_indicator(false) {}

        /**
         * Scans a file and decides if the file is suspicious or not.
         *
         * @return Decision of file suspiciously.
         *
         * @note Deciding that a file is suspicious generally depends on the file type, so the
         * ScanFile implementation depends on the file type. By default ScanFile wrap ScanFileImpl.
         */
        virtual bool ScanFile() = 0;

        virtual ~FileScanner() = default;

        bool IsError() const { return m_error_indicator; }

    protected:
        FileType m_file;
        SuspEntrySeq m_seq;
        bool m_error_indicator;

        /**
         * The implementation of the algorithm for searching for suspicious lines in a file is in this
         * function. Since, in general, it is rather suboptimal to load a file into memory, since it
         * can be huge, the algorithm works without loading a file into memory. Since streams in C++
         * are rather slow, it was decided to use a multi-threaded version of the algorithm. However,
         * in this case more file descriptors are required.
         *
         * @return
         */
        bool SearchSuspiciousEntries();
    };

    class JsFileScanner : public FileScanner {
    public:
        JsFileScanner(const FileType &file, const SuspEntrySeq &seq) : FileScanner(file, seq) {}

        bool ScanFile() override {
            return SearchSuspiciousEntries();
        }
    };

    class BatFileScanner : public FileScanner {
    public:
        BatFileScanner(const FileType &file, const SuspEntrySeq &seq) : FileScanner(file, seq) {}

        bool ScanFile() override {
            return SearchSuspiciousEntries();
        }
    };

    class ExeFileScanner : public FileScanner {
    public:
        ExeFileScanner(const FileType &file, const SuspEntrySeq &seq) : FileScanner(file, seq) {}

        bool ScanFile() override {
            return SearchSuspiciousEntries();
        }
    };
}

#endif //SUSPICIOUSSEARCHUTIL_ANALYZER_H
