#ifndef SUSPICIOUSSEARCHUTIL_ANALYZER_H
#define SUSPICIOUSSEARCHUTIL_ANALYZER_H

#include <fstream>
#include <memory>
#include <exception>
#include <atomic>

#include "FileFinder.hpp"
#include "SuspiciousEntryStorage.h"

namespace suspicious {
    namespace exceptions {
        class FileScannerExceptions : public std::exception {
        public:
            const char * what() const noexcept override {
                return "FileScannerExceptions occur";
            }
        };

        class FileWrongExtension : public FileScannerExceptions {
        public:
            const char * what() const noexcept override {
                return "FileWrongExtension occur";
            }
        };

        class FileAccessError : public FileScannerExceptions {
        public:
            const char * what() const noexcept override {
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
        using FileStream = std::ifstream;
        using FileScannerShPtr = std::shared_ptr<FileScanner>;
        using FileScannerWkPtr = std::weak_ptr<FileScanner>;

        FileScanner(const FileType &file, const SuspEntrySeq &seq) : m_file(file), m_seq(seq) {}

        /**
         * Scans a file and decides if the file is suspicious or not.
         *
         * @return Decision of file suspiciously.
         *
         * @note Deciding that a file is suspicious generally depends on the file type, so the
         * ScanFile implementation depends on the file type. By default ScanFile wrap ScanFileImpl.
         */
        virtual bool ScanFile();

    private:
        FileType m_file;
        SuspEntrySeq m_seq;
        bool m_error_indicator;
        std::atomic_bool m_is_suspicious;
    };
}

#endif //SUSPICIOUSSEARCHUTIL_ANALYZER_H
