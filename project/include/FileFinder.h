#ifndef PROJECT_INCLUDE_FILEFINDER_H_
#define PROJECT_INCLUDE_FILEFINDER_H_

#include <Def.h>

#include <exception>
#include <filesystem>
#include <list>
#include <string>
#include <string_view>
#include <system_error>

namespace suspicious::ffinder {
    namespace fs = std::filesystem;
    namespace exceptions {
        class FinderException : std::exception {
         public:
            const char *what() const noexcept override { return "Finder exception occur"; }
        };

        class DirectoryNotFound : FinderException {
         public:
            const char *what() const noexcept override { return "Specified directory not found"; }
        };

        class NotDirectory : FinderException {
         public:
            const char *what() const noexcept override { return "Specified filesystem object is not a directory"; }
        };
    }  // namespace exceptions

    /**
     * File is just convenient file abstraction, that works as wrapper on std::filesystem::path.
     * It provides possibility simply access file extension in case of this program task.
     */
    struct File {
        File() = default;

        explicit File(const PathType &file_path)
            : path(file_path),
              name(path.filename()),
              extension(path.extension()),
              absolute_path(fs::absolute(file_path)),
              file_size(fs::file_size(absolute_path)) {}

        PathType path;
        PathType name;
        PathType extension;
        PathType absolute_path;
        size_t file_size;
    };

    using FileType = File;
    using FileList = std::list<FileType>;

    /**
     * Basic class, that provides an interface for creating classes that return a list of
     * files contained in a directory, with additional custom logic.
     *
     * @tparam Iter type of directory iterator.
     *
     * @note In fact, Iter should be std::filesystem::directory_iterator or
     * std::filesystem::recursive::directory_iterator.
     */
    template <typename Iter>
    class BasicFilesFinder {
     public:
        using IteratorType = Iter;

        BasicFilesFinder() = default;

        explicit BasicFilesFinder(const PathType &dir_name);

        virtual ~BasicFilesFinder() = default;

        /**
         * @return List of paths to files
         *
         * @note CreateFilesList associated with File structure, so it return the list of ones.
         */
        virtual FileList CreateFilesList() const = 0;

     protected:
        PathType m_dir_name;
    };

    template <typename Iter>
    BasicFilesFinder<Iter>::BasicFilesFinder(const PathType &dir_name) : m_dir_name(dir_name) {
        if (!fs::exists(m_dir_name)) {
            throw exceptions::DirectoryNotFound();
        }

        if (!fs::is_directory(m_dir_name)) {
            throw exceptions::NotDirectory();
        }
    }

    /**
     * In fact is BasicFilesFinder for searching only regular files.
     */
    template <typename Iter>
    class RegularBasicFileFinder : public BasicFilesFinder<Iter> {
     public:
        using IteratorType = Iter;
        static constexpr std::string_view DefaultPath = ".";

        RegularBasicFileFinder() : BasicFilesFinder<Iter>(DefaultPath) {}

        explicit RegularBasicFileFinder(const PathType &dir_name) : BasicFilesFinder<Iter>(dir_name) {}

        FileList CreateFilesList() const override;

     private:
        bool IsRegular(const PathType &file) const { return std::filesystem::is_regular_file(file); }
    };

    template <typename Iter>
    FileList RegularBasicFileFinder<Iter>::CreateFilesList() const {
        FileList regular_files_list;
        // Iterate over directory and find all regular files.
        for (const auto &path_entry : IteratorType{BasicFilesFinder<Iter>::m_dir_name}) {
            if (IsRegular(path_entry)) {
                regular_files_list.emplace_back(path_entry);
            }
        }
        return regular_files_list;
    }

    using RegualarFileFinder = RegularBasicFileFinder<fs::directory_iterator>;
    using RRegualarFileFinder = RegularBasicFileFinder<fs::recursive_directory_iterator>;
}  // namespace suspicious::ffinder

#endif  // PROJECT_INCLUDE_FILEFINDER_H_
