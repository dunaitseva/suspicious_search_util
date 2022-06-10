#ifndef SUSPICIOUSSEARCHENGINE_DIRECTORYOBERVER_H
#define SUSPICIOUSSEARCHENGINE_DIRECTORYOBERVER_H

#include <filesystem>
#include <string>
#include <string_view>
#include <list>
#include <iostream>

namespace ffinder {
    namespace fs = std::filesystem;

    /**
     * File is just convenient file abstraction, that works as wrapper on std::filesystem::path.
     * It provides possibility simply access file extension in case of this program task.
     */
    struct File {
        using PathType = fs::path;

        File() = default;

        explicit File(const PathType &file_path) : path(file_path), absolute_path(fs::absolute(file_path)),
                                                   name(path.filename()), extension(path.extension()) {}

        PathType path;
        PathType absolute_path;
        PathType name;
        PathType extension;
    };

    /**
     * Basic class, that provides an interface for creating classes that return a list of
     * files contained in a directory, with additional custom logic.
     *
     * @tparam Iter type of directory iterator.
     *
     * @note In fact, Iter should be std::filesystem::directory_iterator or
     * std::filesystem::recursive::directory_iterator.
     */
    template<typename Iter>
    class BasicFilesFinder {
    public:
        using IteratorType = Iter;
        using FileType = File;
        using PathType = FileType::PathType;
        using FileList = std::list<FileType>;

        BasicFilesFinder() = default;

        explicit BasicFilesFinder(const PathType &dir_name) : m_dir_name(dir_name) {}

        virtual ~BasicFilesFinder() = default;

        /**
         * @return List of paths to files
         *
         * @note CreateFilesList associated with File structure, so it return the list of ones.
         */
        virtual FileList CreateFilesList() = 0;

    protected:
        PathType m_dir_name;
    };

    /**
     * In fact is BasicFilesFinder for searching only regular files.
     */
    template<typename Iter>
    class RegularBasicFileFinder : public BasicFilesFinder<Iter> {
    public:
        using IteratorType = Iter;
        using PathType = typename BasicFilesFinder<Iter>::PathType;
        using FileList = typename BasicFilesFinder<Iter>::FileList;
        static constexpr std::string_view DefaultPath = ".";

        RegularBasicFileFinder() : BasicFilesFinder<Iter>(DefaultPath) {}

        explicit RegularBasicFileFinder(const PathType &dir_name) : BasicFilesFinder<Iter>(dir_name) {}

        FileList CreateFilesList() override;

    private:

        bool IsRegular(const PathType &file) const { return std::filesystem::is_regular_file(file); }
    };

    template<typename Iter>
    typename RegularBasicFileFinder<Iter>::FileList RegularBasicFileFinder<Iter>::CreateFilesList() {
        FileList regular_files_list;
        // Iterate over directory and find all regular files.
        for (const auto &path_entry: IteratorType{BasicFilesFinder<Iter>::m_dir_name}) {
            if (IsRegular(path_entry)) {
                regular_files_list.emplace_back(path_entry);
            }
        }
        return regular_files_list;
    }

    using RegualrFileFinder = RegularBasicFileFinder<fs::directory_iterator>;
    using RRegualrFileFinder = RegularBasicFileFinder<fs::recursive_directory_iterator>;
}


#endif // SUSPICIOUSSEARCHENGINE_DIRECTORYOBERVER_H
