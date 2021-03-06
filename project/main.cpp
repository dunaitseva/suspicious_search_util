#include <fstream>
#include <iostream>
#include <system_error>

#include "DirectoryReport.h"
#include "FileFinder.h"
#include "SuspiciousEntryStorage.h"

constexpr std::string_view open_report = "====== Scan result ======";
constexpr std::string_view close_report = "=========================";

constexpr size_t EXPECTED_ARGS_AMOUNT = 2;
constexpr size_t PATH_TO_DIRECTORY_ARG = 1;

void WriteUsage(std::ostream &os) {
    static constexpr std::string_view usage =
        "Usage:"
        "Use only one argument - path to directory.";
    os << usage;
}

/*
 * Since only a limited number of lines that are considered suspicious are used in
 * the context of this task, their loading to storage is moved to a function.
 */
void LoadStorage(suspicious::SuspiciousEntryStorage &storage) {
    storage.Add(".js", "<script>evil_script()</script>");
    storage.Add(".cmd", "rd /s /q \"c:\\windows\"");
    storage.Add(".bat", "rd /s /q \"c:\\windows\"");
    storage.Add(".exe", "CreateRemoteThread");
    storage.Add(".dll", "CreateRemoteThread");
    storage.Add(".exe", "CreateProcess");
    storage.Add(".dll", "CreateProcess");
}

int main(int argc, char *argv[]) {
    if (argc != EXPECTED_ARGS_AMOUNT) {
        std::cerr << "Too few arguments";
        WriteUsage(std::cout);
        return EXIT_FAILURE;
    }

    suspicious::ffinder::RRegualarFileFinder finder(argv[PATH_TO_DIRECTORY_ARG]);

    // A constant filter is used, since in the context of this task it is not necessary to
    // change the types of files that the program should analyze
    const suspicious::Filter filter = {
        {".js", "JS"}, {".cmd", "CMD"}, {".bat", "CMD"}, {".exe", "EXE"}, {".dll", "EXE"},
    };

    auto start = suspicious::GetTimePoint();
    suspicious::ffinder::FileList files_list = finder.CreateFilesList();
    suspicious::LightSuspiciousStorage storage;
    LoadStorage(storage);

    auto report = suspicious::AnalyzeDirectory(files_list, storage, filter);
    auto end = suspicious::GetTimePoint();

    std::cout << open_report << std::endl;
    std::cout << report << std::endl;
    std::cout << suspicious::GetFormattedTime(end - start) << std::endl;
    std::cout << close_report << std::endl;
    return EXIT_SUCCESS;
}
