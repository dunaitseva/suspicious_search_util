#include <iostream>
#include <exception>

#include "FileFinder.hpp"

int main() {
    ffinder::exceptions::ErrorCodes ec;
    ffinder::RRegualrFileFinder finder("../tests/FileFinderTestData", ec);
    if (ec != ffinder::exceptions::ErrorCodes::OK) {
        return EXIT_FAILURE;
    }
    for (const auto &i: finder.CreateFilesList()) {
        std::cout << i.absolute_path << " " << i.extension << std::endl;
    }
    return EXIT_SUCCESS;
}