#include <string>
#include <string_view>

#include "FileFinder.h"
#include "gtest/gtest.h"

#define _ITERATOR_DEBUG_LEVEL 2

constexpr std::string_view TEST_DIRECTORY = "../tests/FileFinderTestData";
constexpr size_t FILES_AMOUNT = 2;
constexpr size_t RECURSIVE_FILES_AMOUNT = 3;

using namespace suspicious;

TEST(RegularFileFinderTests, ValidDirectory) {
    ffinder::exceptions::ErrorCodes ec;
    ffinder::RegualarFileFinder rfinder(TEST_DIRECTORY, ec);
    ASSERT_EQ(ec, ffinder::exceptions::ErrorCodes::OK);
}

TEST(RegularFileFinderTests, InvalidDirNotExist) {
    ffinder::exceptions::ErrorCodes ec;
    ffinder::RegualarFileFinder rfinder("asd", ec);
    ASSERT_EQ(ec, ffinder::exceptions::ErrorCodes::NotExist);
}

TEST(RegularFileFinderTests, InvalidDirNotDirectory) {
    ffinder::exceptions::ErrorCodes ec;
    ffinder::RegualarFileFinder rfinder(std::string(TEST_DIRECTORY) + "/some_file1.txt", ec);
    ASSERT_EQ(ec, ffinder::exceptions::ErrorCodes::NotDir);
}

TEST(RegularFileFinderTests, FindFiles) {
    ffinder::exceptions::ErrorCodes ec;
    ffinder::RegualarFileFinder rfinder(TEST_DIRECTORY, ec);
    EXPECT_EQ(ec, ffinder::exceptions::ErrorCodes::OK);
    auto files_list = rfinder.CreateFilesList();
    ASSERT_EQ(files_list.size(), FILES_AMOUNT);

    ffinder::RRegualarFileFinder rrfinder(TEST_DIRECTORY, ec);
    EXPECT_EQ(ec, ffinder::exceptions::ErrorCodes::OK);
    auto rfiles_list = rrfinder.CreateFilesList();
    ASSERT_EQ(rfiles_list.size(), RECURSIVE_FILES_AMOUNT);
}
