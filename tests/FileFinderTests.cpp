#include <string>
#include <string_view>

#include "FileFinder.h"
#include "gtest/gtest.h"

constexpr std::string_view TEST_DIRECTORY = "../tests/FileFinderTestData";
constexpr size_t FILES_AMOUNT = 2;
constexpr size_t RECURSIVE_FILES_AMOUNT = 2;

TEST(RegularFileFinderTests, ValidDirectory) {
    suspicious::ffinder::exceptions::ErrorCodes ec;
    suspicious::ffinder::RegualarFileFinder rfinder(TEST_DIRECTORY, ec);
    ASSERT_EQ(ec, suspicious::ffinder::exceptions::ErrorCodes::OK);
}

TEST(RegularFileFinderTests, InvalidDirNotExist) {
    suspicious::ffinder::exceptions::ErrorCodes ec;
    suspicious::ffinder::RegualarFileFinder rfinder("asd", ec);
    ASSERT_EQ(ec, suspicious::ffinder::exceptions::ErrorCodes::NotExist);
}

TEST(RegularFileFinderTests, InvalidDirNotDirectory) {
    suspicious::ffinder::exceptions::ErrorCodes ec;
    suspicious::ffinder::RegualarFileFinder rfinder(std::string(TEST_DIRECTORY) + "/some_file1.txt", ec);
    ASSERT_EQ(ec, suspicious::ffinder::exceptions::ErrorCodes::NotDir);
}

TEST(RegularFileFinderTests, FindFiles) {
    suspicious::ffinder::exceptions::ErrorCodes ec;
    suspicious::ffinder::RegualarFileFinder rfinder(TEST_DIRECTORY, ec);
    EXPECT_EQ(ec, suspicious::ffinder::exceptions::ErrorCodes::OK);
    auto files_list = rfinder.CreateFilesList();
    ASSERT_EQ(files_list.size(), FILES_AMOUNT);

    suspicious::ffinder::RRegualarFileFinder rrfinder(TEST_DIRECTORY, ec);
    EXPECT_EQ(ec, suspicious::ffinder::exceptions::ErrorCodes::OK);
    auto rfiles_list = rrfinder.CreateFilesList();
    ASSERT_EQ(rfiles_list.size(), RECURSIVE_FILES_AMOUNT);
}
