#include <filesystem>
#include <fstream>
#include <sstream>
#include <string_view>

#include "Match.h"
#include "gtest/gtest.h"


class KMPTests : public ::testing::Test {
protected:
    static constexpr std::string_view file_name = "../tests/KMPTestData/big.txt";
    size_t file_size = std::filesystem::file_size(file_name);
    // Strigng 964
    static constexpr std::string_view file_pattern_valid1 = "##!!some text pattern with ws!!##";
    // String 123
    static constexpr std::string_view file_pattern_valid2 = "SymbolsAnd123123";

    static constexpr std::string_view pattern_valid = "SomeTextIntBegOrEnd";
    std::string text_with_beg_entry = "SomeTextIntBegOrEnd here is not a pattern";
    std::string text_with_end_entry = " here is not a pattern SomeTextIntBegOrEnd";
    std::ifstream fs;
    std::stringstream ss_beg_entry;
    std::stringstream ss_end_entry;

    void SetUp() {
        fs.open(file_name.data());
        ss_beg_entry = std::stringstream(text_with_beg_entry);
        ss_end_entry = std::stringstream(text_with_end_entry);
    }
};

TEST_F(KMPTests, EmptyText) { ASSERT_FALSE(suspicious::algorithm::KMPFindMatch(fs, 0, "pattern")); }

TEST_F(KMPTests, EmptyPattern) { ASSERT_FALSE(suspicious::algorithm::KMPFindMatch(fs, 123, "")); }

TEST_F(KMPTests, PatternValidWithWhiteSpaces) {
    ASSERT_TRUE(fs.is_open());
    ASSERT_TRUE(suspicious::algorithm::KMPFindMatch(fs, file_size, std::string(file_pattern_valid1)));
}

TEST_F(KMPTests, PatternValidWithSymbolsAndDigits) {
    ASSERT_TRUE(fs.is_open());
    ASSERT_TRUE(suspicious::algorithm::KMPFindMatch(fs, file_size, std::string(file_pattern_valid2)));
}

TEST_F(KMPTests, PatternInvalid) {
    ASSERT_TRUE(fs.is_open());
    ASSERT_FALSE(suspicious::algorithm::KMPFindMatch(fs, file_size, "%%^%%1%%^1&&-+123"));
}

TEST_F(KMPTests, PatternValidBegEntry) {
    ASSERT_TRUE(fs.is_open());
    ASSERT_TRUE(
        suspicious::algorithm::KMPFindMatch(ss_beg_entry, text_with_beg_entry.size(), std::string(pattern_valid)));
}

TEST_F(KMPTests, PatternValidEndEntry) {
    ASSERT_TRUE(fs.is_open());
    ASSERT_TRUE(
        suspicious::algorithm::KMPFindMatch(ss_end_entry, text_with_end_entry.size(), std::string(pattern_valid)));
}