#include <Def.h>

#include <string>
#include <string_view>

#include "Analyzer.h"
#include "FileFinder.h"
#include "gtest/gtest.h"

#define _ITERATOR_DEBUG_LEVEL 2

class ScannerBehaviorTests : public ::testing::Test {
protected:
    static constexpr std::string_view valid_file = "../tests/FileScannerTestData/valid.txt";
};

class ExtensionAnalyzerTests : public ::testing::Test {
protected:
    static constexpr std::string_view valid_file_js = "../tests/FileScannerTestData/valid.js";
    static constexpr std::string_view valid_file_bat = "../tests/FileScannerTestData/valid.bat";
    static constexpr std::string_view valid_file_exe = "../tests/FileScannerTestData/valid.dll";
};

TEST_F(ScannerBehaviorTests, ValidFile) {
    suspicious::ffinder::File file(valid_file);
    suspicious::SuspiciousEntrySequence seq{};
    suspicious::FileScanner scanner(file, seq);
    scanner.ScanFile();
    ASSERT_FALSE(scanner.IsError());
}

TEST_F(ScannerBehaviorTests, IsSuspicious) {
    suspicious::ffinder::File file(valid_file);
    suspicious::SuspiciousEntrySequence seq{"char", "template", "int main("};
    suspicious::FileScanner scanner(file, seq);
    bool verdict = scanner.ScanFile();
    ASSERT_FALSE(scanner.IsError());
    ASSERT_TRUE(verdict);
}

TEST_F(ExtensionAnalyzerTests, JsOpenValid) {
    suspicious::ffinder::File file(valid_file_js);
    suspicious::SuspiciousEntrySequence seq{};
    ASSERT_NO_THROW(suspicious::JsFileScanner(file, seq));
}

TEST_F(ExtensionAnalyzerTests, JsOpenInvalid) {
    suspicious::ffinder::File file(valid_file_bat);
    suspicious::SuspiciousEntrySequence seq{};
    ASSERT_THROW(suspicious::JsFileScanner(file, seq), suspicious::exceptions::FileWrongExtension);
}

TEST_F(ExtensionAnalyzerTests, BatOpenValid) {
    suspicious::ffinder::File file(valid_file_bat);
    suspicious::SuspiciousEntrySequence seq{};
    ASSERT_NO_THROW(suspicious::BatFileScanner(file, seq));
}

TEST_F(ExtensionAnalyzerTests, BatOpenInvalid) {
    suspicious::ffinder::File file(valid_file_js);
    suspicious::SuspiciousEntrySequence seq{};
    ASSERT_THROW(suspicious::BatFileScanner(file, seq), suspicious::exceptions::FileWrongExtension);
}

TEST_F(ExtensionAnalyzerTests, ExeOpenValid) {
    suspicious::ffinder::File file(valid_file_exe);
    suspicious::SuspiciousEntrySequence seq{};
    ASSERT_NO_THROW(suspicious::ExeFileScanner(file, seq));
}

TEST_F(ExtensionAnalyzerTests, ExeOpenInvalid) {
    suspicious::ffinder::File file(valid_file_js);
    suspicious::SuspiciousEntrySequence seq{};
    ASSERT_THROW(suspicious::ExeFileScanner(file, seq), suspicious::exceptions::FileWrongExtension);
}
