#include <string_view>
#include <string>

#include "gtest/gtest.h"

#include <Def.h>
#include "Analyzer.h"
#include "FileFinder.h"

class ScannerBehaviorTests : public ::testing::Test {
protected:
    static constexpr std::string_view valid_file = "../tests/FileScannerTestData/valid.txt";
};

class ExtensionScannerTests : public ::testing::Test {
protected:
    static constexpr std::string_view valid_file_js = "../tests/FileScannerTestData/valid.js";
    static constexpr std::string_view valid_file_bat = "../tests/FileScannerTestData/valid.bat";
    static constexpr std::string_view valid_file_exe = "../tests/FileScannerTestData/valid.exe";
};

TEST_F(ScannerBehaviorTests, ValidFile) {
    suspicious::ffinder::File file(valid_file);
    suspicious::SuspiciousEntrySequence seq {};
    suspicious::FileScanner scanner(file, seq);
    scanner.ScanFile();
    ASSERT_FALSE(scanner.IsError());
}

TEST_F(ScannerBehaviorTests, IsSuspicious) {
    suspicious::ffinder::File file(valid_file);
    suspicious::SuspiciousEntrySequence seq {"char", "template", "int main("};
    suspicious::FileScanner scanner(file, seq);
    bool verdict = scanner.ScanFile();
    ASSERT_FALSE(scanner.IsError());
    ASSERT_TRUE(verdict);
}

TEST_F(ExtensionScannerTests, JsOpenValid) {
    suspicious::ffinder::File file(valid_file_js);
    suspicious::SuspiciousEntrySequence seq {};
    ASSERT_NO_THROW(suspicious::JsFileScanner(file, seq));
}

TEST_F(ExtensionScannerTests, JsOpenInvalid) {
    suspicious::ffinder::File file(valid_file_bat);
    suspicious::SuspiciousEntrySequence seq {};
    ASSERT_THROW(suspicious::JsFileScanner(file, seq), suspicious::exceptions::FileWrongExtension);
}

TEST_F(ExtensionScannerTests, BatOpenValid) {
    suspicious::ffinder::File file(valid_file_bat);
    suspicious::SuspiciousEntrySequence seq {};
    ASSERT_NO_THROW(suspicious::BatFileScanner(file, seq));
}

TEST_F(ExtensionScannerTests, BatOpenInvalid) {
    suspicious::ffinder::File file(valid_file_js);
    suspicious::SuspiciousEntrySequence seq {};
    ASSERT_THROW(suspicious::BatFileScanner(file, seq), suspicious::exceptions::FileWrongExtension);
}

TEST_F(ExtensionScannerTests, ExeOpenValid) {
    suspicious::ffinder::File file(valid_file_exe);
    suspicious::SuspiciousEntrySequence seq {};
    ASSERT_NO_THROW(suspicious::ExeFileScanner(file, seq));
}

TEST_F(ExtensionScannerTests, ExeOpenInvalid) {
    suspicious::ffinder::File file(valid_file_js);
    suspicious::SuspiciousEntrySequence seq {};
    ASSERT_THROW(suspicious::ExeFileScanner(file, seq), suspicious::exceptions::FileWrongExtension);
}
