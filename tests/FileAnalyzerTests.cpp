#include <string_view>
#include <string>

#include "gtest/gtest.h"

#include "Analyzer.h"
#include "FileFinder.h"
#include "SuspiciousEntryStorage.h"

class ExtensionScannerTests : public ::testing::Test {
protected:
    static constexpr std::string_view valid_file_js = "../tests/FileScannerTestData/valid.js";
    static constexpr std::string_view valid_file_bat = "../tests/FileScannerTestData/valid.bat";
    static constexpr std::string_view valid_file_exe = "../tests/FileScannerTestData/valid.exe";

    suspicious::LightSuspiciousStorage storage;
};

TEST_F(ExtensionScannerTests, JsOpenValid) {
    suspicious::ffinder::File file(valid_file_js);
    suspicious::StorageAccessor accessor(storage);
    ASSERT_NO_THROW(suspicious::JsFileAnalyzer(file, accessor));
}

TEST_F(ExtensionScannerTests, JsOpenInvalid) {
    suspicious::ffinder::File file(valid_file_bat);
    suspicious::StorageAccessor accessor(storage);
    ASSERT_THROW(suspicious::JsFileAnalyzer(file, accessor), suspicious::exceptions::FileWrongExtension);
}

TEST_F(ExtensionScannerTests, BatOpenValid) {
    suspicious::ffinder::File file(valid_file_bat);
    suspicious::StorageAccessor accessor(storage);
    ASSERT_NO_THROW(suspicious::BatFileAnalyzer(file, accessor));
}

TEST_F(ExtensionScannerTests, BatOpenInvalid) {
    suspicious::ffinder::File file(valid_file_js);
    suspicious::StorageAccessor accessor(storage);
    ASSERT_THROW(suspicious::BatFileAnalyzer(file, accessor), suspicious::exceptions::FileWrongExtension);
}

TEST_F(ExtensionScannerTests, ExeOpenValid) {
    suspicious::ffinder::File file(valid_file_exe);
    suspicious::StorageAccessor accessor(storage);
    ASSERT_NO_THROW(suspicious::ExeFileAnalyzer(file, accessor));
}

TEST_F(ExtensionScannerTests, ExeOpenInvalid) {
    suspicious::ffinder::File file(valid_file_js);
    suspicious::StorageAccessor accessor(storage);
    ASSERT_THROW(suspicious::ExeFileAnalyzer(file, accessor), suspicious::exceptions::FileWrongExtension);
}
