#include <string>
#include <string_view>

#include "Analyzer.h"
#include "FileFinder.h"
#include "SuspiciousEntryStorage.h"
#include "gtest/gtest.h"

#define _ITERATOR_DEBUG_LEVEL 2

class ExtensionAnalyzerTests : public ::testing::Test {
protected:
    static constexpr std::string_view valid_file_js = "../tests/FileScannerTestData/valid.js";
    static constexpr std::string_view valid_file_bat = "../tests/FileScannerTestData/valid.bat";
    static constexpr std::string_view valid_file_exe = "../tests/FileScannerTestData/valid.dll";

    suspicious::LightSuspiciousStorage storage;
};

class AnalyzerBehaviorTests : public ::testing::Test {
protected:
    static constexpr std::string_view valid_file_js = "../tests/FileScannerTestData/valid.js";
    static constexpr std::string_view valid_file_bat = "../tests/FileScannerTestData/valid.bat";
    static constexpr std::string_view valid_file_exe1 = "../tests/FileScannerTestData/valid.dll";
    static constexpr std::string_view valid_file_exe2 = "../tests/FileScannerTestData/test.exe";

    suspicious::ffinder::File file_js;
    suspicious::ffinder::File file_bat;
    suspicious::ffinder::File file_exe1;
    suspicious::ffinder::File file_exe2;

    suspicious::LightSuspiciousStorage storage;

    void SetUp() {
        file_js = suspicious::ffinder::File(valid_file_js);
        file_bat = suspicious::ffinder::File(valid_file_bat);
        file_exe1 = suspicious::ffinder::File(valid_file_exe1);
        file_exe2 = suspicious::ffinder::File(valid_file_exe2);
        storage.Add(".js", "<script>evil_script()</script>");
        storage.Add(".cmd", "rd /s /q \"c:\\windows\"");
        storage.Add(".bat", "rd /s /q \"c:\\windows\"");
        storage.Add(".exe", "CreateRemoteThread");
        storage.Add(".dll", "CreateRemoteThread");
        storage.Add(".exe", "CreateProcess");
        storage.Add(".dll", "CreateProcess");
    }
};

TEST_F(ExtensionAnalyzerTests, JsOpenValid) {
    suspicious::ffinder::File file(valid_file_js);
    suspicious::StorageAccessor accessor(storage);
    ASSERT_NO_THROW(suspicious::JsFileAnalyzer(file, accessor));
}

TEST_F(ExtensionAnalyzerTests, JsOpenInvalid) {
    suspicious::ffinder::File file(valid_file_bat);
    suspicious::StorageAccessor accessor(storage);
    ASSERT_THROW(suspicious::JsFileAnalyzer(file, accessor), suspicious::exceptions::FileWrongExtension);
}

TEST_F(ExtensionAnalyzerTests, BatOpenValid) {
    suspicious::ffinder::File file(valid_file_bat);
    suspicious::StorageAccessor accessor(storage);
    ASSERT_NO_THROW(suspicious::BatFileAnalyzer(file, accessor));
}

TEST_F(ExtensionAnalyzerTests, BatOpenInvalid) {
    suspicious::ffinder::File file(valid_file_js);
    suspicious::StorageAccessor accessor(storage);
    ASSERT_THROW(suspicious::BatFileAnalyzer(file, accessor), suspicious::exceptions::FileWrongExtension);
}

TEST_F(ExtensionAnalyzerTests, ExeOpenValid) {
    suspicious::ffinder::File file(valid_file_exe);
    suspicious::StorageAccessor accessor(storage);
    ASSERT_NO_THROW(suspicious::ExeFileAnalyzer(file, accessor));
}

TEST_F(ExtensionAnalyzerTests, ExeOpenInvalid) {
    suspicious::ffinder::File file(valid_file_js);
    suspicious::StorageAccessor accessor(storage);
    ASSERT_THROW(suspicious::ExeFileAnalyzer(file, accessor), suspicious::exceptions::FileWrongExtension);
}

TEST_F(AnalyzerBehaviorTests, JsAnalyzer) {
    suspicious::StorageAccessor accessor(storage);
    suspicious::JsFileAnalyzer analyzer(file_js, accessor);
    bool verdict = analyzer.AnalyzeFile();
    EXPECT_FALSE(analyzer.IsError());
    ASSERT_TRUE(verdict);
}

TEST_F(AnalyzerBehaviorTests, BatAnalyzer) {
    suspicious::StorageAccessor accessor(storage);
    suspicious::BatFileAnalyzer analyzer(file_bat, accessor);
    bool verdict = analyzer.AnalyzeFile();
    EXPECT_FALSE(analyzer.IsError());
    ASSERT_TRUE(verdict);
}

TEST_F(AnalyzerBehaviorTests, ExeAnalyzer) {
    suspicious::StorageAccessor accessor(storage);
    suspicious::ExeFileAnalyzer analyzer(file_exe1, accessor);
    bool verdict = analyzer.AnalyzeFile();
    EXPECT_FALSE(analyzer.IsError());
    ASSERT_TRUE(verdict);
}

TEST_F(AnalyzerBehaviorTests, ExeAnalyzerLib) {
    suspicious::StorageAccessor accessor(storage);
    suspicious::ExeFileAnalyzer analyzer(file_exe2, accessor);
    bool verdict = analyzer.AnalyzeFile();
    EXPECT_FALSE(analyzer.IsError());
    ASSERT_TRUE(verdict);
}
