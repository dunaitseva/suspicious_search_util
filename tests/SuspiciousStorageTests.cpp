#include "gtest/gtest.h"

#include "SuspiciousStorage.h"

class LightStorageGetAddTests : public ::testing::Test {
protected:
    suspicious::SuspiciousStorage::ExtensionType valid_extension = ".js";
    suspicious::SuspiciousStorage::ExtensionType invalid_extension1 = "js";
    suspicious::SuspiciousStorage::ExtensionType invalid_extension2 = "..js";
    suspicious::SuspiciousStorage::ExtensionType invalid_extension3 = ".";

    suspicious::SuspiciousStorage::SuspiciousEntryType suspicious_entry1 = "<script>evil_script()</script>";
    suspicious::SuspiciousStorage::SuspiciousEntryType suspicious_entry2 = "<script>very_evil_script()</script>";
    suspicious::SuspiciousStorage::SuspiciousEntryType suspicious_entry3 = "<script>very_very_evil_script()</script>";
};

class StorageAccessorTests : public ::testing::Test {
protected:
    suspicious::LightSuspiciousStorage storage;
    suspicious::SuspiciousStorage::ExtensionType valid_extension = ".js";
    suspicious::SuspiciousStorage::ExtensionType invalid_extension1 = "js";
    suspicious::SuspiciousStorage::ExtensionType invalid_extension2 = ".exe";
    size_t valid_storage_expected_size = 3;

    void SetUp() {
        storage.Add(valid_extension, "<script>evil_script1()</script>");
        storage.Add(valid_extension, "<script>evil_script2()</script>");
        storage.Add(valid_extension, "<script>evil_script3()</script>");
    }
};

TEST_F(LightStorageGetAddTests, AddGetTest) {
    suspicious::LightSuspiciousStorage storage;
    storage.Add(valid_extension, suspicious_entry1);
    storage.Add(valid_extension, suspicious_entry2);
    storage.Add(valid_extension, suspicious_entry3);
    storage.Add(valid_extension, suspicious_entry3);
    auto seq = storage.Get(valid_extension);
    ASSERT_EQ(seq.size(), 3);
}

TEST_F(LightStorageGetAddTests, AddWrongExtension) {
    suspicious::LightSuspiciousStorage storage1;
    storage1.Add(invalid_extension1, suspicious_entry1);
    suspicious::LightSuspiciousStorage storage2;
    storage2.Add(invalid_extension2, suspicious_entry1);
    suspicious::LightSuspiciousStorage storage3;
    storage3.Add(invalid_extension3, suspicious_entry1);
    EXPECT_EQ(storage1.Get(invalid_extension1).size(), 0);
    EXPECT_EQ(storage1.Get(invalid_extension2).size(), 0);
    ASSERT_EQ(storage1.Get(invalid_extension3).size(), 0);
}

TEST(SuspiciousStorageTests, GetWrongExtension) {
    suspicious::LightSuspiciousStorage storage;
    auto seq = storage.Get(".js");
    ASSERT_EQ(seq.size(), 0);
}

TEST_F(StorageAccessorTests, Accessablility) {
    suspicious::StorageAccessor accessor(storage);
    auto seq_valid = accessor.GetSuspiciousSequence(valid_extension);
    auto seq_invalid1 = accessor.GetSuspiciousSequence(invalid_extension1);
    auto seq_invalid2 = accessor.GetSuspiciousSequence(invalid_extension2);
    EXPECT_EQ(seq_valid.size(), valid_storage_expected_size);
    EXPECT_EQ(seq_invalid1.size(), 0);
    ASSERT_EQ(seq_invalid2.size(), 0);
}
