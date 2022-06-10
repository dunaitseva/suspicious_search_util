#ifndef SUSPICIOUSSEARCHUTIL_SUSPICIOUSSTORAGE_H
#define SUSPICIOUSSEARCHUTIL_SUSPICIOUSSTORAGE_H

#include <string>
#include <unordered_set>
#include <unordered_map>

namespace suspicious {
    /**
     * This class provides an interface to other classes, with the help of which
     * they can return a set of suspicious occurrences in a file by a given extension.
     * At the user side it looks like key-value storage.
     */
    class SuspiciousStorage {
    public:
        using StringType = std::string;
        using ExtensionType = StringType;
        using SuspiciousEntryType = StringType;
        using SuspiciousSequence = std::unordered_set<SuspiciousEntryType>;

        static constexpr size_t MIN_EXTENSION_SIZE = 2;
        static constexpr char EXTENSION_DELIMITER = '.';

        SuspiciousStorage() = default;

        virtual void Add(const ExtensionType &extension, const SuspiciousEntryType &suspicious_entry) = 0;
        virtual SuspiciousSequence Get(const ExtensionType &extension) const = 0;

        virtual ~SuspiciousStorage() = default;
    };


    /**
     * Simplest implementation of SuspiciousStorage. Based on hash table
     */
    class LightSuspiciousStorage : public SuspiciousStorage {
    public:
        using HashtableType = std::unordered_map<ExtensionType, SuspiciousSequence>;

        LightSuspiciousStorage() = default;

        void Add(const ExtensionType &extension, const SuspiciousEntryType &suspicious_entry) override;
        virtual SuspiciousSequence Get(const ExtensionType &extension) const override;
    private:
        HashtableType m_hash_table;
    };

    /**
     * Accessor, adds DIP to storage related work.
     * @tparam Storage SuspiciousStorage or derived classes
     */
    template<typename Storage>
    class StorageAccessor {
    public:
        StorageAccessor() = delete;
        explicit StorageAccessor(Storage &storage) : m_storage(storage) {}

        SuspiciousStorage::SuspiciousSequence GetSuspiciousSequence(const SuspiciousStorage::ExtensionType &extension) {
            return m_storage.Get(extension);
        }

    private:
        Storage &m_storage;
    };
}


#endif //SUSPICIOUSSEARCHUTIL_SUSPICIOUSSTORAGE_H
