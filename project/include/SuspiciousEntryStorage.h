#ifndef SUSPICIOUSSEARCHUTIL_SUSPICIOUSENTRYSTORAGE_H
#define SUSPICIOUSSEARCHUTIL_SUSPICIOUSENTRYSTORAGE_H

#include <string>
#include <unordered_set>
#include <unordered_map>

#include "Def.h"

namespace suspicious {
    /**
     * This class provides an interface to other classes, with the help of which
     * they can return a set of suspicious occurrences in a file by a given extension.
     * At the user side it looks like key-value storage.
     */
    class SuspiciousEntryStorage {
    public:

        static constexpr size_t MIN_EXTENSION_SIZE = 2;
        static constexpr char EXTENSION_DELIMITER = '.';

        SuspiciousEntryStorage() = default;

        virtual void Add(const ExtensionType &extension, const SuspiciousEntryType &suspicious_entry) = 0;
        virtual SuspiciousEntrySequence Get(const ExtensionType &extension) const = 0;

        virtual ~SuspiciousEntryStorage() = default;
    };


    /**
     * Simplest implementation of SuspiciousEntryStorage. Based on hash table
     */
    class LightSuspiciousStorage : public SuspiciousEntryStorage {
    public:
        using HashtableType = std::unordered_map<ExtensionType, SuspiciousEntrySequence, std::hash<ExtensionType>>;

        void Add(const ExtensionType &extension, const SuspiciousEntryType &suspicious_entry) override;
        virtual SuspiciousEntrySequence Get(const ExtensionType &extension) const override;
    private:
        HashtableType m_hash_table;
    };

    /**
     * Accessor, adds DIP to storage related work.
     * @tparam Storage SuspiciousEntryStorage or derived classes
     */
    class StorageAccessor {
    public:
        StorageAccessor() = delete;
        explicit StorageAccessor(const SuspiciousEntryStorage &storage) : m_storage(storage) {}

        SuspiciousEntrySequence GetSuspiciousSequence(const ExtensionType &extension) {
            return m_storage.Get(extension);
        }

    private:
        const SuspiciousEntryStorage &m_storage;
    };
}


#endif //SUSPICIOUSSEARCHUTIL_SUSPICIOUSENTRYSTORAGE_H
