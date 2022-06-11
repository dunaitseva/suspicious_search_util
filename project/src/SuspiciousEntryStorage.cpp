#include "SuspiciousEntryStorage.h"

namespace suspicious {
    void LightSuspiciousStorage::Add(const ExtensionType &extension, const SuspiciousEntryType &suspicious_entry) {
        if (extension.size() >= MIN_EXTENSION_SIZE &&
            extension[0] == EXTENSION_DELIMITER &&
            extension[1] != EXTENSION_DELIMITER) {
            m_hash_table[extension].insert(suspicious_entry);
        }
    }

    SuspiciousEntrySequence LightSuspiciousStorage::Get(const ExtensionType &extension) const {
        if (m_hash_table.count(extension) == 0) {
            return {};
        }
        return m_hash_table.at(extension);
    }
}