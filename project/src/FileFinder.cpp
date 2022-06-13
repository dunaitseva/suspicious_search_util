#include "FileFinder.h"

namespace suspicious::ffinder::exceptions {
    void LogError(std::ostream &os, const ErrorCodes &ec) {
        if (ec == ErrorCodes::NotExist) {
            os << "Directory does not exist" << std::endl;
            return;
        }

        if (ec == ErrorCodes::NotDir) {
            os << "Passed path is not path to directory" << std::endl;
            return;
        }
    }
}  // namespace suspicious::ffinder::exceptions
