#ifndef SUSPICIOUSSEARCHUTIL_MATCHER_H
#define SUSPICIOUSSEARCHUTIL_MATCHER_H

#include <string>
#include <istream>
#include <vector>
#include <iterator>

namespace suspicious::algorithm {
    using IStream = std::istream;
    using IStreamIterator = std::istream_iterator<char>;
    using StringType = std::string;
    using SizeType = size_t;
    using PrefixFunctionType = std::vector<SizeType>;

    /**
     * Implementation of Knuth-Morris-Pratt algorithm. Specific implementation for
     * stl streams.
     *
     * @param is Input stream.
     * @param text_size Number of characters to be read.
     * @param pattern String patter, that we try to find in stream.
     * @return Return true if pattern found. If not - return false.
     *
     * @note
     * A fairly fast algorithm for searching substrings in a string, which avoids iterating
     * backward through the text being searched. Thus, in one pass, we can understand if the
     * text contains the desired pattern.
     *
     * @complexity
     * Worst: O(N) for matching and O(M) for prefix function calculation.
     * N - text length, M - pattern lengt.
     */
    bool KMPFindMatch(IStream &is, size_t text_size, const StringType &pattern);
}


#endif //SUSPICIOUSSEARCHUTIL_MATCHER_H
