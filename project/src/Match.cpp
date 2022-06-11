#include <iostream>
#include "Match.h"

namespace suspicious::algorithm {
    /**
     * This function calculates the prefix function. The function prefix is an array
     * that matches the size of the template. Each function prefix element denotes the
     * size of the maximum prefix that matches the suffix for the template element
     * at the same index as the function prefix element.
     * @param pattern String patter, that we try to find in stream.
     * @return Prefix function in from of one-dim array.
     */
    static PrefixFunctionType ComputePrefix(const StringType &pattern) {
        SizeType size = pattern.size();
        PrefixFunctionType prefix(size);
        prefix[0] = 0;

        for (SizeType it = 1; it < size; ++it) {
            SizeType last = prefix[it - 1];
            while (last > 0 && pattern[last] != pattern[it]) {
                last = prefix[last - 1];
            }
            if (pattern[last] == pattern[it]) {
                ++last;
            }
            prefix[it] = last;
        }
        return prefix;
    }


    bool KMPFindMatch(IStream &is, size_t text_size, const StringType &pattern) {
        if (text_size == 0 || pattern.empty()) {
            return false;
        }
        is.unsetf(std::ios_base::skipws);
        SizeType pattern_size = pattern.size();
        PrefixFunctionType prefix = ComputePrefix(pattern);
        auto stream_it = IStreamIterator(is);
        auto eof_iter = IStreamIterator();

        // match_sym_counter is the counter of matched symbols.
        for (SizeType i = 0, match_sym_counter = 0;
             i < text_size && stream_it != eof_iter; ++i, stream_it = std::next(stream_it)) {
            while (match_sym_counter > 0 && pattern[match_sym_counter] != *stream_it) {
                match_sym_counter = prefix[match_sym_counter - 1]; // Next symbol don't match
            }

            if (pattern[match_sym_counter] == *stream_it) {
                ++match_sym_counter; // Next symbol match
            }

            if (match_sym_counter == pattern_size) {
                return true; // Whole pattern matches
            }
        }

        is.setf(std::ios_base::skipws);
        return false;
    }
}