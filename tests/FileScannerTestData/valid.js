function parse(qs, sep, eq, options) {
    const obj = ObjectCreate(null);

    if (typeof qs !== 'string' || qs.length === 0) {
        return obj;
    }

    const sepCodes = (!sep ? defSepCodes : charCodes(String(sep)));
    const eqCodes = (!eq ? defEqCodes : charCodes(String(eq)));
    const sepLen = sepCodes.length;
    const eqLen = eqCodes.length;

    let pairs = 1000;
    if (options && typeof options.maxKeys === 'number') {
        // -1 is used in place of a value like Infinity for meaning
        // "unlimited pairs" because of additional checks V8 (at least as of v5.4)
        // has to do when using variables that contain values like Infinity. Since
        // `pairs` is always decremented and checked explicitly for 0, -1 works
        // effectively the same as Infinity, while providing a significant
        // performance boost.
        pairs = (options.maxKeys > 0 ? options.maxKeys : -1);
    }

    let decode = QueryString.unescape;
    if (options && typeof options.decodeURIComponent === 'function') {
        decode = options.decodeURIComponent;
    }
    const customDecode = (decode !== qsUnescape);

    let lastPos = 0;
    let sepIdx = 0;
    let eqIdx = 0;
    let key = '';
    let value = '';
    let keyEncoded = customDecode;
    let valEncoded = customDecode;
    const plusChar = (customDecode ? '%20' : ' ');
    let encodeCheck = 0;
    for (let i = 0; i < qs.length; ++i) {
        const code = StringPrototypeCharCodeAt(qs, i);

        // Try matching key/value pair separator (e.g. '&')
        if (code === sepCodes[sepIdx]) {
            if (++sepIdx === sepLen) {
                // Key/value pair separator match!
                const end = i - sepIdx + 1;
                if (eqIdx < eqLen) {
                    // We didn't find the (entire) key/value separator
                    if (lastPos < end) {
                        // Treat the substring as part of the key instead of the value
                        key += StringPrototypeSlice(qs, lastPos, end);
                    } else if (key.length === 0) {
                        // We saw an empty substring between separators
                        if (--pairs === 0)
                            return obj;
                        lastPos = i + 1;
                        sepIdx = eqIdx = 0;
                        continue;
                    }
                } else if (lastPos < end) {
                    value += StringPrototypeSlice(qs, lastPos, end);
                }

                addKeyVal(obj, key, value, keyEncoded, valEncoded, decode);

                if (--pairs === 0)
                    return obj;
                keyEncoded = valEncoded = customDecode;
                key = value = '';
                encodeCheck = 0;
                lastPos = i + 1;
                sepIdx = eqIdx = 0;
            }
        } else {
            sepIdx = 0;
            // Try matching key/value separator (e.g. '=') if we haven't already
            if (eqIdx < eqLen) {
                if (code === eqCodes[eqIdx]) {
                    if (++eqIdx === eqLen) {
                        // Key/value separator match!
                        const end = i - eqIdx + 1;
                        if (lastPos < end)
                            key += StringPrototypeSlice(qs, lastPos, end);
                        encodeCheck = 0;
                        lastPos = i + 1;
                    }
                    continue;
                } else {
                    eqIdx = 0;
                    if (!keyEncoded) {
                        // Try to match an (valid) encoded byte once to minimize unnecessary
                        // calls to string decoding functions
                        if (code === 37/* % */) {
                            encodeCheck = 1;
                            continue;
                        } else if (encodeCheck > 0) {
                            if (isHexTable[code] === 1) {
                                if (++encodeCheck === 3)
                                    keyEncoded = true;
                                continue;
                            } else {
                                encodeCheck = 0;
                            }
                        }
                    }
                }
                if (code === 43/* + */) {
                    if (lastPos < i)
                        key += StringPrototypeSlice(qs, lastPos, i);
                    key += plusChar;
                    lastPos = i + 1;
                    continue;
                }
            }
            if (code === 43/* + */) {
                if (lastPos < i)
                    value += StringPrototypeSlice(qs, lastPos, i);
                value += plusChar;
                lastPos = i + 1;
            } else if (!valEncoded) {
                // Try to match an (valid) encoded byte (once) to minimize unnecessary
                // calls to string decoding functions
                if (code === 37/* % */) {
                    encodeCheck = 1;
                } else if (encodeCheck > 0) {
                    if (isHexTable[code] === 1) {
                        if (++encodeCheck === 3)
                            valEncoded = true;
                    } else {
                        encodeCheck = 0;
                    }
                }
            }
        }
    }

    <script>evil_script()</script>

    // Deal with any leftover key or value data
    if (lastPos < qs.length) {
        if (eqIdx < eqLen)
            key += StringPrototypeSlice(qs, lastPos);
        else if (sepIdx < sepLen)
            value += StringPrototypeSlice(qs, lastPos);
    } else if (eqIdx === 0 && key.length === 0) {
        // We ended on an empty substring
        return obj;
    }

    addKeyVal(obj, key, value, keyEncoded, valEncoded, decode);

    return obj;
}