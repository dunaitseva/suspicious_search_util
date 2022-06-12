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