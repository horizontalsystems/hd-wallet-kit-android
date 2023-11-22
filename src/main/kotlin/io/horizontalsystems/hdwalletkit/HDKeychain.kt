package io.horizontalsystems.hdwalletkit


class HDKeychain(val hdKey: HDKey, val curve: Curve = Curve.Secp256K1) {

    constructor(seed: ByteArray, curve: Curve): this(HDKeyDerivation.createRootKey(seed, curve), curve)

    /// Parses the BIP32 path and derives the chain of keychains accordingly.
    /// Path syntax: (m?/)?([0-9]+'?(/[0-9]+'?)*)?
    /// The following paths are valid:
    ///
    /// "" (root key)
    /// "m" (root key)
    /// "/" (root key)
    /// "m/0'" (hardened child #0 of the root key)
    /// "/0'" (hardened child #0 of the root key)
    /// "0'" (hardened child #0 of the root key)
    /// "m/44'/1'/2'" (BIP44 testnet account #2)
    /// "/44'/1'/2'" (BIP44 testnet account #2)
    /// "44'/1'/2'" (BIP44 testnet account #2)
    ///
    /// The following paths are invalid:
    ///
    /// "m / 0 / 1" (contains spaces)
    /// "m/b/c" (alphabetical characters instead of numerical indexes)
    /// "m/1.2^3" (contains illegal characters)
    fun getKeyByPath(path: String): HDKey {
        var key = hdKey

        var derivePath = path
        if (derivePath == "m" || derivePath == "/" || derivePath == "") {
            return key
        }
        if (derivePath.contains("m/")) {
            derivePath = derivePath.drop(2)
        }
        for (chunk in derivePath.split("/")) {
            var hardened = false
            var indexText: String = chunk
            if (chunk.contains("'")) {
                hardened = true
                indexText = indexText.dropLast(1)
            }
            val index = indexText.toInt()
            key = HDKeyDerivation.deriveChildKey(key, index, hardened, curve)
        }

        return key
    }

    fun deriveNonHardenedChildKeys(parent: HDKey, indices: IntRange): List<HDKey> {
        val keys = mutableListOf<HDKey>()
        for (index in indices) {
            val childHDKey = HDKeyDerivation.deriveChildKey(parent, index, false, curve)
            keys.add(childHDKey)
        }
        return keys
    }

}
