package io.horizontalsystems.hdwalletkit

import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import kotlin.experimental.and
import kotlin.experimental.or

class Mnemonic {

    private val PBKDF2_ROUNDS = 2048

    enum class EntropyStrength(val entropyLength: Int) {
        Default(128),
        Low(160),
        Medium(192),
        High(224),
        VeryHigh(256);

        val checksumLength: Int
            get() = entropyLength / 32

        val totalLength: Int
            get() = entropyLength + checksumLength

        val wordCount: Int
            get() = checksumLength * 3

        companion object {
            fun fromWordCount(wordCount: Int) = when (wordCount) {
                12 -> Default
                15 -> Low
                18 -> Medium
                21 -> High
                24 -> VeryHigh
                else -> throw InvalidMnemonicCountException("Count: $wordCount")
            }
        }
    }

    /**
     * Generate mnemonic keys
     */
    fun generate(
        strength: EntropyStrength = EntropyStrength.Default,
        language: Language = Language.English
    ): List<String> {
        val seed = ByteArray(strength.entropyLength / 8)
        val random = SecureRandom()
        random.nextBytes(seed)
        return toMnemonic(seed, language)
    }

    /**
     * Convert entropy data to mnemonic word list.
     */
    fun toMnemonic(entropy: ByteArray, language: Language): List<String> {
        if (entropy.isEmpty())
            throw EmptyEntropyException("Entropy is empty.")

        // We take initial entropy of ENT bits and compute its
        // checksum by taking first ENT / 32 bits of its SHA256 hash.

        val hashed = hash(entropy, 0, entropy.size)
        val hashBits = bytesToBits(hashed)

        val entropyBits = bytesToBits(entropy)
        val checksumLengthBits = entropyBits.size / 32

        // We append these bits to the end of the initial entropy.
        val concatBits = BooleanArray(entropyBits.size + checksumLengthBits)
        System.arraycopy(entropyBits, 0, concatBits, 0, entropyBits.size)
        System.arraycopy(hashBits, 0, concatBits, entropyBits.size, checksumLengthBits)

        // Next we take these concatenated bits and split them into
        // groups of 11 bits. Each group encodes number from 0-2047
        // which is a position in a wordlist.  We convert numbers into
        // words and use joined words as mnemonic sentence.

        val wordList = WordList.wordList(language)
        val words = ArrayList<String>()
        val nwords = concatBits.size / 11
        for (i in 0 until nwords) {
            var index = 0
            for (j in 0..10) {
                index = index shl 1
                if (concatBits[i * 11 + j])
                    index = index or 0x1
            }
            words.add(wordList[index])
        }

        return words
    }


    /**
     * Convert mnemonic keys to seed
     */
    fun toSeed(mnemonicKeys: List<String>, passphrase: String = ""): ByteArray {

        validate(mnemonicKeys)

        // To create binary seed from mnemonic, we use PBKDF2 function
        // with mnemonic sentence (in UTF-8) used as a password and
        // string "mnemonic" + passphrase (again in UTF-8) used as a
        // salt. Iteration count is set to 2048 and HMAC-SHA512 is
        // used as a pseudo-random function. Desired length of the
        // derived key is 512 bits (= 64 bytes).
        //
        val pass = mnemonicKeys.joinToString(separator = " ")
        val salt = "mnemonic$passphrase"

        return PBKDF2SHA512.derive(pass, salt, PBKDF2_ROUNDS, 64)
    }


    /**
     * Validate mnemonic keys. Since validation
     * requires deriving the original entropy, this function is the same as calling [toEntropy]
     */
    fun validate(mnemonicKeys: List<String>) {
        var appropriateWordList = WordList.wordList(Language.English)

        for (language in Language.values()) {
            val wordList = WordList.wordList(language)
            if (wordList.validWords(mnemonicKeys)) {
                appropriateWordList = wordList
                break
            }
        }

        toEntropy(mnemonicKeys, appropriateWordList)
    }

    fun validateStrict(mnemonicKeys: List<String>) {
        var appropriateWordList = WordList.wordListStrict(Language.English)

        for (language in Language.values()) {
            val wordList = WordList.wordListStrict(language)
            if (wordList.validWords(mnemonicKeys)) {
                appropriateWordList = wordList
                break
            }
        }

        toEntropy(mnemonicKeys, appropriateWordList)
    }

    fun isWordValid(word: String, partial: Boolean) = Language.values().any { language ->
        WordList.wordList(language).validWord(word, partial)
    }

    /**
     * Get the original entropy that was used to create this MnemonicCode. This call will fail
     * if the words have an invalid length or checksum.
     *
     * @throws InvalidMnemonicCountException when the word count is zero or not a multiple of 3.
     * @throws ChecksumException if the checksum does not match the expected value.
     *
     * source: https://github.com/zcash/kotlin-bip39/blob/master/lib/src/main/java/cash/z/ecc/android/bip39/Mnemonics.kt
     */
    fun toEntropy(mnemonicKeys: List<String>, wordList: MnemonicWordList): ByteArray {

        val strength = EntropyStrength.fromWordCount(mnemonicKeys.size)

        // Look up all the words in the list and construct the
        // concatenation of the original entropy and the checksum.
        //
        val entropy = ByteArray(strength.entropyLength / 8)
        val checksumBits = mutableListOf<Boolean>()

        var bitsProcessed = 0
        var nextByte = 0.toByte()
        mnemonicKeys.forEach {
            wordList.indexOf(it).let { phraseIndex ->
                // fail if the word was not found on the list
                if (phraseIndex < 0) throw InvalidMnemonicKeyException("Invalid word: $it")
                // for each of the 11 bits of the phraseIndex
                (10 downTo 0).forEach { i ->
                    // isolate the next bit (starting from the big end)
                    val bit = phraseIndex and (1 shl i) != 0
                    // if the bit is set, then update the corresponding bit in the nextByte
                    if (bit) nextByte = nextByte or (1 shl 7 - (bitsProcessed).rem(8)).toByte()
                    val entropyIndex = ((++bitsProcessed) - 1) / 8
                    // if we're at a byte boundary (excluding the extra checksum bits)
                    if (bitsProcessed.rem(8) == 0 && entropyIndex < entropy.size) {
                        // then set the byte and prepare to process the next byte
                        entropy[entropyIndex] = nextByte
                        nextByte = 0.toByte()
                        // if we're now processing checksum bits, then track them for later
                    } else if (entropyIndex >= entropy.size) {
                        checksumBits.add(bit)
                    }
                }
            }
        }

        // Check each required checksum bit, against the first byte of the sha256 of entropy
        entropy.toSha256()[0].toBits().let { hashFirstByteBits ->
            repeat(strength.checksumLength) { i ->
                // failure means that each word was valid BUT they were in the wrong order
                if (hashFirstByteBits[i] != checksumBits[i]) throw ChecksumException("Invalid checksum")
            }
        }

        return entropy
    }

    private fun bytesToBits(data: ByteArray): BooleanArray {
        val bits = BooleanArray(data.size * 8)
        for (i in data.indices)
            for (j in 0..7) {
                val tmp1 = 1 shl (7 - j)
                val tmp2 = data[i] and tmp1.toByte()

                bits[i * 8 + j] = tmp2 != 0.toByte()
            }
        return bits
    }

    private fun hash(input: ByteArray, offset: Int, length: Int): ByteArray {
        val digest = newDigest()
        digest.update(input, offset, length)
        return digest.digest()
    }

    private fun newDigest(): MessageDigest {
        try {
            return MessageDigest.getInstance("SHA-256")
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)  // Can't happen.
        }

    }

    open class MnemonicException(message: String) : Exception(message)

    class EmptyEntropyException(message: String) : MnemonicException(message)

    class InvalidMnemonicCountException(message: String) : MnemonicException(message)

    class InvalidMnemonicKeyException(message: String) : MnemonicException(message)

    class ChecksumException(message: String) : MnemonicException(message)

}


//
// Private Extensions
//

private fun ByteArray?.toSha256() = MessageDigest.getInstance("SHA-256").digest(this)

private fun Byte.toBits(): List<Boolean> = (7 downTo 0).map { (toInt() and (1 shl it)) != 0 }
