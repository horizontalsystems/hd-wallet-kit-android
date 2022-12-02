package io.horizontalsystems.hdwalletkit

import java.text.Normalizer

class MnemonicWordList(
        private val words: List<String>,
        private val mustBeNormalized: Boolean
) {
    private val normalizedWords = words.map { normalize(it) }

    operator fun get(index: Int): String {
        return words[index]
    }

    fun indexOf(word: String): Int {
        return normalizedWords.indexOf(normalize(word))
    }

    fun validWord(word: String, partial: Boolean = false): Boolean {
        return if (partial) {
            startsWith(word)
        } else {
            contains(word)
        }
    }

    fun validWords(words: List<String>): Boolean {
        return words.all { contains(it) }
    }

    private fun startsWith(prefix: String): Boolean {
        return normalizedWords.any { it.startsWith(normalize(prefix)) }
    }

    private fun contains(mnemonic: String): Boolean {
        return normalizedWords.contains(normalize(mnemonic))
    }

    private fun normalize(string: String): String {
        return if (mustBeNormalized)
            Normalizer.normalize(string, Normalizer.Form.NFKD).replace("[^\\p{ASCII}]".toRegex(), "")
        else
            string
    }

    fun fetchSuggestions(input: String): List<String> {
        val suggestions = mutableListOf<String>()
        val normalizedInput = normalize(input)

        for (word in normalizedWords) {
            if (word.startsWith(normalizedInput)) {
                suggestions.add(word)
            }
        }

        return suggestions.distinct()
    }

}
