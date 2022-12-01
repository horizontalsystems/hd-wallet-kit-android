package io.horizontalsystems.hdwalletkit

import java.text.Normalizer

class MnemonicWordList(
    private val words: List<String>
) {

    operator fun get(index: Int): String {
        return words[index]
    }

    fun indexOf(word: String): Int {
        return words.indexOf(normalize(word))
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
        return words.any { it.startsWith(normalize(prefix)) }
    }

    private fun contains(mnemonic: String): Boolean {
        return words.contains(normalize(mnemonic))
    }

    companion object {
        fun normalize(string: String): String {
                return Normalizer.normalize(string, Normalizer.Form.NFKD)
        }
    }

    fun fetchSuggestions(input: String): List<String> {
        val suggestions = mutableListOf<String>()
        val normalizedInput = normalize(input)

        for (word in words) {
            if (word.startsWith(normalizedInput)) {
                suggestions.add(word)
            }
        }

        return suggestions.distinct()
    }

}
