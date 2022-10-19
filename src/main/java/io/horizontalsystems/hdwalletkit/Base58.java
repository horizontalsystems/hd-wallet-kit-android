package io.horizontalsystems.hdwalletkit;

import java.util.Arrays;

public class Base58 {
    public static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final char ENCODED_ZERO = ALPHABET[0];

    /** Lookup index for US-ASCII characters (code points 0-127) */
    private static final int[] INDEXES = new int[128];

    static {
        for (int i=0; i<INDEXES.length; i++)
            INDEXES[i] = -1;
        for (int i=0; i<ALPHABET.length; i++)
            INDEXES[ALPHABET[i]] = i;
    }

    /**
     * Encodes the given bytes as a base58 string (no checksum is appended).
     *
     * @param input the bytes to encode
     * @return the base58-encoded string
     */
    public static String encode(byte[] input) {
        if (input.length == 0) {
            return "";
        }       
        // Count leading zeros.
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) {
            ++zeros;
        }
        // Convert base-256 digits to base-58 digits (plus conversion to ASCII characters)
        input = Arrays.copyOf(input, input.length); // since we modify it in-place
        char[] encoded = new char[input.length * 2]; // upper bound
        int outputStart = encoded.length;
        for (int inputStart = zeros; inputStart < input.length; ) {
            encoded[--outputStart] = ALPHABET[divmod(input, inputStart, 256, 58)];
            if (input[inputStart] == 0) {
                ++inputStart; // optimization - skip leading zeros
            }
        }
        // Preserve exactly as many leading encoded zeros in output as there were leading zeros in input.
        while (outputStart < encoded.length && encoded[outputStart] == ENCODED_ZERO) {
            ++outputStart;
        }
        while (--zeros >= 0) {
            encoded[--outputStart] = ENCODED_ZERO;
        }
        // Return encoded string (including encoded leading zeros).
        return new String(encoded, outputStart, encoded.length - outputStart);
    }

    /**
     * Decodes a Base58 string
     *
     * @param   string                          Encoded string
     * @return                                  Decoded bytes
     * @throws      IllegalArgumentException    Invalid Base-58 encoded string
     */
    public static byte[] decode(String string) throws IllegalArgumentException {
        //
        // Nothing to do if we have an empty string
        //
        if (string.length() == 0)
            return new byte[0];
        //
        // Convert the input string to a byte sequence
        //
        byte[] input = new byte[string.length()];
        for (int i=0; i<string.length(); i++) {
            int codePoint = string.codePointAt(i);
            int digit = -1;
            if (codePoint>=0 && codePoint<INDEXES.length)
                digit = INDEXES[codePoint];
            if (digit < 0)
                throw new IllegalArgumentException(
                        String.format("Illegal character %c at index %d", string.charAt(i), i));
            input[i] = (byte)digit;
        }
        //
        // Count the number of leading zero characters
        //
        int zeroCount = 0;
        while (zeroCount < input.length && input[zeroCount] == 0)
            zeroCount++;
        //
        // Convert from Base58 encoding starting with the first non-zero character
        //
        byte[] decoded = new byte[input.length];
        int decodedOffset = decoded.length;
        int offset = zeroCount;
        while (offset < input.length) {
            byte mod = divmod(input, offset, 58, 256);
            if (input[offset] == 0)
                offset++;
            decoded[--decodedOffset] = mod;
        }
        //
        // Strip leading zeroes from the decoded result
        //
        while (decodedOffset < decoded.length && decoded[decodedOffset] == 0)
            decodedOffset++;
        //
        // Return the decoded result prefixed with the number of leading zeroes
        // that were in the original string
        //
        byte[] output = Arrays.copyOfRange(decoded, decodedOffset-zeroCount, decoded.length);
        return output;
    }

    /**
     * Divides a number, represented as an array of bytes each containing a single digit
     * in the specified base, by the given divisor. The given number is modified in-place
     * to contain the quotient, and the return value is the remainder.
     *
     * @param number the number to divide
     * @param firstDigit the index within the array of the first non-zero digit
     *        (this is used for optimization by skipping the leading zeros)
     * @param base the base in which the number's digits are represented (up to 256)
     * @param divisor the number to divide by (up to 256)
     * @return the remainder of the division operation
     */
    private static byte divmod(byte[] number, int firstDigit, int base, int divisor) {
        // this is just long division which accounts for the base of the input digits
        int remainder = 0;
        for (int i = firstDigit; i < number.length; i++) {
            int digit = (int) number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = (byte) (temp / divisor);
            remainder = temp % divisor;
        }
        return (byte) remainder;
    }

}
