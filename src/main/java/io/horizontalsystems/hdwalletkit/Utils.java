package io.horizontalsystems.hdwalletkit;

/**
 * Copyright 2011 Google Inc.
 * Copyright 2013-2016 Ronald W Hoffman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Static utility methods
 */
public class Utils {
    /** Bit masks (Low-order bit is bit 0 and high-order bit is bit 7) */
    private static final int bitMask[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

    /** Strong random number generator */
    private static final Random rnd = new SecureRandom();

    /** Instance of a SHA-256 digest which we will use as needed */
    private static final MessageDigest digest;

    static {
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Can't happen.
        }
    }

    /**
     * Calculate the SHA-256 hash of the input and then hash the resulting hash again
     *
     * @param       input           Data to be hashed
     * @return                      The hash digest
     */
    public static byte[] doubleDigest(byte[] input) {
        return doubleDigest(input, 0, input.length);
    }

    /**
     * Calculate the SHA-256 hash of the input and then hash the resulting hash again
     *
     * @param       input           Data to be hashed
     * @param       offset          Starting offset within the data
     * @param       length          Number of data bytes to hash
     * @return                      The hash digest
     */
    public static byte[] doubleDigest(byte[] input, int offset, int length) {
        byte[] bytes;
        synchronized (digest) {
            digest.reset();
            digest.update(input, offset, length);
            byte[] first = digest.digest();
            bytes = digest.digest(first);
        }
        return bytes;
    }

    /**
     * Calculate RIPEMD160(SHA256(input)).  This is used in Address calculations.
     *
     * @param       input           The byte array to be hashed
     * @return                      The hashed result
     */
    public static byte[] sha256Hash160(byte[] input) {
        byte[] out = new byte[20];
        synchronized(digest) {
            digest.reset();
            byte[] sha256 = digest.digest(input);
            RIPEMD160Digest rDigest = new RIPEMD160Digest();
            rDigest.update(sha256, 0, sha256.length);
            rDigest.doFinal(out, 0);
        }
        return out;
    }

    /**
     * Calculates the SHA-256 hash of the given byte range,
     * and then hashes the resulting hash again.
     *
     * @param input the array containing the bytes to hash
     * @param offset the offset within the array of the bytes to hash
     * @param length the number of bytes to hash
     * @return the double-hash (in big-endian order)
     */
    public static byte[] hashTwice(byte[] input, int offset, int length) {
        MessageDigest digest = newDigest();
        digest.update(input, offset, length);
        return digest.digest(digest.digest());
    }

    /**
     * Returns a new SHA-256 MessageDigest instance.
     *
     * This is a convenience method which wraps the checked
     * exception that can never occur with a RuntimeException.
     *
     * @return a new SHA-256 MessageDigest instance
     */
    public static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Can't happen.
        }
    }

    /**
     * Calculate the HMAC-SHA512 digest for use with BIP 32
     *
     * @param       key             Key
     * @param       input           Bytes to be hashed
     * @return                      Hashed result
     */
    public static byte[] hmacSha512(byte[] key, byte[] input) {
        HMac hmac = new HMac(new SHA512Digest());
        hmac.init(new KeyParameter(key));
        hmac.update(input, 0, input.length);
        byte[] out = new byte[64];
        hmac.doFinal(out, 0);
        return out;
    }

    /**
     * Calculates the SHA-256 hash of the given byte range.
     *
     * @param input the array containing the bytes to hash
     * @param offset the offset within the array of the bytes to hash
     * @param length the number of bytes to hash
     * @return the hash (in big-endian order)
     */
    public static byte[] sha256(byte[] input, int offset, int length) {
        MessageDigest digest = newDigest();
        digest.update(input, offset, length);
        return digest.digest();
    }

    /**
     * Calculates the SHA-256 hash of the given bytes.
     *
     * @param input the bytes to hash
     * @return the hash (in big-endian order)
     */
    public static byte[] sha256(byte[] input) {
        return sha256(input, 0, input.length);
    }

    public static byte[] taggedHash(String tag, byte[] msg) {
        byte[] hash = sha256(tag.getBytes(StandardCharsets.UTF_8));
        ByteBuffer buffer = ByteBuffer.allocate(hash.length + hash.length + msg.length);
        buffer.put(hash);
        buffer.put(hash);
        buffer.put(msg);

        return sha256(buffer.array());
    }

    /**
     * Checks if the specified bit is set
     *
     * @param       data            Byte array to check
     * @param       index           Bit position
     * @return      TRUE if the bit is set
     */
    public static boolean checkBitLE(byte[] data, int index) {
        return (data[index>>>3] & bitMask[7&index]) != 0;
    }

    /**
     * Sets the specified bit
     * @param       data            Byte array
     * @param       index           Bit position
     */
    public static void setBitLE(byte[] data, int index) {
        data[index >>> 3] |= bitMask[7 & index];
    }

    /**
     * Calculate SHA256(SHA256(byte range 1 + byte range 2)).
     *
     * @param       input1          First input byte array
     * @param       offset1         Starting position in the first array
     * @param       length1         Number of bytes to process in the first array
     * @param       input2          Second input byte array
     * @param       offset2         Starting position in the second array
     * @param       length2         Number of bytes to process in the second array
     * @return                      The SHA-256 digest
     */
    public static byte[] doubleDigestTwoBuffers(byte[]input1, int offset1, int length1,
                                                byte[]input2, int offset2, int length2) {
        byte[] bytes;
        synchronized (digest) {
            digest.reset();
            digest.update(input1, offset1, length1);
            digest.update(input2, offset2, length2);
            byte[]first = digest.digest();
            bytes = digest.digest(first);
        }
        return bytes;
    }

    /**
     * Form a long value from a 4-byte array in big-endian format
     *
     * @param       bytes           The byte array
     * @param       offset          Starting offset within the array
     * @return The long value
     */
    public static long readUint32BE(byte[] bytes, int offset) {
        return (((long) bytes[offset++] & 0x00FFL) << 24) |
                (((long) bytes[offset++] & 0x00FFL) << 16) |
                (((long) bytes[offset++] & 0x00FFL) << 8) |
                ((long) bytes[offset] & 0x00FFL);
    }

    /** Parse 2 bytes from the stream as unsigned 16-bit integer in little endian format. */
    public static int readUint16FromStream(InputStream is) {
        try {
            return (is.read() & 0xff) |
                    ((is.read() & 0xff) << 8);
        } catch (IOException x) {
            throw new RuntimeException(x);
        }
    }

    /** Parse 4 bytes from the stream as unsigned 32-bit integer in little endian format. */
    public static long readUint32FromStream(InputStream is) {
        try {
            return (is.read() & 0xffl) |
                    ((is.read() & 0xffl) << 8) |
                    ((is.read() & 0xffl) << 16) |
                    ((is.read() & 0xffl) << 24);
        } catch (IOException x) {
            throw new RuntimeException(x);
        }
    }

    /**
     * Write an unsigned 32-bit value to a byte array in little-endian format
     *
     * @param       val             Value to be written
     * @param       out             Output array
     * @param       offset          Starting offset
     */
    public static void uint32ToByteArrayLE(long val, byte[] out, int offset) {
        out[offset++] = (byte)val;
        out[offset++] = (byte)(val >> 8);
        out[offset++] = (byte)(val >> 16);
        out[offset] = (byte)(val >> 24);
    }

    /**
     * Write an unsigned 64-bit value to a byte array in little-endian format
     *
     * @param       val             Value to be written
     * @param       out             Output array
     * @param       offset          Starting offset
     */
    public static void uint64ToByteArrayLE(long val, byte[] out, int offset) {
        out[offset++] = (byte)val;
        out[offset++] = (byte)(val >> 8);
        out[offset++] = (byte)(val >> 16);
        out[offset++] = (byte)(val >> 24);
        out[offset++] = (byte)(val >> 32);
        out[offset++] = (byte)(val >> 40);
        out[offset++] = (byte)(val >> 48);
        out[offset] = (byte)(val >> 56);
    }

    /**
     * Converts a BigInteger to a fixed-length byte array.
     *
     * The regular BigInteger method isn't quite what we often need: it appends a
     * leading zero to indicate that the number is positive and it may need padding.
     *
     * @param       bigInteger          Integer to format into a byte array
     * @param       numBytes            Desired size of the resulting byte array
     * @return                          Byte array of the desired length
     */
    public static byte[] bigIntegerToBytes(BigInteger bigInteger, int numBytes) {
        if (bigInteger == null)
            return null;
        byte[] bigBytes = bigInteger.toByteArray();
        byte[] bytes = new byte[numBytes];
        int start = (bigBytes.length==numBytes+1) ? 1 : 0;
        int length = Math.min(bigBytes.length, numBytes);
        System.arraycopy(bigBytes, start, bytes, numBytes-length, length);
        return bytes;
    }

    /**
     * Encode the value in little-endian format
     *
     * @param       value           Value to encode
     * @return Byte array
     */
    public static byte[] encode(long value) {
        byte[] bytes;
        if ((value & 0xFFFFFFFF00000000L) != 0) {
            // 1 marker + 8 data bytes
            bytes = new byte[9];
            bytes[0] = (byte) 255;
            Utils.uint64ToByteArrayLE(value, bytes, 1);
        } else if ((value & 0x00000000FFFF0000L) != 0) {
            // 1 marker + 4 data bytes
            bytes = new byte[5];
            bytes[0] = (byte) 254;
            Utils.uint32ToByteArrayLE(value, bytes, 1);
        } else if (value >= 253L) {
            // 1 marker + 2 data bytes
            bytes = new byte[]{(byte) 253, (byte) value, (byte) (value >> 8)};
        } else {
            // Single data byte
            bytes = new byte[]{(byte) value};
        }
        return bytes;
    }

    public static byte[] intToByteArray(int value) {
        return new byte[]{(byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8), (byte) value};
    }

    /** Generate random long number */
    public static long randomLong() {
        return (long) (rnd.nextDouble() * Long.MAX_VALUE);
    }

    /** Generate random number */
    public static int randomInt() {
        return (int) (rnd.nextDouble() * Integer.MAX_VALUE);
    }
}
