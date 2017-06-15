/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.codahale.aesgcmsiv;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Optional;
import javax.annotation.CheckReturnValue;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

/**
 * An AES-GCM-SIV AEAD instance.
 *
 * @see <a href="https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-05">draft-irtf-cfrg-gcmsiv-05</a>
 * @see <a href="https://eprint.iacr.org/2017/168">AES-GCM-SIV: Specification and Analysis</a>
 */
public class AEAD {

  static final int AES_BLOCK_SIZE = 16;
  private static final int NONCE_SIZE = 12;

  private final Cipher aes;
  private final SecureRandom random;
  private final boolean aes128;

  /**
   * Creates a new {@link AEAD} instance with the given key.
   *
   * @param key the secret key; must be 16 or 32 bytes long
   */
  public AEAD(byte[] key) {
    if (key.length != 16 && key.length != 32) {
      throw new IllegalArgumentException("Key must be 16 or 32 bytes long");
    }
    this.aes = newAES(key);
    this.random = new SecureRandom();
    this.aes128 = key.length == 16;
  }

  /**
   * Encrypts the given plaintext.
   *
   * @param nonce a 12-byte random nonce
   * @param plaintext a plaintext message (may be empty)
   * @param data authenticated data (may be empty)
   * @return the encrypted message
   */
  @CheckReturnValue
  public byte[] seal(byte[] nonce, byte[] plaintext, byte[] data) {
    if (nonce.length != NONCE_SIZE) {
      throw new IllegalArgumentException("Nonce must be 12 bytes long");
    }
    final byte[] authKey = subKey(0, 1, nonce);
    final Cipher encAES = newAES(subKey(2, aes128 ? 3 : 5, nonce));
    final byte[] tag = hash(encAES, authKey, nonce, plaintext, data);
    final byte[] output = new byte[plaintext.length + tag.length];
    aesCTR(encAES, tag, plaintext, output);
    System.arraycopy(tag, 0, output, plaintext.length, tag.length);
    return output;
  }

  /**
   * Encrypts the given plaintext, using a random nonce. Prepends the nonce to the resulting
   * ciphertext.
   *
   * @param plaintext a plaintext message (may be empty)
   * @param data authenticated data (may be empty)
   * @return the random nonce and the encrypted message
   */
  @CheckReturnValue
  public byte[] seal(byte[] plaintext, byte[] data) {
    final byte[] nonce = new byte[NONCE_SIZE];
    random.nextBytes(nonce);

    final byte[] ciphertext = seal(nonce, plaintext, data);
    final byte[] output = new byte[nonce.length + ciphertext.length];
    System.arraycopy(nonce, 0, output, 0, nonce.length);
    System.arraycopy(ciphertext, 0, output, nonce.length, ciphertext.length);
    return output;
  }

  /**
   * Decrypts the given encrypted message.
   *
   * @param nonce the 12-byte random nonce used to encrypt the message
   * @param ciphertext the returned value from {@link #seal(byte[], byte[], byte[])}
   * @param data the authenticated data used to encrypt the message (may be empty)
   * @return the plaintext message
   */
  @CheckReturnValue
  public Optional<byte[]> open(byte[] nonce, byte[] ciphertext, byte[] data) {
    if (nonce.length != NONCE_SIZE) {
      throw new IllegalArgumentException("Nonce must be 12 bytes long");
    }

    final byte[] c = new byte[ciphertext.length - AES_BLOCK_SIZE];
    final byte[] tag = new byte[AES_BLOCK_SIZE];
    System.arraycopy(ciphertext, 0, c, 0, c.length);
    System.arraycopy(ciphertext, c.length, tag, 0, tag.length);

    final byte[] authKey = subKey(0, 1, nonce);
    final Cipher encAES = newAES(subKey(2, aes128 ? 3 : 5, nonce));
    aesCTR(encAES, tag, c, c);
    final byte[] actual = hash(encAES, authKey, nonce, c, data);

    if (MessageDigest.isEqual(tag, actual)) {
      return Optional.of(c);
    }
    return Optional.empty();
  }

  /**
   * Decrypts the given encrypted message.
   *
   * @param ciphertext the returned value from {@link #seal(byte[], byte[])}
   * @param data the authenticated data used to encrypt the message (may be empty)
   * @return the plaintext message
   */
  @CheckReturnValue
  public Optional<byte[]> open(byte[] ciphertext, byte[] data) {
    if (ciphertext.length < NONCE_SIZE) {
      return Optional.empty();
    }

    final byte[] nonce = new byte[NONCE_SIZE];
    final byte[] c = new byte[ciphertext.length - NONCE_SIZE];
    System.arraycopy(ciphertext, 0, nonce, 0, nonce.length);
    System.arraycopy(ciphertext, nonce.length, c, 0, c.length);

    return open(nonce, c, data);
  }

  private byte[] hash(Cipher aes, byte[] h, byte[] nonce, byte[] plaintext, byte[] data) {
    final Polyval polyval = new Polyval(h);
    polyval.update(data);
    polyval.update(plaintext);

    final byte[] lens = new byte[AES_BLOCK_SIZE];
    Bytes.putLong((long) data.length * 8, lens, 0);
    Bytes.putLong((long) plaintext.length * 8, lens, 8);
    polyval.updateBlock(lens, 0);

    final byte[] hash = polyval.digest();
    for (int i = 0; i < nonce.length; i++) {
      hash[i] ^= nonce[i];
    }
    hash[hash.length - 1] &= ~0x80;

    // encrypt polyval hash to produce tag
    try {
      aes.update(hash, 0, hash.length, hash, 0);
    } catch (ShortBufferException e) {
      throw new RuntimeException(e);
    }
    return hash;
  }

  private byte[] subKey(int ctrStart, int ctrEnd, byte[] nonce) {
    final byte[] in = new byte[AES_BLOCK_SIZE];
    System.arraycopy(nonce, 0, in, in.length - nonce.length, nonce.length);
    final byte[] out = new byte[(ctrEnd - ctrStart + 1) * 8];
    final byte[] x = new byte[AES_BLOCK_SIZE];
    for (int ctr = ctrStart; ctr <= ctrEnd; ctr++) {
      Bytes.putInt(ctr, in);
      try {
        aes.update(in, 0, in.length, x, 0);
      } catch (ShortBufferException e) {
        throw new RuntimeException(e);
      }
      System.arraycopy(x, 0, out, (ctr - ctrStart) * 8, 8);
    }
    return out;
  }

  private void aesCTR(Cipher aes, byte[] tag, byte[] input, byte[] output) {
    final byte[] counter = Arrays.copyOf(tag, tag.length);
    counter[counter.length - 1] |= 0x80;
    final byte[] k = new byte[AES_BLOCK_SIZE];
    for (int i = 0; i < input.length; i += AES_BLOCK_SIZE) {
      // encrypt counter to produce keystream
      try {
        aes.update(counter, 0, counter.length, k, 0);
      } catch (ShortBufferException e) {
        throw new RuntimeException(e);
      }

      // xor input with keystream
      final int len = Math.min(AES_BLOCK_SIZE, input.length - i);
      for (int j = 0; j < len; j++) {
        final int idx = i + j;
        output[idx] = (byte) (input[idx] ^ k[j]);
      }

      // increment counter
      int j = 0;
      while (j < 4 && ++counter[j] == 0) {
        j++;
      }
    }
  }

  private Cipher newAES(byte[] key) {
    try {
      final Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
      aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
      return aes;
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
      throw new RuntimeException(e);
    }
  }
}
