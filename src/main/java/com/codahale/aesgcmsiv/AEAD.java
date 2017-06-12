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
import okio.Buffer;
import okio.ByteString;

/**
 * An AES-GCM-SIV AEAD instance.
 *
 * @see <a href="https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-05">draft-irtf-cfrg-gcmsiv-05</a>
 * @see <a href="https://eprint.iacr.org/2017/168">AES-GCM-SIV: Specification and Analysis</a>
 */
public class AEAD {

  private final Cipher aes;
  private final SecureRandom random;
  private final boolean aes128;

  /**
   * Creates a new {@link AEAD} instance with the given key.
   *
   * @param key the secret key; must be 16 or 32 bytes long
   */
  public AEAD(ByteString key) {
    if (key.size() != 16 && key.size() != 32) {
      throw new IllegalArgumentException("Key must be 16 or 32 bytes long");
    }
    this.aes = newAES(key.toByteArray());
    this.random = new SecureRandom();
    this.aes128 = key.size() == 16;
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
  public ByteString seal(ByteString nonce, ByteString plaintext, ByteString data) {
    if (nonce.size() != 12) {
      throw new IllegalArgumentException("Nonce must be 12 bytes long");
    }
    final byte[] n = nonce.toByteArray();
    final byte[] p = plaintext.toByteArray();
    final byte[] d = data.toByteArray();
    final byte[] authKey = subKey(0, 1, n);
    final Cipher encAES = newAES(subKey(2, aes128 ? 3 : 5, n));
    final byte[] tag = hash(encAES, authKey, n, p, d);
    final byte[] ciphertext = aesCTR(encAES, tag, p);
    return new Buffer().write(ciphertext).write(tag).readByteString();
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
  public ByteString seal(ByteString plaintext, ByteString data) {
    final byte[] nonce = new byte[12];
    random.nextBytes(nonce);

    return new Buffer().write(nonce)
                       .write(seal(ByteString.of(nonce), plaintext, data))
                       .readByteString();
  }

  /**
   * Decrypts the given encrypted message.
   *
   * @param nonce the 12-byte random nonce used to encrypt the message
   * @param ciphertext the returned value from {@link #seal(ByteString, ByteString, ByteString)}
   * @param data the authenticated data used to encrypt the message (may be empty)
   * @return the plaintext message
   */
  @CheckReturnValue
  public Optional<ByteString> open(ByteString nonce, ByteString ciphertext, ByteString data) {
    if (nonce.size() != 12) {
      throw new IllegalArgumentException("Nonce must be 12 bytes long");
    }

    final byte[] n = nonce.toByteArray();
    final byte[] c = ciphertext.substring(0, ciphertext.size() - 16).toByteArray();
    final byte[] d = data.toByteArray();
    final byte[] tag = ciphertext.substring(c.length, ciphertext.size()).toByteArray();
    final byte[] authKey = subKey(0, 1, n);
    final Cipher encAES = newAES(subKey(2, aes128 ? 3 : 5, n));
    final byte[] plaintext = aesCTR(encAES, tag, c);
    final byte[] actual = hash(encAES, authKey, n, plaintext, d);

    if (MessageDigest.isEqual(tag, actual)) {
      return Optional.of(ByteString.of(plaintext));
    }
    return Optional.empty();
  }

  /**
   * Decrypts the given encrypted message.
   *
   * @param ciphertext the returned value from {@link #seal(ByteString, ByteString)}
   * @param data the authenticated data used to encrypt the message (may be empty)
   * @return the plaintext message
   */
  @CheckReturnValue
  public Optional<ByteString> open(ByteString ciphertext, ByteString data) {
    if (ciphertext.size() < 12) {
      return Optional.empty();
    }
    return open(ciphertext.substring(0, 12), ciphertext.substring(12), data);
  }

  private byte[] hash(Cipher aes, byte[] h, byte[] nonce, byte[] plaintext, byte[] data) {
    final Polyval polyval = new Polyval(h);
    final byte[] x = aeadBlock(plaintext, data);
    final byte[] in = new byte[16];
    for (int i = 0; i < x.length; i += 16) {
      System.arraycopy(x, i, in, 0, 16);
      polyval.update(in);
    }
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

  private byte[] aeadBlock(byte[] plaintext, byte[] data) {
    final int plaintextPad = (16 - (plaintext.length % 16)) % 16;
    final int dataPad = (16 - (data.length % 16)) % 16;
    final byte[] out = new byte[8 + 8 + plaintext.length + plaintextPad + data.length + dataPad];
    System.arraycopy(data, 0, out, 0, data.length);
    System.arraycopy(plaintext, 0, out, data.length + dataPad, plaintext.length);
    Bytes.putInt(data.length * 8, out, out.length - 16);
    Bytes.putInt(plaintext.length * 8, out, out.length - 8);
    return out;
  }

  private byte[] subKey(int ctrStart, int ctrEnd, byte[] nonce) {
    final byte[] in = new byte[16];
    System.arraycopy(nonce, 0, in, in.length - nonce.length, nonce.length);
    final byte[] out = new byte[(ctrEnd - ctrStart + 1) * 8];
    final byte[] x = new byte[16];
    for (int ctr = ctrStart; ctr <= ctrEnd; ctr++) {
      Bytes.putInt(ctr, in, 0);
      try {
        aes.update(in, 0, in.length, x, 0);
      } catch (ShortBufferException e) {
        throw new RuntimeException(e);
      }
      System.arraycopy(x, 0, out, (ctr - ctrStart) * 8, 8);
    }
    return out;
  }

  private byte[] aesCTR(Cipher aes, byte[] tag, byte[] input) {
    final byte[] counter = Arrays.copyOf(tag, tag.length);
    counter[counter.length - 1] |= 0x80;
    final byte[] out = new byte[input.length];
    int ctr = Bytes.getInt(counter, 0);
    final byte[] k = new byte[aes.getBlockSize()];
    for (int i = 0; i < input.length; i += 16) {
      try {
        aes.update(counter, 0, counter.length, k, 0);
      } catch (ShortBufferException e) {
        throw new RuntimeException(e);
      }
      final int len = Math.min(16, input.length - i);
      for (int j = 0; j < len; j++) {
        k[j] ^= input[i + j];
      }
      System.arraycopy(k, 0, out, i, len);
      Bytes.putInt(++ctr, counter, 0);
    }
    return out;
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
