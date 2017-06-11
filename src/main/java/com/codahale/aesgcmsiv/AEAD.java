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

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Optional;
import javax.annotation.CheckReturnValue;
import okio.Buffer;
import okio.ByteString;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.gcm.GCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.GCMUtil;
import org.bouncycastle.crypto.modes.gcm.Tables8kGCMMultiplier;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Pack;

/**
 * An AES-GCM-SIV AEAD instance.
 *
 * @see <a href="https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-05">draft-irtf-cfrg-gcmsiv-05</a>
 * @see <a href="https://eprint.iacr.org/2017/168">AES-GCM-SIV: Specification and Analysis</a>
 */
public class AEAD {

  private final AESEngine aes;
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
    final byte[] encKey = subKey(2, aes128 ? 3 : 5, n);
    final AESEngine encAES = newAES(encKey);
    final byte[] hash = polyval(authKey, n, p, d);
    final byte[] tag = new byte[hash.length];
    encAES.processBlock(hash, 0, tag, 0);
    final byte[] ctr = convertTag(tag);
    final byte[] ciphertext = aesCTR(encAES, ctr, p);
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
    final byte[] authKey = subKey(0, 1, n);
    final byte[] encKey = subKey(2, aes128 ? 3 : 5, n);
    final AESEngine encAES = newAES(encKey);
    final byte[] tag = ciphertext.substring(c.length, ciphertext.size()).toByteArray();
    final byte[] ctr = convertTag(tag);
    final byte[] plaintext = aesCTR(encAES, ctr, c);
    final byte[] hash = polyval(authKey, n, plaintext, d);
    final byte[] actual = new byte[hash.length];
    encAES.processBlock(hash, 0, actual, 0);

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

  private byte[] convertTag(byte[] tag) {
    final byte[] ctr = Arrays.copyOf(tag, tag.length);
    ctr[ctr.length - 1] |= 0x80;
    return ctr;
  }

  private byte[] polyval(byte[] h, byte[] nonce, byte[] plaintext, byte[] data) {
    final GCMMultiplier multiplier = new Tables8kGCMMultiplier();
    multiplier.init(mulX_GHASH(h));

    final byte[] s = new byte[16];
    final byte[] x = aeadBlock(plaintext, data);
    for (int i = 0; i < x.length; i += s.length) {
      final byte[] in = reverse(Arrays.copyOfRange(x, i, i + s.length));
      GCMUtil.xor(s, in);
      multiplier.multiplyH(s);
    }

    final byte[] hash = reverse(s);
    for (int i = 0; i < nonce.length; i++) {
      hash[i] ^= nonce[i];
    }
    hash[hash.length - 1] &= ~0x80;
    return hash;
  }

  private byte[] mulX_GHASH(byte[] x) {
    final int[] ints = GCMUtil.asInts(reverse(x));
    GCMUtil.multiplyP(ints);
    return GCMUtil.asBytes(ints);
  }

  private byte[] reverse(byte[] x) {
    final byte[] out = new byte[x.length];
    for (int i = 0; i < x.length; i++) {
      out[x.length - i - 1] = x[i];
    }
    return out;
  }

  private byte[] aeadBlock(byte[] plaintext, byte[] data) {
    final int plaintextPad = (16 - (plaintext.length % 16)) % 16;
    final int dataPad = (16 - (data.length % 16)) % 16;
    final byte[] out = new byte[8 + 8 + plaintext.length + plaintextPad + data.length + dataPad];
    System.arraycopy(data, 0, out, 0, data.length);
    System.arraycopy(plaintext, 0, out, data.length + dataPad, plaintext.length);
    Pack.intToLittleEndian(data.length * 8, out, out.length - 16);
    Pack.intToLittleEndian(plaintext.length * 8, out, out.length - 8);
    return out;
  }

  private byte[] subKey(int ctrStart, int ctrEnd, byte[] nonce) {
    final byte[] in = new byte[16];
    System.arraycopy(nonce, 0, in, in.length - nonce.length, nonce.length);
    final byte[] out = new byte[(ctrEnd - ctrStart + 1) * 8];
    final byte[] x = new byte[16];
    for (int ctr = ctrStart; ctr <= ctrEnd; ctr++) {
      Pack.intToLittleEndian(ctr, in, 0);
      aes.processBlock(in, 0, x, 0);
      System.arraycopy(x, 0, out, (ctr - ctrStart) * 8, 8);
    }
    return out;
  }

  private byte[] aesCTR(AESEngine aes, byte[] counter, byte[] input) {
    final byte[] out = new byte[input.length];
    int ctr = Pack.littleEndianToInt(counter, 0);
    final byte[] k = new byte[aes.getBlockSize()];
    for (int i = 0; i < input.length; i += 16) {
      aes.processBlock(counter, 0, k, 0);
      final int len = Math.min(16, input.length - i);
      GCMUtil.xor(k, input, i, len);
      System.arraycopy(k, 0, out, i, len);
      Pack.intToLittleEndian(++ctr, counter, 0);
    }
    return out;
  }

  private AESEngine newAES(byte[] key) {
    final AESEngine aes = new AESEngine();
    aes.init(true, new KeyParameter(key));
    return aes;
  }
}
