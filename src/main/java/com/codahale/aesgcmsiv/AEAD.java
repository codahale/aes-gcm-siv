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

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Optional;
import javax.annotation.Nullable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.modes.gcm.GCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.GCMUtil;
import org.bouncycastle.crypto.modes.gcm.Tables8kGCMMultiplier;
import org.bouncycastle.util.Pack;

public class AEAD {

  private static final byte[] EMPTY = new byte[0];
  private final byte[] key;

  public AEAD(byte[] key) {
    if (key.length != 16 && key.length != 32) {
      throw new IllegalArgumentException("Key must be 16 or 32 bytes long");
    }
    this.key = Arrays.copyOf(key, key.length);
  }

  public byte[] seal(byte[] nonce, byte[] plaintext, @Nullable byte[] data) {
    if (nonce.length != 12) {
      throw new IllegalArgumentException("Nonce must be 12 bytes long");
    }

    if (data == null) {
      data = EMPTY;
    }

    final byte[] authKey = subKey(key, 0, 1, nonce);
    final byte[] encKey = subKey(key, 2, key.length == 16 ? 3 : 5, nonce);

    final byte[] hash = polyval(authKey, padWithLengths(plaintext, data));
    for (int i = 0; i < nonce.length; i++) {
      hash[i] ^= nonce[i];
    }
    hash[hash.length - 1] &= ~0x80;
    final byte[] tag = aesECB(encKey, hash);
    final byte[] ctr = convertTag(tag);

    final byte[] ciphertext = aesCTR(encKey, ctr, plaintext);
    final byte[] out = new byte[ciphertext.length + tag.length];
    System.arraycopy(ciphertext, 0, out, 0, ciphertext.length);
    System.arraycopy(tag, 0, out, ciphertext.length, tag.length);
    return out;
  }

  public Optional<byte[]> open(byte[] nonce, byte[] ciphertext, @Nullable byte[] data) {
    if (nonce.length != 12) {
      throw new IllegalArgumentException("Nonce must be 12 bytes long");
    }

    if (data == null) {
      data = EMPTY;
    }

    final byte[] authKey = subKey(key, 0, 1, nonce);
    final byte[] encKey = subKey(key, 2, key.length == 16 ? 3 : 5, nonce);

    final byte[] tag = Arrays
        .copyOfRange(ciphertext, ciphertext.length - 16, ciphertext.length);
    ciphertext = Arrays.copyOf(ciphertext, ciphertext.length - tag.length);

    final byte[] ctr = convertTag(tag);
    final byte[] plaintext = aesCTR(encKey, ctr, ciphertext);

    final byte[] hash = polyval(authKey, padWithLengths(plaintext, data));
    for (int i = 0; i < nonce.length; i++) {
      hash[i] ^= nonce[i];
    }
    hash[hash.length - 1] &= ~0x80;
    final byte[] actual = aesECB(encKey, hash);

    if (MessageDigest.isEqual(tag, actual)) {
      return Optional.of(plaintext);
    }
    return Optional.empty();
  }

  private byte[] convertTag(byte[] tag) {
    final byte[] ctr = Arrays.copyOf(tag, tag.length);
    ctr[ctr.length - 1] |= 0x80;
    return ctr;
  }

  private byte[] polyval(byte[] h, byte[] x) {
    final GCMMultiplier multiplier = new Tables8kGCMMultiplier();
    multiplier.init(mulX_GHASH(h));

    final byte[] s = new byte[16];
    for (int i = 0; i < x.length; i += s.length) {
      final byte[] in = reverse(Arrays.copyOfRange(x, i, i + s.length));
      GCMUtil.xor(s, in);
      multiplier.multiplyH(s);
    }
    return reverse(s);
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

  private byte[] padWithLengths(byte[] plaintext, byte[] data) {
    final int plaintextPad = (16 - (plaintext.length % 16)) % 16;
    final int dataPad = (16 - (data.length % 16)) % 16;
    final byte[] out = new byte[8 + 8 + plaintext.length + plaintextPad + data.length + dataPad];
    System.arraycopy(data, 0, out, 0, data.length);
    System.arraycopy(plaintext, 0, out, data.length + dataPad, plaintext.length);
    Pack.intToLittleEndian(data.length * 8, out, out.length - 16);
    Pack.intToLittleEndian(plaintext.length * 8, out, out.length - 8);
    return out;
  }

  private byte[] subKey(byte[] key, int ctrStart, int ctrEnd, byte[] nonce) {
    final byte[] in = new byte[16];
    System.arraycopy(nonce, 0, in, in.length - nonce.length, nonce.length);
    final byte[] out = new byte[(ctrEnd - ctrStart + 1) * 8];

    for (int ctr = ctrStart; ctr <= ctrEnd; ctr++) {
      Pack.intToLittleEndian(ctr, in, 0);
      final byte[] x = aesECB(key, in);
      System.arraycopy(x, 0, out, (ctr - ctrStart) * 8, 8);
    }

    return out;
  }

  private byte[] aesECB(byte[] key, byte[] input) {
    try {
      final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
      final Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, keySpec);
      return cipher.doFinal(input);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
      throw new RuntimeException(e);
    }
  }

  private byte[] aesCTR(byte[] key, byte[] counter, byte[] input) {
    try {
      final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
      final Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, keySpec);

      long ctr = Integer.toUnsignedLong(Pack.littleEndianToInt(counter, 0));
      final byte[] out = new byte[input.length];
      for (int i = 0; i < input.length; i += 16) {
        final byte[] k = cipher.doFinal(counter);
        final int len = Math.min(16, input.length - i);
        GCMUtil.xor(k, input, i, len);
        System.arraycopy(k, 0, out, i, len);
        Pack.intToLittleEndian((int) ++ctr, counter, 0);
      }
      return out;
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }
}
