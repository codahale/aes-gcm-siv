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

package com.codahale.aesgcmsiv.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.codahale.aesgcmsiv.AEAD;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Optional;
import javax.annotation.Nullable;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import okio.ByteString;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.quicktheories.WithQuickTheories;
import org.quicktheories.core.Gen;
import org.quicktheories.impl.Constraint;

class AEADTest implements WithQuickTheories {

  private Gen<byte[]> bytes(int minSize, int maxSize) {
    return in -> {
      final byte[] bytes = new byte[(int) in.next(Constraint.between(minSize, maxSize))];
      for (int i = 0; i < bytes.length; i++) {
        bytes[i] = (byte) in.next(Constraint.between(0, 255));
      }
      return bytes;
    };
  }

  @ParameterizedTest
  @CsvFileSource(
    resources = {
      "/8_Worked_example.csv",
      // all test vectors from Appendix C
      "/C1_AEAD_AES_128_GCM_SIV.csv",
      "/C2_AEAD_AES_256_GCM_SIV.csv",
      "/C3_Counter_wrap_tests.csv"
    }
  )
  void matchTestVectors(String k, String n, @Nullable String p, @Nullable String d, String c)
      throws NoSuchAlgorithmException, NoSuchPaddingException {
    final byte[] key = ByteString.decodeHex(k).toByteArray();

    assumeTrue(isValidKey(key), String.format("AES-%d is not supported", key.length * 8));

    final byte[] nonce = ByteString.decodeHex(n).toByteArray();
    final byte[] plaintext = (p == null ? ByteString.EMPTY : ByteString.decodeHex(p)).toByteArray();
    final byte[] data = (d == null ? ByteString.EMPTY : ByteString.decodeHex(d)).toByteArray();
    final byte[] ciphertext = ByteString.decodeHex(c).toByteArray();

    final AEAD aead = new AEAD(key);
    final byte[] c2 = aead.seal(nonce, plaintext, data);
    assertArrayEquals(ciphertext, c2);

    final Optional<byte[]> p2 = aead.open(nonce, c2, data);
    assertTrue(p2.isPresent());
    assertArrayEquals(plaintext, p2.get());
  }

  private boolean isValidKey(byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException {
    try {
      final Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
      return true;
    } catch (InvalidKeyException e) {
      return false;
    }
  }

  @Test
  void roundTrip() {
    qt().forAll(bytes(16, 16), bytes(12, 12), bytes(0, 1024), bytes(0, 1024))
        .check(
            (key, nonce, plaintext, data) -> {
              final AEAD aead = new AEAD(key);
              final byte[] ciphertext = aead.seal(nonce, plaintext, data);
              final Optional<byte[]> message = aead.open(nonce, ciphertext, data);

              return message.isPresent() && Arrays.equals(plaintext, message.get());
            });
  }

  @Test
  void simpleRoundTrip() {
    qt().forAll(bytes(16, 16), bytes(0, 1024), bytes(0, 1024))
        .check(
            (key, plaintext, data) -> {
              final AEAD aead = new AEAD(key);
              final byte[] ciphertext = aead.seal(plaintext, data);
              final Optional<byte[]> message = aead.open(ciphertext, data);

              return message.isPresent() && Arrays.equals(plaintext, message.get());
            });
  }
}
