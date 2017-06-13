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

package com.codahale.aesgcmsiv.benchmarks;

import com.codahale.aesgcmsiv.AEAD;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import okio.ByteString;
import org.openjdk.jmh.Main;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.runner.RunnerException;

@State(Scope.Benchmark)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@BenchmarkMode(Mode.AverageTime)
public class Benchmarks {

  private final ByteString key = ByteString.of(new byte[16]);
  private final ByteString nonce = ByteString.of(new byte[12]);
  private final ByteString plaintext = ByteString.of(new byte[1024]);
  private final AEAD aead = new AEAD(key);

  public static void main(String[] args) throws IOException, RunnerException {
    Main.main(args);
  }

  @Benchmark
  public ByteString aes_GCM_SIV() {
    return aead.seal(nonce, plaintext, ByteString.EMPTY);
  }

  @Benchmark
  public byte[] aes_GCM() throws Exception {
    final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    final GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce.toByteArray());
    final SecretKeySpec keySpec = new SecretKeySpec(key.toByteArray(), "AES");
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
    return cipher.doFinal(new byte[1024]);
  }
}
