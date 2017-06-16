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

// An implementation of POLYVAL based on GHASH because even BoringSSL doesn't have a POLYVAL impl.
// Does its own byte-order conversion to avoid confusion.
final class Polyval {

  private static final long E = 0xe100000000000000L;
  private static final int E1 = 0xe1000000;
  private final long h0;
  private final long h1;
  private long s0;
  private long s1;

  // mulX_GHASH, basically
  Polyval(byte[] h) {
    int v3 = Bytes.getInt(h, 0);
    int v2 = Bytes.getInt(h, 4);
    int v1 = Bytes.getInt(h, 8);
    int v0 = Bytes.getInt(h, 12);

    int b = v0;
    v0 = b >>> 1;
    int c = b << 31;
    b = v1;
    v1 = (b >>> 1) | c;
    c = b << 31;
    b = v2;
    v2 = (b >>> 1) | c;
    c = b << 31;
    b = v3;
    v3 = (b >>> 1) | c;
    v0 ^= (b << 31 >> 8 & E1);

    this.h0 = ((v0 & 0xffffffffL) << 32) | v1 & 0xffffffffL;
    this.h1 = ((v2 & 0xffffffffL) << 32) | v3 & 0xffffffffL;
  }

  void update(byte[] b) {
    final int extra = b.length % AEAD.AES_BLOCK_SIZE;
    for (int i = 0; i < b.length - extra; i += AEAD.AES_BLOCK_SIZE) {
      updateBlock(b, i);
    }

    if (extra != 0) {
      final byte[] block = new byte[AEAD.AES_BLOCK_SIZE];
      System.arraycopy(b, b.length - extra, block, 0, extra);
      updateBlock(block, 0);
    }
  }

  @SuppressWarnings("Duplicates")
  void updateBlock(byte[] b, int offset) {
    long v0 = h0;
    long v1 = h1;
    long z0 = 0;
    long z1 = 0;

    long x0 = s1 ^ Bytes.getLong(b, offset);
    long x1 = s0 ^ Bytes.getLong(b, offset + 8);

    // breaking this up into two duplicate loops is faster

    for (int i = 0; i < 64; i++) {
      long m = x1 >> 63;
      z0 ^= v0 & m;
      z1 ^= v1 & m;
      m = v1 << 63 >> 63;
      final long c = v0 & 1L;
      v0 >>>= 1;
      v1 = v1 >>> 1 | c << 63;
      v0 ^= E & m;
      x1 <<= 1;
    }

    for (int i = 64; i < 127; i++) {
      long m = x0 >> 63;
      z0 ^= v0 & m;
      z1 ^= v1 & m;
      m = v1 << 63 >> 63;
      final long c = v0 & 1L;
      v0 >>>= 1;
      v1 = v1 >>> 1 | c << 63;
      v0 ^= E & m;
      x0 <<= 1;
    }

    final long m = x0 >> 63;
    this.s0 = (z0 ^ (v0 & m));
    this.s1 = (z1 ^ (v1 & m));
  }

  void digest(byte[] d) {
    Bytes.putLong(s1, d, 0);
    Bytes.putLong(s0, d, 8);
  }
}

