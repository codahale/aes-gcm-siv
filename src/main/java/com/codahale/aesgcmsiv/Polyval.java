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

import org.bouncycastle.util.Pack;

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
    int v0 = Pack.littleEndianToInt(h, 12);
    int v1 = Pack.littleEndianToInt(h, 8);
    int v2 = Pack.littleEndianToInt(h, 4);
    int v3 = Pack.littleEndianToInt(h, 0);
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
    int m = b << 31 >> 8;
    v0 ^= (m & E1);
    this.h0 = ((v0 & 0xffffffffL) << 32) | v1 & 0xffffffffL;
    this.h1 = ((v2 & 0xffffffffL) << 32) | v3 & 0xffffffffL;
  }

  @SuppressWarnings("Duplicates")
  void update(byte[] b) {
    long v0 = h0;
    long v1 = h1;
    long z0 = 0;
    long z1 = 0;

    // breaking this up into two duplicate loops is faster

    long x = s0 ^ Pack.littleEndianToLong(b, 8);
    for (int i = 0; i < 64; i++) {
      long m = x >> 63;
      z0 ^= v0 & m;
      z1 ^= v1 & m;
      m = v1 << 63 >> 63;
      final long c = v0 & 1L;
      v0 >>>= 1;
      v1 = v1 >>> 1 | c << 63;
      v0 ^= E & m;
      x <<= 1;
    }

    x = s1 ^ Pack.littleEndianToLong(b, 0);
    for (int i = 64; i < 127; i++) {
      long m = x >> 63;
      z0 ^= v0 & m;
      z1 ^= v1 & m;
      m = v1 << 63 >> 63;
      final long c = v0 & 1L;
      v0 >>>= 1;
      v1 = v1 >>> 1 | c << 63;
      v0 ^= E & m;
      x <<= 1;
    }

    long m = x >> 63;
    this.s0 = (z0 ^ (v0 & m));
    this.s1 = (z1 ^ (v1 & m));
  }

  byte[] digest() {
    byte[] d = new byte[16];
    Pack.longToLittleEndian(s0, d, 8);
    Pack.longToLittleEndian(s1, d, 0);
    return d;
  }
}

