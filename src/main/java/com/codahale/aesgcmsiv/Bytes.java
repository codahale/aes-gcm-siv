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

interface Bytes {

  static void putInt(int n, byte[] b) {
    b[0] = (byte) (n);
    b[1] = (byte) (n >> 8);
    b[2] = (byte) (n >> 16);
    b[3] = (byte) (n >> 24);
  }

  static void putLong(long n, byte[] b, int offset) {
    final int hi = (int) (n & 0xffffffffL);
    final int lo = (int) (n >> 32);
    b[offset] = (byte) hi;
    b[++offset] = (byte) (hi >> 8);
    b[++offset] = (byte) (hi >> 16);
    b[++offset] = (byte) (hi >> 24);
    b[++offset] = (byte) lo;
    b[++offset] = (byte) (lo >> 8);
    b[++offset] = (byte) (lo >> 16);
    b[++offset] = (byte) (lo >> 24);
  }

  static int getInt(byte[] b, int offset) {
    int n = b[offset] & 0xff;
    n |= (b[++offset] & 0xff) << 8;
    n |= (b[++offset] & 0xff) << 16;
    n |= b[++offset] << 24;
    return n;
  }

  static long getLong(byte[] b, int offset) {
    int lo = b[offset] & 0xff;
    lo |= (b[++offset] & 0xff) << 8;
    lo |= (b[++offset] & 0xff) << 16;
    lo |= b[++offset] << 24;

    int hi = b[++offset] & 0xff;
    hi |= (b[++offset] & 0xff) << 8;
    hi |= (b[++offset] & 0xff) << 16;
    hi |= b[++offset] << 24;

    return ((hi & 0xffffffffL) << 32) | lo & 0xffffffffL;
  }
}
