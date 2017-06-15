# Change Log

## v0.4.1: 2017-06-15

* Reduced allocation and copying for `POLYVAL` calculation.
* Improved performance very slightly, but now on par with AES-GCM.

## v0.4.0: 2017-06-14

* Moved to `byte[]`-based API.
* Removed okio dependency.

## v0.3.1: 2017-06-14

* Sequentialized reads and writes.
* Optimized keystream generation.
* Optimized counter operations.
* Improved performance by an additional ~10%.

## v0.3.0: 2017-06-12

* Added a 64-bit implementation of `POLYVAL`, doubling performance.
* Moved AES usage to JCE.
* Removed Bouncy Castle dependency.

## v0.2.2: 2017-06-11

* Eliminated unnecessary AES key scheduling.

## v0.2.1: 2017-05-26

* Added JSR 305 annotations.

## v0.2.0: 2017-05-25

* Added automatic nonce management.
* Small internal refactorings.

## v0.1.0: 2017-05-22

* Initial release.