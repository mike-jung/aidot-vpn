# BouncyCastle ML-KEM — keep only what PqcKemClient touches.
#
# bcprov ships ~8MB of algorithms; this app uses exactly one. R8 strips
# the rest because we call the low-level classes directly and never
# register a JCE provider (provider lookup is reflective and would defeat
# shrinking entirely).
#
# The failure mode if these rules are wrong is quiet: PqcKemClient
# catches NoClassDefFoundError and falls back to the classical PSK, so
# an over-aggressive config downgrades security without breaking
# anything visibly. PqcKemClient logs that case distinctly for exactly
# this reason.
-keep class org.bouncycastle.pqc.crypto.mlkem.** { *; }
-keep class org.bouncycastle.crypto.SecretWithEncapsulation { *; }

# BC references optional JCE/JSSE surfaces it does not need here. Without
# these the build fails on missing classes that are never reached.
-dontwarn org.bouncycastle.jce.**
-dontwarn org.bouncycastle.jsse.**
-dontwarn javax.naming.**
