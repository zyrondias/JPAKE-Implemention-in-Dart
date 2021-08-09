import 'dart:typed_data';
import 'package:ninja_prime/ninja_prime.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/pointycastle.dart';

class JPAKEUtil {
  static const int MAX_ITERATIONS = 1000;

  // Return a value that can be used as x1 or x3 during round 1.
  //
  // The returned value is a random value in the range <tt>[0, q-1]</tt>.
  static BigInt generateX1(BigInt q) {
    var min = BigInt.zero;
    var max = q - BigInt.one;
    return createRandomInRange(min, max);
  }

  // ignore: slash_for_doc_comments
  /**
     * Return a value that can be used as x2 or x4 during round 1.
     * <p>
     * The returned value is a random value in the range <tt>[1, q-1]</tt>.
  */
  static BigInt generateX2(BigInt q) {
    var min = BigInt.one;
    var max = q - BigInt.one;
    return createRandomInRange(min, max);
  }

  // ignore: slash_for_doc_comments
  /**
     * Converts the given password to a {@link BigInteger}
     * for use in arithmetic calculations.
  */
  static BigInt calculateS(String password) {
    return decodeBigInt(Uint8List.fromList(password.codeUnits));
  }

  static BigInt calculateGx(BigInt p, BigInt g, BigInt x) {
    return g.modPow(x, p);
  }

  static BigInt calculateGa(BigInt p, BigInt gx1, BigInt gx3, BigInt gx4) {
    return (gx1 * gx3 * gx4) % p;
  }

  static BigInt calculateX2s(BigInt q, BigInt x2, BigInt s) {
    return (x2 * s) % q;
  }

  static BigInt calculateA(BigInt p, BigInt q, BigInt gA, BigInt x2s) {
    return gA.modPow(x2s, p);
  }

  static List<BigInt> calculateZeroKnowledgeProof(
      BigInt p,
      BigInt q,
      BigInt g,
      BigInt gx,
      BigInt x,
      String participantID,
      Digest digest,
      SecureRandom random) {
    var zeroKnowlegeProof = <BigInt>[];
    var vMin = BigInt.zero;
    var vMax = q - BigInt.one;
    var v = createRandomInRange(vMin, vMax);

    var gv = g.modPow(v, p);
    var h =
        calculateHashForZeroKnowledgeProof(g, gv, gx, participantID, digest);
    zeroKnowlegeProof.add(gv);
    zeroKnowlegeProof.add((v - (x * h)) % q);
    return zeroKnowlegeProof;
  }

  static BigInt calculateHashForZeroKnowledgeProof(
      BigInt g, BigInt gr, BigInt gx, String participantID, Digest digest) {
    digest.reset();
    updateDigestIncludingSize(digest, g);
    updateDigestIncludingSize(digest, gr);
    updateDigestIncludingSize(digest, gx);
    updateDigestIncludingSizeWithString(digest, participantID);

    var output = Uint8List(digest.digestSize);
    digest.doFinal(output, 0);
    return decodeBigInt(output);
  }

  static void validateGx4(BigInt gx4) {
    if (gx4 == BigInt.one) {
      throw Exception('g^x validation failed.  g^x should not be 1');
    }
  }

  static void validateGa(BigInt ga) {
    if (ga == BigInt.one) {
      throw Exception(
          'ga is equal to 1.  It should not be.  The chances of this happening are on the order of 2^160 for a 160-bit q.  Try again.');
    }
  }

  static void validateZKP(BigInt p, BigInt q, BigInt g, BigInt gx,
      List<BigInt> zkp, String participantID, Digest digest) {
    var gv = zkp[0];
    var r = zkp[1];

    var h =
        calculateHashForZeroKnowledgeProof(g, gv, gx, participantID, digest);
    if (!(gx.compareTo(BigInt.zero) >= 1 &&
        gx.compareTo(p) <= -1 &&
        gx.modPow(q, p).compareTo(BigInt.one) == 0 &&
        ((g.modPow(r, p) * gx.modPow(h, p)) % p).compareTo(gv) == 0)) {
      throw Exception('Zero Knowledge Proof validation failed');
    }
  }

  static BigInt calculateKeyingMaterial(
      BigInt p, BigInt q, BigInt gx4, BigInt x2, BigInt s, BigInt b) {
    return (gx4.modPow(-(x2 * s) % q, p) * b).modPow(x2, p);
  }

  static void validateParticipantIDdiffers(
      String participanID1, String participantID2) {
    if (participanID1 == participantID2) {
      throw Exception('Both participants are using the same participant ID');
    }
  }

  static void validateParticipantIDsEqual(
      String expectedParticipant, String actualParticipant) {
    if (!(expectedParticipant == actualParticipant)) {
      throw Exception('Received payload from incorrect partner');
    }
  }

  static void updateDigest(Digest digest, BigInt bigInteger) {
    var byteArray = encodeBigInt(bigInteger);
    digest.update(byteArray, 0, byteArray.length);
    byteArray.fillRange(0, byteArray.length - 1, 0);
  }

  static void validateNotNull(Object object, String description) {
    if (object == Null) {
      throw Exception('$description must not be null');
    }
  }

  static BigInt calculateMacTag(
      String participantID,
      String partnerPatricipantID,
      BigInt gx1,
      BigInt gx2,
      BigInt gx3,
      BigInt gx4,
      BigInt keyMaterial,
      Digest digest) {
    var macKey = calculateMacKey(keyMaterial, digest);
    var mac = HMac.withDigest(digest);
    var macOutput = Uint8List(mac.macSize);
    mac.init(KeyParameter(macKey));
    updateMacWithString(mac, 'KC_1_U');
    updateMacWithString(mac, participantID);
    updateMacWithString(mac, partnerPatricipantID);
    updateMac(mac, gx1);
    updateMac(mac, gx2);
    updateMac(mac, gx3);
    updateMac(mac, gx4);

    mac.doFinal(macOutput, 0);
    macKey.fillRange(0, macKey.length, 0);

    return decodeBigInt(macOutput);
  }

  static Uint8List calculateMacKey(BigInt keyingMaterial, Digest digest) {
    digest.reset();
    updateDigest(digest, keyingMaterial);
    updateDigestWithString(digest, 'JPAKE_KC');
    var output = Uint8List(digest.digestSize);
    digest.doFinal(output, 0);
    return output;
  }

  static void updateMac(Mac mac, BigInt bigInteger) {
    var byteArray = encodeBigInt(bigInteger);
    mac.update(byteArray, 0, byteArray.length);
    byteArray.fillRange(0, byteArray.length - 1, 0);
  }

  static void updateMacWithString(Mac mac, String string) {
    var byteArray = Uint8List.fromList(string.codeUnits);
    mac.update(byteArray, 0, byteArray.length);
    byteArray.fillRange(0, byteArray.length - 1, 0);
  }

  static void validateMACTag(
      String participantId,
      String partnerParticipantId,
      BigInt gx1,
      BigInt gx2,
      BigInt gx3,
      BigInt gx4,
      BigInt keyingMaterial,
      Digest digest,
      BigInt partnerMacTag) {
    var expectedMacTag = calculateMacTag(partnerParticipantId, participantId,
        gx3, gx4, gx1, gx2, keyingMaterial, digest);
    if (!(expectedMacTag == partnerMacTag)) {
      throw Exception('Partner MACTag validation failed');
    }
  }

  static Uint8List encodeBigInt(BigInt number) {
    final _byteMask = BigInt.from(0xff);
    // Not handling negative numbers. Decide how you want to do that.
    var size = (number.bitLength + 7) >> 3;
    var result = Uint8List(size);
    for (var i = 0; i < size; i++) {
      result[size - i - 1] = (number & _byteMask).toInt();
      number = number >> 8;
    }
    return result;
  }

  static BigInt decodeBigInt(Uint8List bytes) {
    var result = BigInt.from(0);
    for (var i = 0; i < bytes.length; i++) {
      result += BigInt.from(bytes[bytes.length - i - 1]) << (8 * i);
    }
    return result;
  }

  static void updateDigestIncludingSize(Digest digest, BigInt bigInteger) {
    var byteArray = encodeBigInt(bigInteger);
    digest.update(intToByteArray(byteArray.length), 0, 4);
    digest.update(byteArray, 0, byteArray.length);
    byteArray.fillRange(0, byteArray.length - 1, 0);
  }

  static Uint8List intToByteArray(int value) {
    var elements = <int>[value >> 24, value >> 16, value >> 8, value];
    return Uint8List.fromList(elements);
  }

  static void updateDigestWithString(Digest digest, String string) {
    var byteArray = Uint8List.fromList(string.codeUnits);
    digest.update(byteArray, 0, byteArray.length);
  }

  static void updateDigestIncludingSizeWithString(
      Digest digest, String string) {
    var byteArray = Uint8List.fromList(string.codeUnits);
    digest.update(intToByteArray(byteArray.length), 0, 4);
    digest.update(byteArray, 0, byteArray.length);
    byteArray.fillRange(0, byteArray.length - 1, 0);
  }

// ignore: slash_for_doc_comments
/**
 * Convert a bytes array to a BigInt
 */

  static BigInt createRandomInRange(BigInt min, BigInt max) {
    var cmp = min.compareTo(max);
    if (cmp >= 0) {
      if (cmp > 0) {
        throw Exception('min may not be bigger than max');
      }
      return min;
    }
    if (min.bitLength > max.bitLength / 2) {
      return createRandomInRange(BigInt.zero, max - min) + min;
    }

    for (var i = 0; i < MAX_ITERATIONS; ++i) {
      var x = randomBigInt(max.bitLength);
      if (x.compareTo(min) >= 0 && x.compareTo(max) <= 0) {
        return x;
      }
    }
    return randomBigInt((max - min).bitLength - 1) + min;
  }
}
