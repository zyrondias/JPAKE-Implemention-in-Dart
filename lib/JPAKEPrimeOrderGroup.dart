import 'package:jpake/JPAKEUtil.dart';
import 'package:ninja_prime/ninja_prime.dart';

class JPAKEPrimeOrderGroup {
  BigInt p = BigInt.zero;
  BigInt q = BigInt.zero;
  BigInt g = BigInt.zero;

  JPAKEPrimeOrderGroup(BigInt p, BigInt q, BigInt g, bool skipChecks) {
    JPAKEUtil.validateNotNull(p, 'p');
    JPAKEUtil.validateNotNull(q, 'q');
    JPAKEUtil.validateNotNull(g, 'g');

    if (!skipChecks) {
      if (((p - BigInt.one) % q) == BigInt.zero) {
        throw Exception('p-1 must be divisible by q');
      }
      if (g.compareTo(BigInt.two) == -1 || g.compareTo(p - BigInt.one) == 1) {
        throw Exception('g must be in [2, p-1]');
      }
      if (!(g.modPow(q, p) == BigInt.one)) {
        throw Exception('g^q mod p must equal 1');
      }
      if (!p.probablyPrimeMillerRabin(20)) {
        throw Exception('P must be prime');
      }
      if (!q.probablyPrimeMillerRabin(20)) {
        throw Exception('q must be prime');
      }
    }

    this.p = p;
    this.q = q;
    this.g = g;
  }

  BigInt getP() {
    return p;
  }

  BigInt getQ() {
    return q;
  }

  BigInt getG() {
    return g;
  }
}
