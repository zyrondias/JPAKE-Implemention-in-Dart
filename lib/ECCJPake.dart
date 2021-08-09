import 'package:jpake/JPAKEUtil.dart';
import 'package:pointycastle/pointycastle.dart';

main(List<String> args) {
  final alicePassword = 'password';
  final bobPassword = 'password';
  final curve = ECDomainParameters('secp256k1');
  final s = JPAKEUtil.calculateS(alicePassword);

// Alice generates
  final x1 = JPAKEUtil.createRandomInRange(BigInt.zero, curve.n - BigInt.one);
  final x2 = JPAKEUtil.createRandomInRange(BigInt.zero, curve.n - BigInt.one);

// Bob generates
  final x3 = JPAKEUtil.createRandomInRange(BigInt.zero, curve.n - BigInt.one);
  final x4 = JPAKEUtil.createRandomInRange(BigInt.zero, curve.n - BigInt.one);

  // Alice generates
  final x1G = curve.G * x1;
  final x2G = curve.G * x2;

  // Bob Generates
  final x3G = curve.G * x3;
  final x4G = curve.G * x4;

  var A = x1G! + x3G!;
  A = A! + x4G;
  A = A! * (x2 * s);

//   B = point_add(x1G,x2G)
// B = point_add(B,x3G)
// B = scalar_mult(x4*s,B)

  var B = x1G + x2G;
  B = B! + x3G;
  B = B! * (x4 * s);

//   Ka = scalar_mult(x2,point_add(B,point_neg(scalar_mult(x2*s,x4G))))
// # Bob computes Kb = (A - (G2 x [x4*s])) x [x4]
// Kb = scalar_mult(x4,point_add(A,point_neg(scalar_mult(x4*s,x2G))))
  final Ka = B! - ((x4G! * (x2 * s))! * x2)!;
  final Kb = A! - ((x2G! * (x4 * s))! * x4)!;

  print('Shared password is ' + alicePassword);
  print('****************Alice params********************');
  print(
      'Alice x1=${x1.toRadixString(16)}, x2=${x2.toRadixString(16)}\nAlice sends: x1G =${x1G.toString()}, x2G (mod p)=${x2G.toString()}');
  print('');
  print('*********************Bob params***************************');
  print(
      'Bob x3=${x3.toRadixString(16)}, x4=${x4.toRadixString(16)}\nBob sends: x3G =${x3G.toString()}, x4G =${x4G.toString()}');

  print('===Alice parameters=== ');
  print('Alice sends A=${A.toString()}');

  print('===Bob parameters===');
  print('Bob sends B=${B.toString()}');

  final aliceKey = Ka!.x!.toBigInteger();
  final bobKey = Kb!.x!.toBigInteger();

  print('Alice Key : ${aliceKey!.toRadixString(16)}');
  print('Bob Key : ${bobKey!.toRadixString(16)}');

  print('JPAKE using Eliptical Curve Implemented: ${aliceKey == bobKey}');
}
