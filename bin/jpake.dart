import 'dart:typed_data';

import 'package:jpake/JPAKEParticipant.dart';
import 'package:jpake/JPAKEPrimeOrderGroups.dart';
import 'package:jpake/JPAKEUtil.dart';
import 'package:ninja_prime/ninja_prime.dart';
import 'package:pointycastle/export.dart';

final nonce = randomBigInt(128);
void main(List<String> args) {
  final group = JPAKEPrimeOrderGroups.NIST_3072;
  final p = group.getP();
  final q = group.getQ();
  final g = group.getG();

  const alicePassword = 'password';
  const bobPassword = 'password';

  print('***********Initializing************');
  print('Public parameters for the cyclic group:');
  print('p ( ${p.bitLength} bits): ' + p.toRadixString(16));
  print('q ( ${q.bitLength} bits): ' + q.toRadixString(16));
  print('g ( ${p.bitLength} bits): ' + g.toRadixString(16));
  print('p mod q = ${(p % q).toString()}');
  print('g^{q} mod p = ${g.modPow(q, p).toRadixString(16)}');
  print('');

  print('Secret Passwords:');
  print('Alice password: ' + alicePassword);
  print('Bob Password: ' + bobPassword);

  final digest = SHA256Digest();
  final random = SecureRandom('AES/CTR/PRNG');

  final alice = JPAKEParticipant('alice', alicePassword, group, digest, random);
  final bob = JPAKEParticipant('bob', bobPassword, group, digest, random);

  final aliceRound1Payload = alice.createRound1PayloadToSend();
  final bobRound1Payload = bob.createRound1PayloadToSend();

  print('**************Round1**************************');
  print('Alice sends to bob:');
  print('g^{x1} = ' + aliceRound1Payload.getGx1().toRadixString(16));
  print('g^{x2}=' + aliceRound1Payload.getGx2().toRadixString(16));
  print('KP{x1}={' +
      aliceRound1Payload.getKnowledgeProofForX1()[0].toRadixString(16) +
      '};{' +
      aliceRound1Payload.getKnowledgeProofForX1()[1].toRadixString(16) +
      '}');
  print('KP{x2}={' +
      aliceRound1Payload.getKnowledgeProofForX2()[0].toRadixString(16) +
      '};{' +
      aliceRound1Payload.getKnowledgeProofForX2()[1].toRadixString(16) +
      '}');
  print('');
  print('Bob sends to Alice:');
  print('g^{x3} = ' + bobRound1Payload.getGx1().toRadixString(16));
  print('g^{x4}=' + bobRound1Payload.getGx2().toRadixString(16));
  print('KP{x3}={' +
      bobRound1Payload.getKnowledgeProofForX1()[0].toRadixString(16) +
      '};{' +
      bobRound1Payload.getKnowledgeProofForX1()[1].toRadixString(16) +
      '}');
  print('KP{x4}={' +
      bobRound1Payload.getKnowledgeProofForX2()[0].toRadixString(16) +
      '};{' +
      bobRound1Payload.getKnowledgeProofForX2()[1].toRadixString(16) +
      '}');
  print('');

  alice.validateRound1PayLoadReceived(bobRound1Payload);
  print('Alice checks g^{x4}!=1: OK');
  print('Alice checks KP{x3}: OK');
  print('Alice checks KP{x4}: OK');
  print('');

  bob.validateRound1PayLoadReceived(aliceRound1Payload);
  print('Bob checks g^{x4}!=1: OK');
  print('Bob checks KP{x3}: OK');
  print('Bob checks KP{x4}: OK');
  print('');

  final aliceRound2Payload = alice.createRound2PayloadToSend();
  final bobRound2Payload = bob.createRound2PayloadToSend();

  print('***************** Round 2 ***************************');
  print('ALice sends to Bob: ');
  print('A = ' + aliceRound2Payload.getA().toRadixString(16));
  print('KP{x2*s}={' +
      aliceRound2Payload.getKnowledgeProofForX2()[0].toRadixString(16) +
      '},{' +
      aliceRound2Payload.getKnowledgeProofForX2()[1].toRadixString(16) +
      '}');
  print('');
  print('Bob sends to Alice: ');
  print('A = ' + bobRound2Payload.getA().toRadixString(16));
  print('KP{x2*s}={' +
      bobRound2Payload.getKnowledgeProofForX2()[0].toRadixString(16) +
      '},{' +
      bobRound2Payload.getKnowledgeProofForX2()[1].toRadixString(16) +
      '}');
  print('');

  alice.validateRound2PayloadReceived(bobRound2Payload);
  print('Alice checks KP{x4*s}: OK');
  bob.validateRound2PayloadReceived(aliceRound2Payload);
  print('Bob checks KP{x2*s}: OK');

  final aliceKeyingMaterial = alice.calculateKeyingMAterial();
  final bobKeyingMaterial = bob.calculateKeyingMAterial();

  print('****************** After Round 2************************');
  print('Alice computes key material:');
  print(aliceKeyingMaterial.toRadixString(16));
  print('Bob Keying Material ');
  print(bobKeyingMaterial.toRadixString(16));
  print('');

  final aliceKey = deriveSessionKey(aliceKeyingMaterial);
  final bobKey = deriveSessionKey(bobKeyingMaterial);

  print('Alice Key = ' + aliceKey.toRadixString(16));
  print('Bob Key = ' + bobKey.toRadixString(16));

  final aliceRound3Payload =
      alice.createRound3PayloadToSend(aliceKeyingMaterial);
  final bobRound3Payload = bob.createRound3PayloadToSend(bobKeyingMaterial);

  print('************* Round 3 **************************************');
  print('Alice sends to bob ');
  print('MacTag=' + aliceRound3Payload.getMacTag().toRadixString(16));
  print('Bob sends to alice');
  print('MacTag=' + bobRound3Payload.getMacTag().toRadixString(16));
  print('');

//        System.out.println();
//        System.out.println("MacTags validated, therefore the keying material matches.");

  alice.validateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);
  print('Alice checks MacTag: OK');

  bob.validateRound3PayloadReceived(aliceRound3Payload, bobKeyingMaterial);
  print('Bob checks MacTag: OK');

  print('');
  print(
      'MAC Tag validated hence keying material matches. JPAKE SUCCESSFULLY IMPLEMENTED');
}

BigInt deriveSessionKey(BigInt keyingMaterial) {
  final digest = SHA256Digest();
  final byteArray = JPAKEUtil.encodeBigInt(keyingMaterial);
  final output = Uint8List(digest.digestSize);
  digest.update(byteArray, 0, byteArray.length);
  digest.doFinal(output, 0);
  return JPAKEUtil.decodeBigInt(output);
}
