import 'package:jpake/JPAKEUtil.dart';

class JPAKERound1Payload {
  late String _participantID;
  late BigInt _gx1;
  late BigInt _gx2;
  late List<BigInt> _knowledgeProofForX1;
  late List<BigInt> _knowledgeProofForX2;

  JPAKERound1Payload(String participantID, BigInt gx1, BigInt gx2,
      List<BigInt> knowlegeProofForX1, List<BigInt> knowledgeProofForX2) {
    JPAKEUtil.validateNotNull('particpantID', 'participantID');
    JPAKEUtil.validateNotNull(gx1, 'gx1');
    JPAKEUtil.validateNotNull(gx2, 'gx2');
    JPAKEUtil.validateNotNull(knowlegeProofForX1, 'knowlegeProofForX1');
    JPAKEUtil.validateNotNull(knowledgeProofForX2, 'knowledgeProofForX2');

    _participantID = participantID;
    _gx1 = gx1;
    _gx2 = gx2;
    _knowledgeProofForX1 = List<BigInt>.from(knowlegeProofForX1);
    _knowledgeProofForX2 = List<BigInt>.from(knowledgeProofForX2);
  }

  String getParticipantID() {
    return _participantID;
  }

  BigInt getGx1() {
    return _gx1;
  }

  BigInt getGx2() {
    return _gx2;
  }

  List<BigInt> getKnowledgeProofForX1() {
    return List<BigInt>.from(_knowledgeProofForX1);
  }

  List<BigInt> getKnowledgeProofForX2() {
    return List<BigInt>.from(_knowledgeProofForX2);
  }
}
