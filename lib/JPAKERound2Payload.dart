import 'package:jpake/JPAKEUtil.dart';

class JPAKERound2Payload {
  late String _participantID;
  late BigInt _a;
  late List<BigInt> _knowledgeProofForX2s;

  JPAKERound2Payload(
      String participantID, BigInt a, List<BigInt> knowledgeProofForX2s) {
    JPAKEUtil.validateNotNull(participantID, 'participantID');
    JPAKEUtil.validateNotNull(a, 'a');
    JPAKEUtil.validateNotNull(knowledgeProofForX2s, 'KnowledgeProofForX2s');

    _participantID = participantID;
    _a = a;
    _knowledgeProofForX2s = List<BigInt>.from(knowledgeProofForX2s);
  }

  String getParticipantID() {
    return _participantID;
  }

  BigInt getA() {
    return _a;
  }

  List<BigInt> getKnowledgeProofForX2() {
    return List<BigInt>.from(_knowledgeProofForX2s);
  }
}
