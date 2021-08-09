import 'package:jpake/JPAKEPrimeOrderGroup.dart';
import 'package:jpake/JPAKERound1Payload.dart';
import 'package:jpake/JPAKERound2Payload.dart';
import 'package:jpake/JPAKERound3Payload.dart';
import 'package:jpake/JPAKEUtil.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/pointycastle.dart';

class JPAKEParticipant {
  static final int STATE_INITIALIZED = 0;
  static final int STATE_ROUND_1_CREATED = 10;
  static final int STATE_ROUND_1_VALIDATED = 20;
  static final int STATE_ROUND_2_CREATED = 30;
  static final int STATE_ROUND_2_VALIDATED = 40;
  static final int STATE_KEY_CALCULATED = 50;
  static final int STATE_ROUND_3_CREATED = 60;
  static final int STATE_ROUND_3_VALIDATED = 70;

  late String _participantID;
  late String _password;
  late Digest _digest;
  late SecureRandom _random;

  late BigInt _p;
  late BigInt _q;
  late BigInt _g;

  late String partnerParticipantID;

  late BigInt? _x1;
  late BigInt? _x2;
  late BigInt? _gx1;
  late BigInt? _gx2;
  late BigInt? _gx3;
  late BigInt? _gx4;
  late BigInt? _b;

  late int _state;

  JPAKEParticipant(String participantID, String password,
      JPAKEPrimeOrderGroup group, Digest digest, SecureRandom random) {
    JPAKEUtil.validateNotNull(participantID, 'participantID');
    JPAKEUtil.validateNotNull(password, 'password');
    JPAKEUtil.validateNotNull(group, 'group');
    JPAKEUtil.validateNotNull(digest, 'digest');
    JPAKEUtil.validateNotNull(random, 'random');

    if (password.isEmpty) {
      throw Exception('Password cannot be empty');
    }
    _participantID = participantID;
    _password = password;
    _p = group.getP();
    _q = group.getQ();
    _g = group.getG();
    _digest = digest;
    _random = random;
    _state = STATE_INITIALIZED;
  }

  int getState() {
    return _state;
  }

  JPAKERound1Payload createRound1PayloadToSend() {
    if (_state >= STATE_ROUND_1_CREATED) {
      throw Exception(
          'Round 1 payload already created for ' + partnerParticipantID);
    }
    // TODO: Add secure random
    _x1 = JPAKEUtil.generateX1(_q);
    _x2 = JPAKEUtil.generateX2(_q);

    _gx1 = JPAKEUtil.calculateGx(_p, _g, _x1!);
    _gx2 = JPAKEUtil.calculateGx(_p, _g, _x2!);
    var knowledgeProofForX1 = JPAKEUtil.calculateZeroKnowledgeProof(
        _p, _q, _g, _gx1!, _x1!, _participantID, _digest, _random);
    var knowledgeProofForX2 = JPAKEUtil.calculateZeroKnowledgeProof(
        _p, _q, _g, _gx2!, _x2!, _participantID, _digest, _random);

    _state = STATE_ROUND_1_CREATED;
    return JPAKERound1Payload(
        _participantID, _gx1!, _gx2!, knowledgeProofForX1, knowledgeProofForX2);
  }

  void validateRound1PayLoadReceived(JPAKERound1Payload round1PayloadReceived) {
    if (_state >= STATE_ROUND_1_VALIDATED) {
      throw Exception('Validation Already attempted for ' + _participantID);
    }

    partnerParticipantID = round1PayloadReceived.getParticipantID();
    _gx3 = round1PayloadReceived.getGx1();
    _gx4 = round1PayloadReceived.getGx2();

    var knowledgeProofForX3 = round1PayloadReceived.getKnowledgeProofForX1();
    var knowledgeProofForX4 = round1PayloadReceived.getKnowledgeProofForX2();

    JPAKEUtil.validateParticipantIDdiffers(
        _participantID, round1PayloadReceived.getParticipantID());
    JPAKEUtil.validateGx4(_gx4!);
    JPAKEUtil.validateZKP(_p, _q, _g, _gx3!, knowledgeProofForX3,
        round1PayloadReceived.getParticipantID(), _digest);
    JPAKEUtil.validateZKP(_p, _q, _g, _gx4!, knowledgeProofForX4,
        round1PayloadReceived.getParticipantID(), _digest);
    _state = STATE_ROUND_1_VALIDATED;
  }

  JPAKERound2Payload createRound2PayloadToSend() {
    if (_state >= STATE_ROUND_2_CREATED) {
      throw Exception('Round 2 payload aready created');
    }

    if (_state < STATE_ROUND_1_VALIDATED) {
      throw Exception(
          'Round1 payload must be validated prior to creating Round2 payload for ' +
              _participantID);
    }

    var gA = JPAKEUtil.calculateGa(_p, _gx1!, _gx3!, _gx4!);
    var s = JPAKEUtil.calculateS(_password);
    var x2s = JPAKEUtil.calculateX2s(_q, _x2!, s);
    var A = JPAKEUtil.calculateA(_p, _q, gA, x2s);
    var knowledgeProofForX2s = JPAKEUtil.calculateZeroKnowledgeProof(
        _p, _q, gA, A, x2s, _participantID, _digest, _random);
    _state = STATE_ROUND_2_CREATED;
    return JPAKERound2Payload(_participantID, A, knowledgeProofForX2s);
  }

  void validateRound2PayloadReceived(JPAKERound2Payload round2payloadReceived) {
    if (_state >= STATE_ROUND_2_VALIDATED) {
      throw Exception('Validation Already attempted for round2 payload for ' +
          _participantID);
    }
    if (_state < STATE_ROUND_1_VALIDATED) {
      throw Exception(
          'Round 1 payload must be validated prior to validating round 2 payload for ' +
              _participantID);
    }
    var gB = JPAKEUtil.calculateGa(_p, _gx3!, _gx1!, _gx2!);
    _b = round2payloadReceived.getA();
    var knowledgeProofForX4s = round2payloadReceived.getKnowledgeProofForX2();

    JPAKEUtil.validateParticipantIDdiffers(
        _participantID, round2payloadReceived.getParticipantID());
    JPAKEUtil.validateParticipantIDsEqual(
        partnerParticipantID, round2payloadReceived.getParticipantID());
    JPAKEUtil.validateGa(gB);
    JPAKEUtil.validateZKP(_p, _q, gB, _b!, knowledgeProofForX4s,
        round2payloadReceived.getParticipantID(), _digest);

    _state = STATE_ROUND_2_VALIDATED;
  }

  BigInt calculateKeyingMAterial() {
    if (_state > STATE_KEY_CALCULATED) {
      throw Exception('Key already calculated');
    }
    if (_state < STATE_ROUND_2_VALIDATED) {
      throw Exception(
          'Round 2 payload must be validated prior to creating key for ' +
              _participantID);
    }

    var s = JPAKEUtil.calculateS(_password);
    _password = '';
    var keyingMaterial =
        JPAKEUtil.calculateKeyingMaterial(_p, _q, _gx4!, _x2!, s, _b!);
    _x1 = null;
    _x2 = null;
    _b = null;
    _state = STATE_KEY_CALCULATED;
    return keyingMaterial;
  }

  JPAKERound3Payload createRound3PayloadToSend(BigInt keyingMaterial) {
    if (_state >= STATE_ROUND_3_CREATED) {
      throw Exception('Round3 payload already created for ' + _participantID);
    }
    if (_state < STATE_KEY_CALCULATED) {
      throw Exception(
          'Keying material must be calculated prior to creating round 3 payload for ' +
              _participantID);
    }

    var macTag = JPAKEUtil.calculateMacTag(_participantID, partnerParticipantID,
        _gx1!, _gx2!, _gx3!, _gx4!, keyingMaterial, _digest);

    _state = STATE_ROUND_3_CREATED;
    return JPAKERound3Payload(_participantID, macTag);
  }

  void validateRound3PayloadReceived(
      JPAKERound3Payload round3PayloadReceived, BigInt keyingMaterial) {
    if (_state >= STATE_ROUND_3_VALIDATED) {
      throw Exception('Validation already attempted for round3 payload for ' +
          _participantID);
    }
    if (_state < STATE_KEY_CALCULATED) {
      throw Exception(
          'Keying material must be calculated and validated prior to validating round 3 payload for ' +
              _participantID);
    }
    JPAKEUtil.validateParticipantIDdiffers(
        _participantID, round3PayloadReceived.getPatricipantID());
    JPAKEUtil.validateParticipantIDsEqual(
        partnerParticipantID, round3PayloadReceived.getPatricipantID());
    JPAKEUtil.validateMACTag(
        _participantID,
        partnerParticipantID,
        _gx1!,
        _gx2!,
        _gx3!,
        _gx4!,
        keyingMaterial,
        _digest,
        round3PayloadReceived.getMacTag());

    _gx1 = null;
    _gx2 = null;
    _gx3 = null;
    _gx4 = null;

    _state = STATE_ROUND_3_VALIDATED;
  }
}
