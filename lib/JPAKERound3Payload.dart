class JPAKERound3Payload {
  String _participantID;
  BigInt _macTag;

  JPAKERound3Payload(this._participantID, this._macTag);

  String getPatricipantID() {
    return _participantID;
  }

  BigInt getMacTag() {
    return _macTag;
  }
}
