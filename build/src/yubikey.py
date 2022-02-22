"""
helper functions to work with Yubikeys and YubiHSM
"""

# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import binascii
import string
import sys

__all__ = [
    # constants
    # functions
    'validate_otp',
    'validate_yubikey_with_aead',
    'modhex_encode',
    'modhex_decode',
    'split_id_otp',
    # classes
 ]

import ksmexception
import util
import aead_cmd

def validate_otp(hsm, from_key):
    """
    Try to validate an OTP from a YubiKey using the internal database
    on the YubiHSM.

    `from_key' is the modhex encoded string emitted when you press the
    button on your YubiKey.

    Will only return on succesfull validation. All failures will result
    in an L{ksmexception.YHSM_CommandFailed}.

    @param hsm: The YHSM instance
    @param from_key: The OTP from a YubiKey (in modhex)
    @type hsm: L{YHSM}
    @type from_key: string

    @returns: validation response, if successful
    @rtype: L{YHSM_ValidationResult}

    @see: L{db_cmd.YHSM_Cmd_DB_Validate_OTP.parse_result}
    """
    public_id, otp = split_id_otp(from_key)
    return hsm.db_validate_yubikey_otp(modhex_decode(public_id).decode('hex'),
                                       modhex_decode(otp).decode('hex')
                                       )

def validate_yubikey_with_aead(hsm, from_key, aead, key_handle):

    from_key = util.input_validate_str(from_key, 'from_key', max_len = 48)
    
    nonce = aead.nonce
    aead = util.input_validate_aead(aead)
    key_handle = util.input_validate_key_handle(key_handle)

    public_id, otp = split_id_otp(from_key)

    public_id = modhex_decode(public_id)
    otp = modhex_decode(otp)

    if not nonce:
        nonce = bytes.fromhex(public_id)
    
    return hsm.validate_aead_otp(nonce, bytes.fromhex(otp),
        key_handle, aead)

def modhex_decode(data):
    """
    Convert a modhex string to ordinary hex.

    @param data: Modhex input
    @type data: string

    @returns: Hex
    @rtype: str
    """
    t_map = str.maketrans("cbdefghijklnrtuv", "0123456789abcdef")
    return data.translate(t_map)

def modhex_encode(data):
    """
    Convert an ordinary hex string to modhex.

    @param data: Hex input
    @type data: string

    @returns: Modhex
    @rtype: str
    """
    t_map = str.maketrans("0123456789abcdef", "cbdefghijklnrtuv")
    return data.translate(t_map)

def split_id_otp(from_key):
    """
    Separate public id from OTP given a YubiKey OTP as input.

    @param from_key: The OTP from a YubiKey (in modhex)
    @type from_key: string

    @returns: public_id and OTP
    @rtype: tuple of string
    """
    if len(from_key) > 32:
        public_id, otp = from_key[:-32], from_key[-32:]
    elif len(from_key) == 32:
        public_id = ''
        otp = from_key
    else:
        raise ksmexception.YHSM_Error("Bad from_key length %i < 32 : %s" \
                                       % (len(from_key), from_key))
    return public_id, otp
