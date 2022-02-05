"""
collection of utility functions
"""

# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import struct
import sys

__all__ = [
    # constants
    # functions
    'hexdump',
    'group',
    'key_handle_to_int',
    # classes
]
import ksmexception
import defines
import aead_cmd

def hexdump(src, length=8):
    """ Produce a string hexdump of src, for debug output."""
    if not src:
        return str(src)
    src = input_validate_str(src, 'src')
    offset = 0
    result = ''
    for this in group(src, length):
        hex_s = ' '.join(["%02x" % ord(x) for x in this])
        result += "%04X   %s\n" % (offset, hex_s)
        offset += length
    return result

def group(data, num):
    """ Split data into chunks of num chars each """
    return [data[i:i+num] for i in range(0, len(data), num)]

def key_handle_to_int(this):
    """
    Turn "123" into 123 and "KSM1" into 827151179
    (0x314d534b, 'K' = 0x4b, S = '0x53', M = 0x4d).

    YHSM is little endian, so this makes the bytes KSM1 appear
    in the most human readable form in packet traces.
    """
    try:
        num = int(this)
        return num
    except ValueError:
        if this[:2] == "0x":
            return int(this, 16)
        if (len(this) == 4):
            num = int.from_bytes(this, byteorder='little')
            return num
    raise ksmexception.YHSM_Error("Could not parse key_handle '{}'".format(this))

def input_validate_str(string, name, max_len=None, exact_len=None):
    """ Input validation for strings. """
    if type(string) is not str:
        raise ksmexception.YHSM_WrongInputType(name, str, type(string))
    if max_len != None and len(string) > max_len:
        raise ksmexception.YHSM_InputTooLong(name, max_len, len(string))
    if exact_len != None and len(string) != exact_len:
        raise ksmexception.YHSM_WrongInputSize(name, exact_len, len(string))
    return string

def input_validate_bytes(byt, name, max_len=None, exact_len=None):
    """ Input validation for bytes. """
    #benjamin
    if type(byt) is not bytes:
        raise ksmexception.YHSM_WrongInputType(name, bytes, type(byt))
    if max_len != None and len(byt) > max_len:
        raise ksmexception.YHSM_InputTooLong(name, max_len, len(byt))
    if exact_len != None and len(byt) != exact_len:
        raise ksmexception.YHSM_WrongInputSize(name, exact_len, len(byt))
    return byt

def input_validate_int(value, name, max_value=None):
    """ Input validation for integers. """
    if type(value) is not int:
        raise ksmexception.YHSM_WrongInputType(name, int, type(value))
    if max_value != None and value > max_value:
        raise ksmexception.YHSM_WrongInputSize(name, max_value, value)
    return value

def input_validate_nonce(nonce, name='nonce', pad = False):
    """ Input validation for nonces. """
    if type(nonce) is not bytes:
        raise ksmexception.YHSM_WrongInputType( \
            name, bytes, type(nonce))
    if len(nonce) > defines.YSM_AEAD_NONCE_SIZE:
        raise ksmexception.YHSM_InputTooLong(
            name, defines.YSM_AEAD_NONCE_SIZE, len(nonce))
    if pad:
        return nonce.ljust(defines.YSM_AEAD_NONCE_SIZE, b'\x00')
    else:
        return nonce

def input_validate_key_handle(key_handle, name='key_handle'):
    """ Input validation for key_handles. """
    if type(key_handle) is not int:
        try:
            return key_handle_to_int(key_handle)
        except ksmexception.YHSM_Error:
            raise ksmexception.YHSM_WrongInputType(name, int, type(key_handle))
    return key_handle

def input_validate_yubikey_secret(data, name='data'):
    """ Input validation for YHSM_YubiKeySecret or string. """
    if isinstance(data, aead_cmd.YHSM_YubiKeySecret):
        data = data.pack()
    return input_validate_bytes(data, name)

def input_validate_aead(aead, name='aead', expected_len=None, max_aead_len = defines.YSM_AEAD_MAX_SIZE):
    """ Input validation for YHSM_GeneratedAEAD or bytes. """
    if isinstance(aead, aead_cmd.YHSM_GeneratedAEAD):
        aead = aead.data
    if expected_len != None:
        return input_validate_bytes(aead, name, exact_len = expected_len)
    else:
        return input_validate_bytes(aead, name, max_len=max_aead_len)

def validate_cmd_response_int(name, got, expected):
    """
    Check that some value returned in the response to a command matches what
    we put in the request (the command).
    """
    if got != expected:
        raise ksmexception.pyhsm
    return got


def validate_cmd_response_hex(name, got, expected):
    """
    Check that some value returned in the response to a command matches what
    we put in the request (the command).
    """
    if got != expected:
        raise ksmexception.pyhsm
    return got


def validate_cmd_response_bytes(name, got, expected, hex_encode=True):
    """
    Check that some value returned in the response to a command matches what
    we put in the request (the command).
    """
    if got != expected:
        if hex_encode:
            got_s = got.hex()
            exp_s = expected.hex()
        else:
            got_s = got
            exp_s = expected
        raise ksmexception.pyhsm
    return got

def validate_cmd_response_nonce(got, used):
    """
    Check that the returned nonce matches nonce used in request.

    A request nonce of 000000000000 means the HSM should generate a nonce internally though,
    so if 'used' is all zeros we actually check that 'got' does NOT match 'used'.
    """
    if used == b'\x00' * defines.YSM_EAD_NONCE_SIZE:
        if got == used:
            raise ksmexception.pyhsm
        return got
    return validate_cmd_response_bytes('nonce', got, used)
