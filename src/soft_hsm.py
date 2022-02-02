"""
functions for implementing parts of the HSMs machinery in software
"""

# Copyright (c) 2012 Yubico AB
# See the file COPYING for licence statement.

import struct
import json
import os
import sys

import aead_cmd
import soft_hsm

__all__ = [
    # constants
    # functions
    'aesCCM',
    'crc16',
    # classes
    'SoftYHSM'
]

import binascii
import ksmexception
import validate_cmd
import defines
import util
from Crypto.Cipher import AES


def _xor_block(a, b):
    """ XOR two blocks of equal length. """
    return bytes([x ^ y for (x, y) in zip(a, b)])

class _ctr_counter():
    """
    An object implementation of the struct aesCtr.
    """
    def __init__(self, key_handle, nonce, flags = None, value = 0):
        self.flags = defines.YSM_CCM_CTR_SIZE - 1 if flags is None else flags
        self.key_handle = key_handle
        self.nonce = nonce
        self.value = value

    def __next__(self):
        """
        Return next counter value, encoded into YSM_BLOCK_SIZE.
        """
        self.value += 1
        return self.pack()

    def pack(self):
        fmt = b'< B I %is BBB 2s' % (defines.YSM_AEAD_NONCE_SIZE)
        val = struct.pack('> H', self.value)
        return struct.pack(fmt,
                           self.flags,
                           self.key_handle,
                           self.nonce,
                           0, 0, 0, # rfu
                           val
                           )


class _cbc_mac():
    def __init__(self, key, key_handle, nonce, data_len):
        """
        Initialize CBC-MAC like the YubiHSM does.
        """
        flags = (((defines.YSM_AEAD_MAC_SIZE - 2) // 2) << 3) | (defines.YSM_CCM_CTR_SIZE - 1)
        t = _ctr_counter(key_handle, nonce, flags = flags, value = data_len)
        t_mac = t.pack()
        self.mac_aes = AES.new(key, AES.MODE_ECB)
        self.mac = self.mac_aes.encrypt(t_mac)

    def update(self, block):
        block = block.ljust(defines.YSM_BLOCK_SIZE, b"\x00")
        t1 = _xor_block(self.mac, block)
        t2 = self.mac_aes.encrypt(t1)
        self.mac = t2

    def finalize(self, block):
        """
        The final step of CBC-MAC encrypts before xor.
        """
        t1 = self.mac_aes.encrypt(block)
        t2 = _xor_block(self.mac, t1)
        self.mac = t2

    def get(self):
        return self.mac[: defines.YSM_AEAD_MAC_SIZE]


def _split_data(data, pos):
    a = data[:pos]
    b = data[pos:]
    return (a, b,)


def aesCCM(key, key_handle, nonce, data, decrypt=False):
    """
    Function implementing YubiHSM AEAD encrypt/decrypt in software.
    """

    if decrypt:
        (data, saved_mac) = _split_data(data, len(data) - defines.YSM_AEAD_MAC_SIZE)

    nonce = util.input_validate_nonce(nonce, pad = True)
    mac = _cbc_mac(key, key_handle, nonce, len(data))

    counter = _ctr_counter(key_handle, nonce, value = 0)
    ctr_aes = AES.new(key, AES.MODE_CTR, counter = counter.__next__)
    out = []
    while data:
        (thisblock, data) = _split_data(data, defines.YSM_BLOCK_SIZE)

        # encrypt/decrypt and CBC MAC
        if decrypt:
            aes_out = ctr_aes.decrypt(thisblock)
            mac.update(aes_out)
        else:
            mac.update(thisblock)
            aes_out = ctr_aes.encrypt(thisblock)

        out.append(aes_out)

    # Finalize MAC
    counter.value = 0
    mac.finalize(counter.pack())
    if decrypt:
        if mac.get() != saved_mac:
            raise ksmexception.YHSM_Error('AEAD integrity check failed')
    else:
        out.append(mac.get())
    return b''.join(out)


def crc16(data):
    """
    Calculate an ISO13239 CRC checksum of the input buffer.
    """
    m_crc = 0xffff
    for this in data:
        m_crc ^= this
        for _ in range(8):
            j = m_crc & 1
            m_crc >>= 1
            if j:
                m_crc ^= 0x8408
    return m_crc


class SoftYHSM(object):
    def __init__(self, keys, debug=False):
        self._buffer = ''
        self.debug = debug
        if not keys:
            raise ValueError('Data contains no key handles!')
        for k, v in list(keys.items()):
            if len(v) not in AES.key_size:
                raise ValueError('Keyhandle of unsupported length: %d (was %d bytes)' % (k, len(v)))
        self.keys = keys

    @classmethod
    def from_file(cls, filename, debug=False):
        with open(filename, 'r') as f:
            return cls.from_json(f.read(), debug)

    @classmethod
    def from_json(cls, data, debug=False):
        data = json.loads(data)
        if not isinstance(data, dict):
            raise ValueError('Data does not contain object as root element.')
        keys = {}
        for kh, aes_key_hex in list(data.items()):
            #Benjamin
            #keys[int(kh)] = aes_key_hex.decode('hex')
            keys[int(kh)] = binascii.unhexlify(aes_key_hex)
        return cls(keys, debug)

    def _get_key(self, kh, cmd):
        try:
            return self.keys[kh]
        except KeyError:
            raise ksmexception.YHSM_CommandFailed(
                defines.cmd2str(cmd),
                defines.YSM_KEY_HANDLE_INVALID)

    def validate_aead_otp(self, public_id, otp, key_handle, aead):
        aes_key = self._get_key(key_handle, defines.YSM_AEAD_YUBIKEY_OTP_DECODE)
        cmd = validate_cmd.YHSM_Cmd_AEAD_Validate_OTP(None, public_id, otp, key_handle, aead)

        aead_pt = aesCCM(aes_key, cmd.key_handle, cmd.public_id, aead, True)
        yk_key, yk_uid = aead_pt[:16], aead_pt[16:]
    
        ecb_aes = AES.new(yk_key, AES.MODE_ECB)
        
        otp_plain = ecb_aes.decrypt(otp)
        
        uid = otp_plain[:6]
        use_ctr, ts_low, ts_high, session_ctr, rnd, crc = struct.unpack(
            '<HHBBHH', otp_plain[6:])

        if uid == yk_uid and crc16(otp_plain) == 0xf0b8:
            return validate_cmd.YHSM_ValidationResult(
                cmd.public_id, use_ctr, session_ctr, ts_high, ts_low
            )

        raise ksmexception.YHSM_CommandFailed(
            defines.cmd2str(cmd.command), defines.YSM_OTP_INVALID)

    def load_secret(self, secret):
        self._buffer = secret.pack()

    def load_random(self, num_bytes, offset = 0):
        self._buffer = self._buffer[:offset] + os.urandom(num_bytes)

    def generate_aead(self, nonce, key_handle):
        if nonce == "":
            # no hardware to generate it for us, so do it here.
            nonce = os.urandom(6)
        aes_key = self._get_key(key_handle, defines.YSM_BUFFER_AEAD_GENERATE)
        ct = soft_hsm.aesCCM(aes_key, key_handle, nonce, self._buffer,False)
        return aead_cmd.YHSM_GeneratedAEAD(nonce, key_handle, ct)
