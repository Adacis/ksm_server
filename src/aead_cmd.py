"""
implementations of AEAD commands for the YubiHSM
"""

# Copyright (c) 2011 Yubico AB
# See the file COPYING for licence statement.

import binascii
import codecs
import struct

__all__ = [
    # constants
    'YHSM_AEAD_File_Marker',
    # functions
    # classes
    'YHSM_AEAD_Cmd',
    'YHSM_Cmd_AEAD_Generate',
    'YHSM_Cmd_AEAD_Random_Generate',
    'YHSM_Cmd_AEAD_Buffer_Generate',
    'YHSM_Cmd_AEAD_Decrypt_Cmp',
    'YHSM_GeneratedAEAD',
    'YHSM_YubiKeySecret',
]

import defines
import ksmexception
import util
from cmd import YHSM_Cmd

YHSM_AEAD_File_Marker = 'YubiHSM AEAD\n'
# AEADs generated on Windows using pyhsm <= 1.1.1 will have CRLF instead of LF.
YHSM_AEAD_CRLF_File_Marker = YHSM_AEAD_File_Marker[:-1] + '\r\n'

class YHSM_AEAD_Cmd(YHSM_Cmd):
    """
    Class for common non-trivial parse_result for commands returning a
    YSM_AEAD_GENERATE_RESP.
    """

    nonce = ''
    key_handle = 0
    status = 0
    response = None

    def __repr__(self):
        if self.executed:
            return '<%s instance at %s: nonce=%s, key_handle=0x%x, status=%s>' % (
                self.__class__.__name__,
                hex(id(self)),
                self.nonce.encode('hex'),
                self.key_handle,
                defines.status2str(self.status)
                )
        else:
            return '<%s instance at %s (not executed)>' % (
                self.__class__.__name__,
                hex(id(self))
                )

    def parse_result(self, data):
        """
        Returns a YHSM_GeneratedAEAD instance, or throws pyhsm.exception.YHSM_CommandFailed.
        """
        # typedef struct {
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
        #   uint32_t keyHandle;                 // Key handle
        #   YSM_STATUS status;                  // Status
        #   uint8_t numBytes;                   // Number of bytes in AEAD block
        #   uint8_t aead[YSM_AEAD_MAX_SIZE];    // AEAD block
        # } YSM_AEAD_GENERATE_RESP;

        nonce, \
            key_handle, \
            self.status, \
            num_bytes = struct.unpack_from("< %is I B B" % (defines.YSM_AEAD_NONCE_SIZE), data, 0)

        util.validate_cmd_response_hex('key_handle', key_handle, self.key_handle)

        if self.status == defines.YSM_STATUS_OK:
            util.validate_cmd_response_nonce(nonce, self.nonce)
            offset = defines.YSM_AEAD_NONCE_SIZE + 6
            aead = data[offset:offset + num_bytes]
            self.response = YHSM_GeneratedAEAD(nonce, key_handle, aead)
            return self.response
        else:
            raise ksmexception.YHSM_CommandFailed(defines.cmd2str(self.command), self.status)

class YHSM_Cmd_AEAD_Generate(YHSM_AEAD_Cmd):
    """
    Generate AEAD block from data for a specific key.

    `data' is either a string, or a YHSM_YubiKeySecret.
    """
    def __init__(self, stick, nonce, key_handle, data):
        self.nonce = util.input_validate_nonce(nonce, pad = True)
        self.key_handle = util.input_validate_key_handle(key_handle)
        self.data = util.input_validate_yubikey_secret(data)
        # typedef struct {
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
        #   uint32_t keyHandle;                 // Key handle
        #   uint8_t numBytes;                   // Number of data bytes
        #   uint8_t data[YSM_DATA_BUF_SIZE];    // Data
        # } YSM_AEAD_GENERATE_REQ;
        fmt = "< %is I B %is" % (defines.YSM_AEAD_NONCE_SIZE, len(self.data))
        packed = struct.pack(fmt, nonce, key_handle, len(self.data), self.data)
        YHSM_AEAD_Cmd.__init__(self, stick, defines.YSM_AEAD_GENERATE, packed)

class YHSM_Cmd_AEAD_Random_Generate(YHSM_AEAD_Cmd):
    """
    Generate a random AEAD block using the YubiHSM internal TRNG.

    To generate a secret for a YubiKey, use public_id as nonce.
    """
    def __init__(self, stick, nonce, key_handle, num_bytes):
        self.nonce = util.input_validate_nonce(nonce, pad = True)
        self.key_handle = util.input_validate_key_handle(key_handle)
        self.num_bytes = util.input_validate_int(num_bytes, 'num_bytes')
        # typedef struct {
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
        #   uint32_t keyHandle;                 // Key handle
        #   uint8_t numBytes;                   // Number of bytes to randomize
        # } YSM_RANDOM_AEAD_GENERATE_REQ;
        fmt = "< %is I B" % (defines.YSM_AEAD_NONCE_SIZE)
        packed = struct.pack(fmt, nonce, key_handle, num_bytes)
        YHSM_AEAD_Cmd.__init__(self, stick, defines.YSM_RANDOM_AEAD_GENERATE, packed)

class YHSM_Cmd_AEAD_Buffer_Generate(YHSM_AEAD_Cmd):
    """
    Generate AEAD block of data buffer for a specific key.

    After a key has been loaded into the internal data buffer, this command can be
    used a number of times to get AEADs of the data buffer for different key handles.

    For example, to encrypt a YubiKey secrets to one or more Yubico KSM's that
    all have a YubiHSM attached to them.

    Key handle (and system flags) permission flags required for this operation :
    YSM_BUFFER_AEAD_GENERATE
    YSM_BUFFER_LOAD if non-random data has been loaded into the internal buffer
    """
    def __init__(self, stick, nonce, key_handle):
        self.nonce = util.input_validate_nonce(nonce, pad = True)
        self.key_handle = util.input_validate_key_handle(key_handle)
        # typedef struct {
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
        #   uint32_t keyHandle;                 // Key handle
        # } YSM_BUFFER_AEAD_GENERATE_REQ;
        packed = struct.pack("< %is I" % (defines.YSM_AEAD_NONCE_SIZE), \
                                 self.nonce, self.key_handle)
        YHSM_AEAD_Cmd.__init__(self, stick, defines.YSM_BUFFER_AEAD_GENERATE, packed)

class YHSM_Cmd_AEAD_Decrypt_Cmp(YHSM_Cmd):
    """
    Validate an AEAD using the YubiHSM, matching it against some known plain text.
    Matching is done inside the YubiHSM so the decrypted AEAD is never exposed.
    """

    status = None

    def __init__(self, stick, nonce, key_handle, aead, cleartext):
        aead = util.input_validate_aead(aead)
        expected_ct_len = len(aead) - defines.YSM_AEAD_MAC_SIZE
        cleartext = util.input_validate_str(cleartext, 'cleartext', exact_len = expected_ct_len)
        self.nonce = util.input_validate_nonce(nonce, pad = True)
        self.key_handle = util.input_validate_key_handle(key_handle)
        data = cleartext + aead
        if len(data) > defines.YSM_MAX_PKT_SIZE - 10:
            raise ksmexception.YHSM_InputTooLong(
                'cleartext+aead', defines.YSM_MAX_PKT_SIZE - 10, len(data))
        # typedef struct {
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
        #   uint32_t keyHandle;                 // Key handle
        #   uint8_t numBytes;                   // Number of data bytes (cleartext + aead)
        #   uint8_t data[YSM_MAX_PKT_SIZE - 0x10]; // Data (cleartext + aead). Empty cleartext validates aead only
        # } YSM_AEAD_DECRYPT_CMP_REQ;
        fmt = "< %is I B %is" % (defines.YSM_AEAD_NONCE_SIZE, len(data))
        packed = struct.pack(fmt, self.nonce, key_handle, len(data), data)
        YHSM_Cmd.__init__(self, stick, defines.YSM_AEAD_DECRYPT_CMP, packed)

    def parse_result(self, data):
        # typedef struct {
        #   uint8_t nonce[YSM_AEAD_NONCE_SIZE]; // Nonce (publicId for Yubikey AEADs)
        #   uint32_t keyHandle;                 // Key handle
        #   YSM_STATUS status;                  // Status
        # } YSM_AEAD_DECRYPT_CMP_RESP;
        fmt = "< %is I B" % (defines.YSM_AEAD_NONCE_SIZE)
        nonce, key_handle, self.status = struct.unpack(fmt, data)
        util.validate_cmd_response_str('nonce', nonce, self.nonce)
        util.validate_cmd_response_hex('key_handle', key_handle, self.key_handle)
        if self.status == defines.YSM_STATUS_OK:
            return True
        if self.status == defines.YSM_MISMATCH:
            return False
        else:
            raise ksmexception.YHSM_CommandFailed(defines.cmd2str(self.command), self.status)

class YHSM_GeneratedAEAD():
    """ Small class to represent a YHSM_AEAD_GENERATE_RESP. """
    def __init__(self, nonce, key_handle, aead):
        self.nonce = nonce
        self.key_handle = key_handle
        self.data = aead

    def __repr__(self):
        nonce_str = "None"
        if self.nonce is not None:
            #Python3
            nonce_str = ''.join(['{:02x}'.format(ord(c)) for c in self.nonce])
        return '<%s instance at %s: nonce=%s, key_handle=0x%x, data=%i bytes>' % (
            self.__class__.__name__,
            hex(id(self)),
            nonce_str,
            self.key_handle,
            len(self.data)
            )

    def save(self, filename):
        """
        Store AEAD in a file.

        @param filename: File to create/overwrite
        @type filename: string
        """
        aead_f = open(filename, "wb")
        fmt = "< B I %is %is" % (defines.YSM_AEAD_NONCE_SIZE, len(self.data))
        version = 1
        packed = struct.pack(fmt, version, self.key_handle, self.nonce, self.data)
        aead_f.write(YHSM_AEAD_File_Marker + packed)
        aead_f.close()

    def load(self, filename):
        """
        Load AEAD from a file.

        @param filename: File to read AEAD from
        @type filename: string
        """
        aead_f = open(filename, "rb")
        buf = aead_f.read(1024)
        if buf.startswith(YHSM_AEAD_CRLF_File_Marker):
            buf = YHSM_AEAD_File_Marker + buf[len(YHSM_AEAD_CRLF_File_Marker):]
        if buf.startswith(YHSM_AEAD_File_Marker):
            if buf[len(YHSM_AEAD_File_Marker)] == chr(1):
                # version 1 format
                fmt = "< I %is" % (defines.YSM_AEAD_NONCE_SIZE)
                self.key_handle, self.nonce = struct.unpack_from(fmt, buf, len(YHSM_AEAD_File_Marker) + 1)
                self.data = buf[len(YHSM_AEAD_File_Marker) + 1 + struct.calcsize(fmt):]
            else:
                raise ksmexception.YHSM_Error('Unknown AEAD file format')
        else:
            # version 0 format, just AEAD data
            self.data = buf[:defines.YSM_MAX_KEY_SIZE + defines.YSM_BLOCK_SIZE]
        aead_f.close()

class YHSM_YubiKeySecret():
    """ Small class to represent a YUBIKEY_SECRETS struct. """
    def __init__(self, key, uid):
        self.key = util.input_validate_str(key, 'key', exact_len = defines.KEY_SIZE)
        self.uid = util.input_validate_str(uid, 'uid', max_len = defines.UID_SIZE)

    def pack(self):
        """ Return key and uid packed for sending in a command to the YubiHSM. """
        # # 22-bytes Yubikey secrets block
        # typedef struct {
        #   uint8_t key[KEY_SIZE];              // AES key
        #   uint8_t uid[UID_SIZE];              // Unique (secret) ID
        # } YUBIKEY_SECRETS;
        return self.key + self.uid.ljust(defines.UID_SIZE, chr(0))
