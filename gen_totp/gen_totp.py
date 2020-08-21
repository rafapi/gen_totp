#!/usr/bin/env python


import base64
import hashlib
import hmac
import datetime
import time

from hmac import compare_digest
import unicodedata


secret = '<secret>'


class OTP:
    """
    Base class for OTP handlers.
    """
    def __init__(self, s, digits=6, digest=hashlib.sha1):
        """
        :param s: secret in base32 format
        :param digits: number of integers in the OTP - default: len 6
        :param digest: digest function to use in the HMAC - default: sha1
        """
        self.digits = digits
        self.digest = digest
        self.secret = s

    def generate_otp(self, input):
        """
        :param input: the HMAC counter value to use as the OTP input.
        """
        if input < 0:
            raise ValueError('input must be positive integer')
        hasher = hmac.new(self.byte_secret(),
                          self.int_to_bytestring(input), self.digest)
        hmac_hash = bytearray(hasher.digest())
        offset = hmac_hash[-1] & 0xf
        code = ((hmac_hash[offset] & 0x7f) << 24 |
                (hmac_hash[offset + 1] & 0xff) << 16 |
                (hmac_hash[offset + 2] & 0xff) << 8 |
                (hmac_hash[offset + 3] & 0xff))
        str_code = str(code % 10 ** self.digits)
        while len(str_code) < self.digits:
            str_code = '0' + str_code

        return str_code

    def byte_secret(self):
        missing_padding = len(self.secret) % 8
        if missing_padding != 0:
            self.secret += '=' * (8 - missing_padding)
        return base64.b32decode(self.secret, casefold=True)

    @staticmethod
    def int_to_bytestring(i, padding=8):
        """
        Turns an integer to the OATH specified bytestring
        """
        result = bytearray()
        while i != 0:
            result.append(i & 0xFF)
            i >>= 8

        return bytearray(reversed(result)).rjust(padding, b'\0')


class TempOTP(OTP):
    """
    time-based OTP counters.
    """
    def __init__(self, *args, **kwargs):
        self.interval = kwargs.pop('interval', 30)
        super(TempOTP, self).__init__(*args, **kwargs)

    def now(self):
        return self.generate_otp(self.timecode(datetime.datetime.now()))

    def timecode(self, for_time):
        i = time.mktime(for_time.timetuple())
        return int(i / self.interval)


def strings_equal(s1, s2):
    """
    Timing-attack resistant string comparison.

    Normal comparison using == will short-circuit on the first mismatching
    character. This avoids that by scanning the whole string, though we
    still reveal to a timing attack whether the strings are the same
    length.
    """
    s1 = unicodedata.normalize('NFKC', s1)
    s2 = unicodedata.normalize('NFKC', s2)
    return compare_digest(s1, s2)


def main():
    totp = TempOTP(secret)
    print(totp.now())


if __name__ == '__main__':
    main()
