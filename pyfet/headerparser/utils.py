import time
from dkim import CV_Fail, CV_None, CV_Pass, ValidationError
from dkim.crypto import *
import re

def my_validate_signature_fields(sig, mandatory_fields=[b'v', b'a', b'b', b'bh', b'd', b'h', b's'], arc=False, now=int(time.time())):
    """Validate DKIM or ARC Signature fields.
    Basic checks for presence and correct formatting of mandatory fields.
    Raises a ValidationError if checks fail, otherwise returns None.
    @param sig: A dict mapping field keys to values.
    @param mandatory_fields: A list of non-optional fields
    @param arc: flag to differentiate between dkim & arc
    """
    if arc:
        hashes = ARC_HASH_ALGORITHMS
    else:
        hashes = HASH_ALGORITHMS
    for field in mandatory_fields:
        if field not in sig:
            raise ValidationError("missing %s=" % field)

    if b'a' in sig and not sig[b'a'] in hashes:
        raise ValidationError("unknown signature algorithm: %s" % sig[b'a'])

    if b'b' in sig:
        if re.match(br"[\s0-9A-Za-z+/]+[\s=]*$", sig[b'b']) is None:
            raise ValidationError("b= value is not valid base64 (%s)" % sig[b'b'])
        if len(re.sub(br"\s+", b"", sig[b'b'])) % 4 != 0:
            raise ValidationError("b= value is not valid base64 (%s)" % sig[b'b'])

    if b'bh' in sig:
        if re.match(br"[\s0-9A-Za-z+/]+[\s=]*$", sig[b'b']) is None:
            raise ValidationError("bh= value is not valid base64 (%s)" % sig[b'bh'])
        if len(re.sub(br"\s+", b"", sig[b'bh'])) % 4 != 0:
            raise ValidationError("bh= value is not valid base64 (%s)" % sig[b'bh'])

    if b'cv' in sig and sig[b'cv'] not in (CV_Pass, CV_Fail, CV_None):
        raise ValidationError("cv= value is not valid (%s)" % sig[b'cv'])

    # Limit domain validation to ASCII domains because too hard
    try:
        str(sig[b'd'], 'ascii')
        # No specials, which is close enough
        if re.findall(rb"[\(\)<>\[\]:;@\\,]", sig[b'd']):
            raise ValidationError("d= value is not valid (%s)" % sig[b'd'])
    except UnicodeDecodeError as e:
        # Not an ASCII domain
        pass

    # Nasty hack to support both str and bytes... check for both the
    # character and integer values.
    if not arc and b'i' in sig and (
        not sig[b'i'].lower().endswith(sig[b'd'].lower()) or
        sig[b'i'][-len(sig[b'd'])-1] not in ('@', '.', 64, 46)):
        raise ValidationError(
            "i= domain is not a subdomain of d= (i=%s d=%s)" %
            (sig[b'i'], sig[b'd']))
    if b'l' in sig and re.match(br"\d{,76}$", sig[b'l']) is None:
        raise ValidationError(
            "l= value is not a decimal integer (%s)" % sig[b'l'])
    if b'q' in sig and sig[b'q'] != b"dns/txt":
        raise ValidationError("q= value is not dns/txt (%s)" % sig[b'q'])

    if b't' in sig:
        if re.match(br"\d+$", sig[b't']) is None:
            raise ValidationError(
                "t= value is not a decimal integer (%s)" % sig[b't'])
        slop = 36000 # 10H leeway for mailers with inaccurate clocks
        t_sign = int(sig[b't'])
        if t_sign > now + slop:
            raise ValidationError("t= value is in the future (%s)" % sig[b't'])
    else:
        t_sign = None

    if b'v' in sig and sig[b'v'] != b"1":
        raise ValidationError("v= value is not 1 (%s)" % sig[b'v'])

    if b'x' in sig:
        if re.match(br"\d+$", sig[b'x']) is None:
            raise ValidationError(
              "x= value is not a decimal integer (%s)" % sig[b'x'])
        x_sign = int(sig[b'x'])
        slop = 36000 # 10H leeway for mailers with inaccurate clocks
        if x_sign < now - slop:
            raise ValidationError(
                "x= value is past (%s)" % sig[b'x'])
        if t_sign and x_sign < t_sign:
            raise ValidationError(
                "x= value is less than t= value (x=%s t=%s)" %
                (sig[b'x'], sig[b't']))
