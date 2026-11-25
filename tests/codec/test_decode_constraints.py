#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.cer import decoder as cer_decoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import univ


class RangedInteger(univ.Integer):
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(1, 3)


class LimitedOctetString(univ.OctetString):
    subtypeSpec = univ.OctetString.subtypeSpec + constraint.ValueSizeConstraint(1, 2)


class RequiredRangeRecord(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('number', RangedInteger())
    )


class OptionalRangeRecord(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('number', RangedInteger())
    )


class OneComponentSequenceOf(univ.SequenceOf):
    componentType = univ.Integer()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, 1)


class DecodeConstraintsTestCase(BaseTestCase):
    decoders = (ber_decoder, cer_decoder, der_decoder)

    def _assertRejected(self, substrate, asn1Spec, description):
        for codec in self.decoders:
            with self.subTest(codec=codec.__name__, description=description):
                try:
                    codec.decode(substrate, asn1Spec=asn1Spec)

                except PyAsn1Error:
                    pass

                else:
                    assert False, '%s tolerated' % description

    def testTopLevelRangeConstraint(self):
        valid_substrates = (
            b'\x02\x01\x01',
            b'\x02\x01\x03',
        )

        for decoder in self.decoders:
            for substrate in valid_substrates:
                value, _ = decoder.decode(substrate, asn1Spec=RangedInteger())
                assert value in (1, 3)

        self._assertRejected(
            b'\x02\x01\x09', RangedInteger(),
            'out-of-range top-level INTEGER'
        )
        self._assertRejected(
            b'\x02\x01\x09', RangedInteger,
            'out-of-range class-specified INTEGER'
        )

    def testTopLevelSizeConstraint(self):
        value, _ = ber_decoder.decode(
            b'\x04\x02ab', asn1Spec=LimitedOctetString())
        assert value == b'ab'

        self._assertRejected(
            b'\x04\x03abc', LimitedOctetString(),
            'over-sized top-level OCTET STRING'
        )

    def testRequiredSequenceComponentConstraint(self):
        value, _ = ber_decoder.decode(
            b'0\x03\x02\x01\x01',
            asn1Spec=RequiredRangeRecord()
        )
        assert value['number'] == 1

        self._assertRejected(
            b'0\x03\x02\x01\x09', RequiredRangeRecord(),
            'out-of-range required SEQUENCE component'
        )

    def testOptionalSequenceComponentConstraint(self):
        value, _ = ber_decoder.decode(
            b'0\x03\x02\x01\x02', asn1Spec=OptionalRangeRecord())
        assert value['number'] == 2

        self._assertRejected(
            b'0\x03\x02\x01\x09', OptionalRangeRecord(),
            'out-of-range optional SEQUENCE component'
        )

    def testContainerConstraintCheckedAtCommonExit(self):
        substrate = b'0\x06\x02\x01\x01\x02\x01\x02'

        value, _ = ber_decoder.decode(
            b'0\x03\x02\x01\x01', asn1Spec=OneComponentSequenceOf())
        assert len(value) == 1

        self._assertRejected(
            substrate, OneComponentSequenceOf(),
            'SequenceOf violating its size constraint'
        )

        indefinite_substrate = (
            b'\x30\x80\x02\x01\x01\x02\x01\x02\x00\x00'
        )
        try:
            ber_decoder.decode(
                indefinite_substrate, asn1Spec=OneComponentSequenceOf())

        except PyAsn1Error:
            pass

        else:
            assert False, 'indefinite-length SequenceOf size violation tolerated'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
