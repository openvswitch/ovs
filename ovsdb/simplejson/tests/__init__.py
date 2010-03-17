import unittest
import doctest

def additional_tests():
    import simplejson
    import simplejson.encoder
    import simplejson.decoder
    suite = unittest.TestSuite()
    for mod in (simplejson, simplejson.encoder, simplejson.decoder):
        suite.addTest(doctest.DocTestSuite(mod))
    suite.addTest(doctest.DocFileSuite('../../index.rst'))
    return suite

def main():
    suite = additional_tests()
    runner = unittest.TextTestRunner()
    runner.run(suite)

if __name__ == '__main__':
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    main()
