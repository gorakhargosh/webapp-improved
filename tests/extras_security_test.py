# -*- coding: utf-8 -*-
import re

from webapp2_extras import security

import test_base


class TestSecurity(test_base.BaseTestCase):
    def test_create_token(self):
        self.assertRaises(TypeError, security.create_token, None)
        self.assertRaises(ValueError, security.create_token, 9)
        self.assertRaises(ValueError, security.create_token, 0)
        self.assertRaises(ValueError, security.create_token, -1)

        token = security.create_token(16, 16)
        self.assertTrue(re.match(r'^[a-f0-9]{4}$', token) is not None)

        token = security.create_token(16, 10)
        self.assertTrue(int(token, 10) >= 0)

        token = security.create_token(32, 16)
        self.assertTrue(re.match(r'^[a-f0-9]{8}$', token) is not None)

        token = security.create_token(64, 16)
        self.assertTrue(re.match(r'^[a-f0-9]{16}$', token) is not None)

        token = security.create_token(128, 16)
        self.assertTrue(re.match(r'^[a-f0-9]{32}$', token) is not None)


    def test_create_check_password_hash(self):
        self.assertRaises(TypeError, security.create_password_hash, 'foo',
                          'bar')

        password = 'foo'
        hashval = security.create_password_hash(password, 'sha1')
        self.assertTrue(security.check_password_hash(password, hashval))

        hashval = security.create_password_hash(password, 'sha1', pepper='bar')
        self.assertTrue(security.check_password_hash(password, hashval,
                                                     pepper='bar'))

        hashval = security.create_password_hash(password, 'md5')
        self.assertTrue(security.check_password_hash(password, hashval))

        hashval = security.create_password_hash(password, 'plain')
        self.assertTrue(security.check_password_hash(password, hashval))

        hashval = security.create_password_hash(password, 'plain')
        self.assertFalse(security.check_password_hash(password, ''))

        hashval1 = security.hash_password(unicode(password), 'sha1', u'bar')
        hashval2 = security.hash_password(unicode(password), 'sha1', u'bar')
        self.assertTrue(hashval1 is not None)
        self.assertEqual(hashval1, hashval2)

        hashval1 = security.hash_password(unicode(password), 'md5', None)
        hashval2 = security.hash_password(unicode(password), 'md5', None)
        self.assertTrue(hashval1 is not None)
        self.assertEqual(hashval1, hashval2)


if __name__ == '__main__':
    test_base.main()
