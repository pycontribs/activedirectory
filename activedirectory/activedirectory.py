#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from __future__ import print_function
import logging
import os
import traceback
import types
import unittest
import socket
import sys
from collections import defaultdict
from collections import OrderedDict
import ldap3
from ldap3.utils.conv import escape_bytes
from ldap3.protocol.rfc4511 import SearchRequest, ValsAtLeast1, Scope, Integer0ToMax, TypesOnly, Filter, AttributeSelection, Selector, EqualityMatch
try:
    import configparser
except:
    from six.moves import configparser
try:
    from urlparse import urlparse
except:
    from urllib.parse import urlparse


class ActiveDirectory(object):

    def reconnect(self):
        self.__init__(self.url, self.dn, self.secret, base=self.base)

    def __init__(self, url, dn=None, secret=None, base="", debug=False, paged_size=1000, size_limit=None, time_limit=None):
        """If you do not specify credentials (dn and secret) it will try to load them from ~/.netrc file.

        @param server: url of LDAP Server
        @param dn: username of the service account
        @param secret: password of the servce account
        """
        self.filter = ''
        self.scope = ldap3.SEARCH_SCOPE_WHOLE_SUBTREE
        self.paged_size = paged_size
        if not size_limit:
            self.size_limit = Integer0ToMax(0)
        else:
            self.size_limit = size_limit

        if not time_limit:
            self.time_limit = Integer0ToMax(0)
        else:
            self.time_limit = time_limit

        self.attrs = '*'

        self.logger = logging.getLogger('ldap')
        if debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
        self.url = url

        self.dn = dn
        self.secret = secret

        u = urlparse(url)

        if base:
            self.base = base
        else:
            self.base = u.path[1:]

        if u.scheme == 'ldaps':
            use_ssl = True
        else:
            use_ssl = False

        if ":" in u.hostname:
            u.hostname = u.hostname.split(":")[0]
        if dn is None:
            import netrc
            try:
                netrc_config = netrc.netrc()
                for h in netrc_config.hosts:
                    if h.lower() == u.hostname.lower():
                        dn, account, secret = netrc_config.authenticators(h)
                        break
            except Exception as e:
                logging.warning("~/.netrc ignored due to: %s" % e)

        self.server = ldap3.Server(host=u.hostname, port=u.port, use_ssl=use_ssl)
        self.conn = ldap3.Connection(self.server,
                                     auto_bind=True,
                                     # client_strategy=ldap3.STRATEGY_REUSABLE_THREADED, # .STRATEGY_SYNC,
                                     client_strategy=ldap3.STRATEGY_SYNC,
                                     user=dn,
                                     password=secret,
                                     authentication=ldap3.AUTH_SIMPLE)
        try:
            ret = self.conn.bind()
        except Exception as e:
            self.logger.error(e)
        else:
            self._connected = True

    def __bool__(self):
        return self._connected

    def __nonzero__(self):
        return self._connected

    @staticmethod
    def check_credentials(url, dn, secret, base=""):
        raise NotImplementedError()

    # def __del__(self):
    #    if self.conn:
    #        self.conn.unbind()

    def search_ext_s(self, filterstr=None, attrlist=ldap3.ALL_ATTRIBUTES, base=None, scope=None):
        """

        :rtype : object
        """
        ret = []
        total_entries = 0
        if base is None:
            base = self.base
        if scope is None:
            scope = self.scope

        self.conn.search(
            search_base=base,
            search_filter=filterstr,
            search_scope=scope,
            attributes=attrlist,
            paged_size=self.paged_size,
            size_limit=self.size_limit,
            time_limit=self.time_limit
        )
        if self.conn.result['description'] == 'sizeLimitExceeded' or 'controls' not in self.conn.result:
            logging.error("sizeLimitExceeded")
            cookie = None
        else:
            cookie = self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        ret.extend(self.conn.response)

        total_entries += len(self.conn.response)
        while cookie:
            self.conn.search(
                search_base=base,
                search_filter=filterstr,
                search_scope=scope,
                attributes=attrlist,
                paged_size=self.paged_size,
                size_limit=self.size_limit,
                time_limit=self.time_limit,
                paged_cookie=cookie
            )
            if self.conn.result['description'] == 'sizeLimitExceeded' or 'controls' not in self.conn.result:
                logging.error("sizeLimitExceeded")
                cookie = None
            else:
                cookie = self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
            total_entries += len(self.conn.response)
            ret.extend(self.conn.response)
            if self.size_limit and len(ret) >= self.size_limit:
                return ret[:self.size_limit]

        # FIX for Microsoft bug: ldap.UNAVAILABLE_CRITICAL_EXTENSION: {'info': '00002040: SvcErr: DSID-031401E7, problem 5010 (UNAVAIL_EXTENSION), data 0\n', 'desc': 'Critical extension is unavailable'}
        # explain: second pagination query fails, so after a query we will establish a new connection to the server.
        # if pages > 1:
        #    self.reconnect()
        # ret = self.conn.search_ext_s(*args)
        return ret

    @staticmethod
    def decode_cn(s):
        d = defaultdict(list)
        for nv in s.split(","):
            n, v = nv.split("=")
            d[n].append(v)
        return d

    def get_manager(self, user):
        """

        :param user: sAMAccountName of the user
        :return: sAMAccountName of the manager or None
        """
        filter = "(&%s(sAMAccountName=%s))" % (self.filter, user)
        ret = self.search_ext_s(filter, ["manager"])
        if ret and ret[0] and 'manager' in ret[0]['attributes'] and ret[0]['attributes']['manager']:
            ret = ret[0]['attributes']['manager'][0]
            if ret:
                return self.get_username(dn=ret)

    def get_managers(self):
        filter = "(&%s(sAMAccountName=*)(manager=*))" % self.filter
        result = {}
        for r in self.search_ext_s(filterstr=filter, attrlist=['sAMAccountName', "manager"]):
            user = self.get_username(dn=r['dn'])
            manager = self.get_username(dn=r['attributes']['manager'][0])
            if user is None or manager is None:
                raise Exception("Unable to map DN to usernames.")
            result[user] = manager
        return result

    def get_users(self, new_filter=None, attrlist=ldap3.ALL_ATTRIBUTES):
        # removed (mail=*) filter form default set
        # attrlist default used to be ["sAMAccountName"] instead of all.
        if not new_filter:
            new_filter = ""
        filter = "(&%s(sAMAccountName=*)(samAccountType=805306368)%s)" % (self.filter, new_filter)
        rets = OrderedDict()
        for x in self.search_ext_s(filterstr=filter, attrlist=attrlist):
            # if ret and ret[0] and isinstance(ret[0][1], dict):
            username = x['attributes']["sAMAccountName"][0]
            rets[username] = self.__compress_attributes(x['attributes'])
        return rets

    def get_groups(self):
        """

        :type self: object
        """
        filter = "(&(objectCategory=group)(mail=*))"
        rets = []
        for x in self.search_ext_s(filterstr=filter, attrlist=["sAMAccountName"]):
            # if ret and ret[0] and isinstance(ret[0][1], dict):
            # print(x)
            try:
                rets.append(x['attributes']["sAMAccountName"][0])
            except Exception as e:
                logging.error("%s: %s" % (e, x))
        return sorted(rets)

    def get_manager_attributes(self, user):
        manager = self.get_manager(user)
        if manager and "CN" in manager:
            name = manager["CN"][0]
            ret = self.get_attributes(name=name)
            return ret

    @staticmethod
    def escaped(query):
        return escape_bytes(query)

    def __as_unicode(self, s):
        if s:
            return s.decode('utf-8')
        else:
            return s

    def __compress_attributes(self, dic):
        """
        This will convert all attributes that are list with only one item string into simple string. It seems that LDAP always return lists, even when it doesn
        t make sense.

        :param dic:
        :return:
        """
        result = {}
        for k, v in dic.iteritems():
            if isinstance(v, types.ListType) and len(v) == 1:
                if k not in ('msExchMailboxSecurityDescriptor', 'msExchSafeSendersHash', 'msExchBlockedSendersHash',
                             'replicationSignature', 'msExchSafeRecipientsHash', 'sIDHistory',
                             'msRTCSIP-UserRoutingGroupId', 'mSMQDigests', 'mSMQSignCertificates',
                             'msExchMasterAccountSid', 'msExchPreviousAccountSid', 'msExchUMPinChecksum',
                             'userSMIMECertificate', 'userCertificate', 'userCert',
                             'msExchDisabledArchiveGUID', 'msExchUMPinChecksum', 'msExchUMSpokenName',
                             'objectSid', 'objectGUID', 'msExchArchiveGUID', 'thumbnailPhoto', 'msExchMailboxGuid'):
                    try:
                        result[k] = v[0].decode('utf-8')
                    except Exception as e:
                        logging. error("Failed to decode attibuteAILED: %s -- %s" % (k, e))
                        result[k] = v[0]
        return result

    def get_attributes(self, attributes=None, user=None, email=None, name=None):
        if user is None and email is None and name is None:
            raise Exception("How do you expect to get an attribute when you specify no even one of user/email/name?")
        if attributes is None:
            attributes = self.attrs
        if user:
            filter = "(&%s(sAMAccountName=%s))" % (
                self.filter, self.escaped(user))
        elif name:
            filter = "(&%s(displayName=%s))" % (
                self.filter, self.escaped(name))
        elif email:
            filter = "(&%s(|(mail=%s)(proxyAddresses=smtp:%s)))" % (self.filter, self.escaped(email), self.escaped(email))
        else:
            filter = None

        res = {}
        self.logger.debug("%s : %s" % (filter, attributes))
        r = self.search_ext_s(filterstr=filter, attrlist=attributes)
        if not r:
            return {}

        if len(r) != 1:
            raise NotImplementedError("getAttributes does not support returning values for multiple ldap objects")

        # print(r[0])
        return self.__compress_attributes(r[0]['attributes'])

    def get_attribute(self, attribute='sAMAccountName', user=None, email=None, name=None, dn=None):
        """

        :param attribute:
        :param user:
        :param email:
        :param name:
        :param dn:
        :return: str
        """
        filter = "(objectclass=*)"
        if user is None and email is None and name is None and dn is None:
            raise Exception("How do you expect to get an attribute when you specify no even one of user/email/name?")
        if user:
            filter = "(&%s(sAMAccountName=%s))" % (
                self.filter, self.escaped(user))
        elif name:
            filter = "(&%s(displayName=*%s*))" % (
                self.filter, self.escaped(name))
        elif email:
            filter = "(&%s(|(mail=%s)(proxyAddresses=smtp:%s)))" % (self.filter, self.escaped(email), self.escaped(email))

        if dn:
            try:
                # TODO: it seems that if we specify attrilist = ['manager'] or just 'manager ' it will fail
                # This seems like a bug in ldap3 to me.
                r = self.search_ext_s(base=dn, scope=ldap3.SEARCH_SCOPE_BASE_OBJECT, filterstr='(objectClass=*)')
                if len(r) > 1:
                    raise NotImplementedError("getAttribute does not support returning attribute for multiple entities")
                return r[0]['attributes'][attribute][0]
                # filter, [attribute]
            except Exception as e:
                raise e
        else:
            r = self.search_ext_s(filterstr=filter, attrlist=[attribute])

        if not r:
            return None
        # if not user or not r or len(r) != 1:
        #    return None
        if attribute in r[0]['attributes']:
            return r[0]['attributes'][attribute][0]  # display name is returned as a list
        else:
            logging.error("xxx")

    def get_name(self, user=None):
        return self.__as_unicode(self.get_attribute('displayName', user=user))

    def get_username(self, user=None, dn=None):
        if user:
            return self.get_attribute('sAMAccountName', user=user)
        elif dn:
            return self.get_attribute('sAMAccountName', dn=dn)
        else:
            NotImplementedError()

    def get_dn(self, user):
        filter = "(&%s(sAMAccountName=%s))" % (self.filter, user)
        r = self.search_ext_s(filterstr=filter, scope=self.scope)
        if not user or not r or len(r) != 1:
            return None
        return r[0]['dn']

    def get_email(self, user=None):
        return self.__as_unicode(self.get_attribute(attribute='mail', user=user))

    def is_user_enabled(self, user):
        ret = None
        dn = self.get_dn(user)
        if user is None:
            return None
        attr = self.get_attribute(attribute="userAccountControl", user=user)
        if attr is None:
            return None
        if int(attr) & 0x02:
            return False
        else:
            return True

    def find_by_nis(self, pwent):
        # By user
        attrs = self.get_attributes(user=pwent.user)
        if attrs:
            return attrs
        attrs = self.get_attributes(name=pwent.fullname)
        if attrs:
            return attrs


class ActiveDirectoryTestCase(unittest.TestCase):

    def setUp(self):
        self.size_limit = 5
        self.paged_size = 2
        self.time_limit = 10

        """
        To prevent scanners from detecting and hammering the server we do not use standard ports. Even so the credentials below are just for a single limited test user.

        389 -> 10389
        636 -> 10636 or 8443 ?
        3268 -> 13268
        3269 -> 13269
        """

        test_server = 'sorintest.cloudapp.net'
        test_port = 10389
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((test_server, test_port))
        if result != 0:
            raise Exception("Cannot connect to LDAP server %s:%s: Error %s" % (test_server, test_port, result))

        self.ad = ActiveDirectory("ldap://%s:%s" % (test_server, test_port),
                                  dn='john.doe@AD.SBARNEA.COM',
                                  secret='a3sv42vAS2vl',
                                  size_limit=self.size_limit,
                                  paged_size=self.paged_size,
                                  time_limit=self.time_limit
                                  )

    def test_get_name(self):
        name = self.ad.get_name('john.doe')
        self.assertEqual(name, u'John Doe')

    def test_get_name2(self):
        # this one tests special characters that do need to be properly escaped
        self.assertEqual(self.ad.get_name('tester'), 'Eşcâpe Tester (./\@$#)')

    def test_get_email_invalid(self):
        # getting email of non existing account should return none
        self.assertEqual(self.ad.get_email('xcxsfscbr33g'), None)

    def test_get_email(self):
        self.assertEqual(self.ad.get_email('john.doe'), 'john.doe@AD.SBARNEA.COM')

    def test_get_manager(self):
        self.assertEqual(self.ad.get_manager('john.doe'), 'god')

    def test_get_users(self):
        users = self.ad.get_users()
        self.assertEqual(len(users), self.size_limit)

    def test_get_users_new_filter(self):
        users = self.ad.get_users(new_filter='(mail=god@ad.sbarnea.com)')
        self.assertEqual(users[0], 'god')

    def test_get_manager_unicode(self):
        x = self.ad.get_manager(u"_Paris vidéo p-1")
        self.assertEqual(x, None)

    def test_is_user_enabled(self):
        self.assertTrue(self.ad.is_user_enabled('john.doe'))

    def test_is_user_enabled_non_existing(self):
        self.assertTrue(self.ad.is_user_enabled('sdsECGCCgcreRHdrsrdhd') is None)

    def test_get_attributes(self):
        user = self.ad.get_attributes(user='john.doe')
        self.assertEqual(user['displayName'], u'John Doe')
        self.assertEqual(user['name'], u'John Doe')

    # def test_get_attributes_multiple(self):
    #    user = self.ad.get_attributes(user='adm_gregsl')
    #    self.assertEqual(user['displayName'], u'Sorin Sbârnea')
    #    self.assertEqual(user['name'], u'Sorin Sbârnea')


if __name__ == "__main__":
    import sys

    logging.basicConfig(format='%(levelname)s %(message)s', level=logging.DEBUG)

    unittest.main()
