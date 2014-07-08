#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import ConfigParser
import logging
import os
import traceback
import unittest
from collections import defaultdict
from urlparse import urlparse
import ldap3


class ActiveDirectory(object):
    @staticmethod
    def factory(section, debug=False):
        config = ConfigParser.RawConfigParser()
        fname = os.path.splitext(__file__)[0] + ".ini"
        config.read(fname)
        server = config.get(section, 'hostname')
        username = config.get(section, 'bind_username')
        password = config.get(section, 'bind_password')
        try:
            basedn = config.get(section, 'base_dn')
        except:
            basedn = ""
        ret = ActiveDirectory(url=server, dn=username, secret=password, base=basedn, debug=debug)
        return ret

    def reconnect(self):
        self.__init__(self.url, self.dn, self.secret, base=self.base)

    def __init__(self, url, dn=None, secret=None, base="", debug=False, paged_size = 1000, size_limit=0):
        """
        @param server: url of LDAP Server
        @param dn: username of the service account
        @param secret: password of the servce account
        """
        self.filter = ''
        self.scope = ldap3.SEARCH_SCOPE_WHOLE_SUBTREE
        self.paged_size = paged_size
        self.size_limit = size_limit
        self.attrs = '*'

        self.logger = logging.getLogger('ldap')
        if debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
        self.url = url

        self.dn = dn
        self.secret = secret
        self.base = base

        u = urlparse(url)
        if u.scheme == 'ldaps':
            use_ssl = True
        else:
            use_ssl = False

        if ":" in u.hostname:
            u.hostname = u.hostname.split(":")[0]
        if dn is None:
            import netrc
            netrc_config = netrc.netrc()
            for h in netrc_config.hosts:
                if h == u.hostname:
                    dn, account, secret = netrc_config.authenticators(h)
                    break

        self.server = ldap3.Server(host=u.hostname, port=u.port, use_ssl=use_ssl)
        self.conn = ldap3.Connection(self.server,
                                     auto_bind = True,
                                     client_strategy = ldap3.STRATEGY_SYNC,
                                     user=dn,
                                     password=secret,
                                     authentication=ldap3.AUTH_SIMPLE)
        try:
            ret = self.conn.bind()
            #ret = self.conn.simple_bind_s(self.dn, self.secret)
        except Exception, e:
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

    def __del__(self):
        if self.conn:
            self.conn.unbind()

    def search_ext_s(self, filterstr=None, attrlist=None, base=None, scope=None):
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
            base,
            search_filter=filterstr,
            search_scope=scope,
            attributes=attrlist,
            paged_size=self.paged_size,
            size_limit=self.size_limit
        )
        if self.conn.result['description'] == 'sizeLimitExceeded' or 'controls' not in self.conn.result:
            cookie = None
        else:
            cookie = self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        ret.extend(self.conn.response)

        total_entries += len(self.conn.response)
        while cookie:
            self.conn.search(
                    self.base,
                    search_scope=self.scope,
                    search_filter=filterstr,
                    attributes=attrlist,
                    paged_size=self.paged_size,
                    paged_cookie=cookie
                )
            if self.conn.result['description'] == 'sizeLimitExceeded':
                cookie = None
            else:
                cookie = self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
            total_entries += len(self.conn.response)
            ret.extend(self.conn.response)

        # FIX for Microsoft bug: ldap.UNAVAILABLE_CRITICAL_EXTENSION: {'info': '00002040: SvcErr: DSID-031401E7, problem 5010 (UNAVAIL_EXTENSION), data 0\n', 'desc': 'Critical extension is unavailable'}
        # explain: second pagination query fails, so after a query we will establish a new connection to the server.
        #if pages > 1:
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
        filter = "(&%s(sAMAccountName=%s))" % (self.filter, user)
        ret = self.search_ext_s(filter, ["manager"])
        if ret and ret[0] and isinstance(ret[0][1], dict):
            ret = ret[0][1].get("manager")
            if ret:
                return ActiveDirectory.decode_cn(ret[0])

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

    def get_users(self):
        filter = "(&%s(sAMAccountName=*)(samAccountType=805306368)(mail=*))" % self.filter
        rets = []
        for x in self.search_ext_s(filterstr=filter, attrlist=["sAMAccountName"]):
        # if ret and ret[0] and isinstance(ret[0][1], dict):
            rets.append(x['attributes']["sAMAccountName"][0])
        return sorted(set(rets))

    def get_groups(self):
        """

        :type self: object
        """
        filter = "(&(objectCategory=group)(mail=*))"
        rets = []
        for x in self.search_ext_s(filterstr=filter, attrlist=["sAMAccountName"]):
        # if ret and ret[0] and isinstance(ret[0][1], dict):
            rets.append(x[1].get("sAMAccountName")[0])
        return sorted(rets)

    def get_manager_attributes(self, user):
        manager = self.get_manager(user)
        if manager and "CN" in manager:
            name = manager["CN"][0]
            ret = self.get_attributes(name=name)
            return ret

    @staticmethod
    def escaped(query):
        return query
        #return ldap.filter.escape_filter_chars(query)

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
        # Type,user = self.conn.result(r,60)
        # print Type,user
        # sys.exit()
        # print "user:", user
        # Name,Attrs = user[0]
        if not r:
            return None
        # print(r[0])
        Name = r[0]['dn']
        Attrs = r[0]['attributes']
        for attribute in attributes:
            if hasattr(Attrs, 'has_key') and attribute in Attrs:
                res[attribute] = Attrs[attribute][0]
        return res

    def get_attribute(self, attribute='sAMAccountName', user=None, email=None, name=None, dn=None):
        """

        :param attribute:
        :param user:
        :param email:
        :param name:
        :param dn:
        :return: str
        """
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

        #self.logger.debug(filter)
        if dn:
            filter = "(&%s(sAMAccountName=*))" % self.filter
            r = self.search_ext_s( base=dn, scope=ldap3.SEARCH_SCOPE_BASE_OBJECT)
            # filter, [attribute]
        else:
            r = self.search_ext_s(filterstr=filter, attrlist=[attribute])

        if not r:
            return None
        # if not user or not r or len(r) != 1:
        #    return None
        if attribute in r[0]['attributes']:
            return r[0]['attributes'][attribute][0] # display name is returned as a list
        else:
            logging.error("xxx")

    def get_name(self, user=None):
        return self.get_attribute('displayName', user=user)

    def get_username(self, user=None, dn=None):
        if user:
            return self.get_attribute('sAMAaccount', user=user)
        elif dn:
            return self.get_attribute('sAMAaccount', dn=dn)
        else:
            NotImplementedError()

    def get_dn(self, user):
        filter = "(&%s(sAMAccountName=%s))" % (self.filter, user)
        r = self.search_ext_s(filterstr=filter, scope=self.scope)
        if not user or not r or len(r) != 1:
            return None
        return r[0]['dn']

    def get_email(self, user=None):
        return self.get_attribute('mail', user=user)

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
        # "ldap://ldap.forumsys.com:389", "cn=read-only-admin,dc=example,dc=com", "password"

        directory = "ldap://ldap.forumsys.com:389"
        self.ad = ActiveDirectory(directory, dn='cn=read-only-admin,dc=example,dc=com', secret='password', size_limit=50)

    def test_get_name(self):
        self.assertEqual(self.ad.get_name('gauss'), 'Sorin Sbârnea')

    def test_get_email(self):
        self.assertEqual(self.ad.get_email('gauss'), 'sorin.sbarnea@citrix.com')

    def test_get_users(self):
        self.ad.get_users()

    def test_is_user_enabled(self):
        self.assertTrue(self.ad.is_user_enabled('gauss'))

    def test_is_user_enabled_non_existing(self):
        self.assertTrue(self.ad.is_user_enabled('sdsECGCCgcreRHdrsrdhd') is None)

if __name__ == "__main__":
    import sys

    logging.basicConfig(format='%(levelname)s %(message)s', level=logging.DEBUG)

    if len(sys.argv) < 2:
        logging.error("Please specify the URI of the LDAP server to connect to.")
        sys.exit(2)
    else:
        directory = sys.argv[1]
    logging.info("--- %s ---" % directory)



    unittest.main()

    logging.debug('---')
