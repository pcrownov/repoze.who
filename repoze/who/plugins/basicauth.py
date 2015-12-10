import binascii
import logging

from webob.exc import HTTPUnauthorized
from zope.interface import implementer

from repoze.who.interfaces import IIdentifier
from repoze.who.interfaces import IChallenger
from repoze.who._compat import AUTHORIZATION
from repoze.who._compat import decodebytes
from repoze.who._compat import must_decode

logger = logging.getLogger(__name__)

@implementer(IIdentifier, IChallenger)
class BasicAuthPlugin(object):

    def __init__(self, realm):
        self.realm = realm

    # IIdentifier
    def identify(self, environ):
    	#get auth from header
        authorization = AUTHORIZATION(environ)
        logger.debug('BASIC AUTH: {0}'.format(authorization))

        if type(authorization) != type(b''):
            # this header *must* be base64-encoded ASCII
            authorization = authorization.encode('ascii')
        try:
            authmeth, auth = authorization.split(b' ', 1)
        except ValueError: # not enough values to unpack
            return None
        logger.debug('BASIC AUTH AUTHMETH: {0}'.format(authmeth.lower()))
        logger.debug('BASIC AUTH AUTH: {0}'.format(decodebytes(auth.strip())))
        if authmeth.lower() == b'basic':
            try:
                auth = auth.strip()
                auth = decodebytes(auth)
            except binascii.Error: # can't decode
                return None
            try:
                login, password = auth.split(b':', 1)
            except ValueError: # not enough values to unpack
                return None
            auth = {'login': must_decode(login),
                    'password': must_decode(password)}
            logger.debug('BASIC AUTH CREDS: {0}'.format(auth))
            return auth

        return None

    # IIdentifier
    def remember(self, environ, identity):
        # we need to do nothing here; the browser remembers the basic
        # auth info as a result of the user typing it in.
        pass

    def _get_wwwauth(self):
        head = [('WWW-Authenticate', 'Basic realm="%s"' % self.realm)]
        return head

    # IIdentifier
    def forget(self, environ, identity):
        return self._get_wwwauth()

    # IChallenger
    def challenge(self, environ, status, app_headers, forget_headers):
        head = self._get_wwwauth()
        if head[0] not in forget_headers:
            head = head + forget_headers
        return HTTPUnauthorized(headers=head)

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__,
                            id(self)) #pragma NO COVERAGE

def make_plugin(realm='basic'):
	logger.debug('BASIC AUTH MAKE PLUGIN')
    plugin = BasicAuthPlugin(realm)
    return plugin

