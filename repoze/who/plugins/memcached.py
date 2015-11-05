#
"""
A Plugin that allows you to use memcached as an IAuthentication and IIdentifier plugins for repoze.who. This system will store all user information in the cache of a system and is completely standalone. This is for use in systems where loss of user identification is low impact and presents no challeneges to the usage if that occurs.
"""

import logging
import memcache
import time
import datetime
from wsgiref.handlers import _monthname     # Locale-independent, RFC-2616
from wsgiref.handlers import _weekdayname   # Locale-independent, RFC-2616

from zope.interface import implementer

from repoze.who.interfaces import IIdentifier
from repoze.who.interfaces import IAuthenticator

from repoze.who._compat import get_cookies

from requests.exceptions import ConnectionError

logger = logging.getLogger(__name__)

_UTCNOW = None  # unit tests can replace
def _utcnow():  #pragma NO COVERAGE
    if _UTCNOW is not None:
        return _UTCNOW
    return datetime.datetime.utcnow()

@implementer(IIdentifier, IAuthenticator)
class MemcachedPlugin(object):
	def __init__(	self,
					hosts='127.0.0.1:11211',
					cookie_name='mc_tkt',
					timeout=None, 
					reissue_time=None,
					debug=0):
		
		if not hosts:
			raise ValueError('You must specify a Memcached Host string to connect to')
		
		try:
			self.mc = memcache.Client([hosts], debug=debug)
		except Exception as e:
			logger.error('Exception trying to establish Memcache connection')
			raise ConnectionError('Could not connect to the memcache server. Please check the provided host and try again')

		self.cookie_name = cookie_name
		if timeout and ( (not reissue_time) or (reissue_time > timeout) ):
			raise ValueError('When timeout is specified, reissue_time must '
							 'be set to a lower value')
		self.timeout = timeout
		self.reissue_time = reissue_time

	# IIdentifier
	def identify(self, environ):
		#get the cookie from the environment if it exsits
		cookies = get_cookies(environ)
		cookie = cookies.get(self.cookie_name)

		#check if it is not null
		if cookie is None or not cookie.value:
			return None

		try:
			#Use the cookie to get the users id from memcache
			user = self.mc.get(cookie.value)
		except Exception as e:
			logger.error('Exception getting user from memcache: {0}'.format(e))
			return None

		#check if user exists
		if not user:
			return None

		#check if user has timed out credentials
		if self.timeout and ( (user.timestamp + self.timeout) < time.time() ):
			return None

		#if user is valid and their creds haven't timed out then set environ and return the user data
		environ['REMOTE_USER_DATA'] = user
		environ['AUTH_TYPE'] = 'memcached'

		return user

	# IIdentifier
	def forget(self, environ, identity):
		#get the cookie and delete it's key & data from memcache
		cookies = get_cookies(environ)
		cookie = cookies.get(self.cookie_name)
		
		if cookie is None or not cookie.value:
			raise ValueError('Cookie is null or wrong type: {0}'.format(type(cookie)))

		self.mc.delete(cookie.value)
		
		# return a set of expires Set-Cookie headers
		return self._get_cookies(environ, 'INVALID', 0)
	
	# IIdentifier
	def remember(self, environ, identity):
		#get the users IP address to be stored
		users_ip = environ['REMOTE_ADDR']

		cookies = get_cookies(environ)
		cookie = cookies.get(self.cookie_name)
		max_age = identity.get('max_age', None)
		#if no timestamp then set to 0 as earliest to can be reissued
		timestamp = 0

		old_user = {}
		#get users data from memcache and compare it to new data received
		if cookie and cookie.value:
			timestamp = cookie.get('timestamp', 0)
			old_user = self.mc.get(cookie.value)
		
		new_user_data = identity.get('userdata', {})
		new_user_altid = identity.get('repoze.who.userid')
		new_user_given = new_user_data.get('givenName', '')
		new_user_sn = new_user_data.get('sn', '')
		new_user_uid = new_user_data.get('uid', None)
		new_user_ip = users_ip
		
		#build objects to compare
		old_data = (old_user.get('altid'), old_user.get('given'), old_user.get('sn'), old_user.get('uid'), old_user.get('ip'))
		new_data = (new_user_altid, 		new_user_given, 		new_user_sn, 		new_user_uid, 		new_user_ip)

		#if new data or reissue time is reached, then create new timestamp and store data in cache
		if old_data != new_data or (self.reissue_time and
				( (timestamp + self.reissue_time) < time.time() )):
			#get a new hash for the new cookie
			new_cookie_value = self._get_hash()
			#delete the old cookie's data from memcache
			if cookie and cookie.value:
				self.mc.delete(cookie.value)

			#add the new data for the new cookie
			new_user = {}
			new_user['timestamp'] = int(round(time.time() * 1000))
			new_user['altid'] = new_user_altid
			new_user['uid'] = new_user_uid
			new_user['given'] = new_user_given
			new_user['sn'] = new_user_sn
			new_user['ip'] = identity.get('ip')
			self.mc.set(new_cookie_value, new_user)

			# return a set of Set-Cookie headers
			return self._get_cookies(environ, new_cookie_value, max_age)

	# IAuthenticator
	def authenticate(self, environ, identity):
		userid = identity.get('altid', None)
		if userid is None:
			return None
		identity['repoze.who.userid'] = userid
		return userid

	def _get_cookies(self, environ, value, max_age=None):
		if max_age is not None:
			max_age = int(max_age)
			later = _utcnow() + datetime.timedelta(seconds=max_age)
			# Wdy, DD-Mon-YY HH:MM:SS GMT
			expires = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
				_weekdayname[later.weekday()],
				later.day,
				_monthname[later.month],
				later.year,
				later.hour,
				later.minute,
				later.second,
			)
			# the Expires header is *required* at least for IE7 (IE7 does
			# not respect Max-Age)
			max_age = "; Max-Age=%s; Expires=%s" % (max_age, expires)
		else:
			max_age = ''

		secure = '; secure; HttpOnly'

		cur_domain = environ.get('HTTP_HOST', environ.get('SERVER_NAME'))
		cur_domain = cur_domain.split(':')[0] # drop port
		wild_domain = '.' + cur_domain
		cookies = [
			('Set-Cookie', '%s="%s"; Path=/%s%s' % (
			self.cookie_name, value, max_age, secure)),
			('Set-Cookie', '%s="%s"; Path=/; Domain=%s%s%s' % (
			self.cookie_name, value, cur_domain, max_age, secure)),
			('Set-Cookie', '%s="%s"; Path=/; Domain=%s%s%s' % (
			self.cookie_name, value, wild_domain, max_age, secure))
			]
		return cookies

	def _get_hash(self):
		return self._get_random();

	def _get_random(self):
		import os
		return ''.join(str(x) for x in map(ord,os.urandom(20)))		
	
	def __repr__(self):
		return '<%s %s>' % (self.__class__.__name__,
							id(self)) #pragma NO COVERAGE

def make_plugin(hosts='127.0.0.1:11211',
				cookie_name='mc_tkt',
				timeout=None, 
				reissue_time=None,
				debug=0):
	if timeout:
		timeout = int(timeout)
	if reissue_time:
		reissue_time = int(reissue_time)
	if debug:
		debug = int(debug)

	plugin = MemcachedPlugin(	hosts,
								cookie_name,
								timeout,
								reissue_time,
								debug)
	return plugin
