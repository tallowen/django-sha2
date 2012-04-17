import base64
import bcrypt
import hmac
import hashlib
import logging

from django.conf import settings
from django.contrib.auth.hashers import BCryptPasswordHasher
from django.utils.encoding import smart_str

log = logging.getLogger('common.hashers')

algo_name = lambda hmac_id: 'bcrypt{0}'.format(hmac_id.replace('-', '_'))


def get_hasher(hmac_id):
    """
    Dynamically create password hashers based on hmac_id.

    This class takes the hmac_id corresponding to an HMAC_KEY and creates a
    password hasher class based off of it. This allows us to use djangos
    built-in updating mechanisms to automatically update the HMAC KEYS.
    """
    dash_hmac_id = hmac_id.replace('_', '-')

    class BcryptHMACPasswordHasher(BCryptPasswordHasher):
        algorithm = algo_name(hmac_id)
        rounds = 12

        def encode(self, password, salt):

            shared_key = settings.HMAC_KEYS[dash_hmac_id]

            hmac_value = self._hmac_create(password, shared_key)
            bcrypt_value = bcrypt.hashpw(hmac_value, salt)
            return '{0}{1}${2}'.format(
                self.algorithm,
                bcrypt_value,
                dash_hmac_id)

        def verify(self, password, encoded):
            algo_and_hash, key_ver = encoded.rsplit('$', 1)
            try:
                shared_key = settings.HMAC_KEYS[key_ver]
            except KeyError:
                log.info('Invalid shared key version "{0}"'.format(key_ver))
                return False

            bc_value = '${0}'.format(algo_and_hash.split('$', 1)[1])  # Yes, bcrypt <3s the leading $.
            hmac_value = self._hmac_create(password, shared_key)
            return bcrypt.hashpw(hmac_value, bc_value) == bc_value

        def _hmac_create(self, password, shared_key):
            """Create HMAC value based on pwd"""
            hmac_value = base64.b64encode(hmac.new(
                    smart_str(shared_key),
                    smart_str(password),
                    hashlib.sha512).digest())
            return hmac_value

    return BcryptHMACPasswordHasher

# We must have HMAC_KEYS. If not, let's raise an import error.
if not settings.HMAC_KEYS:
    raise ImportError('settings.HMAC_KEYS must not be empty.')

# Create the basic 'bcrypt' algorithm for compatibility with django_sha2
# passwords
BcryptHMACPasswordHasher = get_hasher('')

# For each HMAC_KEY, dynamically create a hasher to be imported.
for hmac_key in settings.HMAC_KEYS.keys():
    hmac_id = hmac_key.replace('-', '_')
    globals()[algo_name(hmac_id)] = get_hasher(hmac_id)
