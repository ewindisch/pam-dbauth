# vim: noai:ts=2:sw=2:set expandtab:
#
# pam_mysql.py
# Performs salted-hash authentication from MySQL
#
"""
  Author: Eric Windisch <eric@windisch.us>
  Copyright: 2010, Eric Windisch <eric@grokthis.net>, VPS Village
  License: EPL v1.0
"""


"""
Add to PAM configuration with:
  auth    required    pam_python.so pam_mysql.py


Requires configuration file, /etc/security/pam_mysql.conf,
Example:

  [database]
  host=localhost
  user=myuser
  password=mypass
  db=myuser_db

  [query]
  select_statement=select password from users where username=%s

  ; ---------------------------------------------------------------- 
  ;  Support forcing or defaulting hashtypes,
  ;  ONLY effective if stored password does not start with {hashtype}.
  ; ---------------------------------------------------------------- 
  ; hashtype_force=sha1
  ;
  ; ----------------------------------------------------------------
  ;  Default type to be used if all auto-detection fails (unlikely)
  ; ----------------------------------------------------------------
  ; hashtype_default=md5
  ;
"""

import MySQLdb
import syslog
import hashlib
import base64
import string

import ConfigParser

def pam_sm_authenticate(pamh, flags, argv):
  resp=pamh.conversation(
    pamh.Message(pamh.PAM_PROMPT_ECHO_OFF,"Password")
  )

  try:
    user = pamh.get_user(None)
  except pamh.exception, e:
    return e.pam_result
  if user == None:
    return pamh.PAM_USER_UNKNOWN

  try:
    config = ConfigParser.ConfigParser()
    config.read('/etc/security/pam_mysql.conf')

    db=MySQLdb.connect(
      host=config.get('database', 'host'),
      user=config.get('database', 'user'),
      passwd=config.get('database','password'),
      db=config.get('database','db')
      )
    cursor=db.cursor()
    cursor.execute(config.get('query','select_statement'),(user))
    pass_raw=cursor.fetchone()[0]
    pass_stored=pass_raw

    # We search for a {} section containing the hashtype
    htindex=string.find(pass_raw,"}")
    if htindex > 0:
      # password contained a hashtype
      hashtype=pass_raw[1:htindex]
      # Remove the hashtype indicator
      pass_stored=pass_raw[htindex:]
    elif config.has_option('query','hashtype_force'):
      # if a hashtype is forced on us
      hashtype=config.get('query','hashtype_force')
    elif len(pass_raw) == 16:
      # assume 16-byte length is md5
      hashtype='md5'
    elif len(pass_raw) == 20:
      # assume 20-byte length is sha-1
      hashtype='ssha1'
    elif config.has_option('query','hashtype_default'):
      # attempt to fall back...
      hashtype=config.get('query','hashtype_default')
    else:
      return pamh.PAM_SERVICE_ERR

    pass_decoded=base64.b64decode(pass_stored)

    # Set the hashlib
    hl={
      'ssha1': hashlib.sha1(),
      'sha1': hashlib.sha1(),
      'md5':  hashlib.md5()
    }[hashtype]

    pass_base=pass_decoded[:hl.digest_size]
    pass_salt=pass_decoded[hl.digest_size:]

    hl.update(resp.resp)
    hl.update(pass_salt)

    hashedrep = base64.b64encode(hl.digest())

    if hl.digest() == pass_base:
      syslog.syslog ("pam-mysql.py hashes match")
      return pamh.PAM_SUCCESS
    else:
       pamh.PAM_AUTH_ERR
  except:
     return pamh.PAM_SERVICE_ERR

  return pamh.PAM_SERVICE_ERR

def pam_sm_setcred(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_open_session(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_close_session(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_chauthtok(pamh, flags, argv):
  return pamh.PAM_SUCCESS

#if __name__ == '__main__':
#  pam_sm_authenticate(pamh, flags, argv):


"""
  Author: Eric Windisch <eric@windisch.us>
  Copyright: 2010, Eric Windisch <eric@grokthis.net>, VPS Village
  License: EPL v1.0
"""

