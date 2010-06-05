# vim: noai:ts=2:sw=2:set expandtab:
#
# pam_mysql.py
# Performs SSHA1 authentication from MySQL
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
    pass_stored=string.lstrip(cursor.fetchone()[0],"{ssha1}")
    pass_decoded=base64.b64decode(pass_stored)
    pass_base=pass_decoded[:20]
    pass_salt=pass_decoded[20:]

    #  syslog.syslog ("pam-mysql.py stored password: %s" % (pass_stored))
    #  syslog.syslog ("pam-mysql.py plain-text response: %s" % (resp.resp))
    #
    #  syslog.syslog ("pam-mysql.py base: %s" % (len(pass_base)))
    #  syslog.syslog ("pam-mysql.py salt: %s" % (len(pass_salt)))

    hl=hashlib.sha1()
    hl.update(resp.resp)
    hl.update(pass_salt)

    hashedrep = base64.b64encode(hl.digest())
    #syslog.syslog ("pam-mysql.py hashed response: %s" % (hashedrep))
    #syslog.syslog ("pam-mysql.py sizes: %s %s" % (len(hl.digest()), len(pass_decoded)))

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

