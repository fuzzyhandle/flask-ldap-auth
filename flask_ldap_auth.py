#!/usr/bin/env python
# encoding: utf-8


from functools import wraps
from flask import Blueprint, current_app, jsonify, Response, request, url_for
from enum import Enum
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import BadSignature, SignatureExpired
import json
import ldap
import re

import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

token = Blueprint('token', __name__)


__all__ = [
    'login_required',
    'token'
    ]

class UserAccess(Enum):
    DEFAULT_ALLOW = 1
    DEFAULT_DENY = 2
    NOT_FOUND = 3
    DENY = 4
    DENY_GROUP = 5
    ALLOW = 6
    ALLOW_GROUP = 7

class UserAuth(Enum):
    DEFAULT_SUCCESS = 1
    DEFAULT_FAILURE = 2
    SUCCESS = 3
    FAILURE = 4
    
class User(object):

    def __init__(self, username):
        self.username = username
        
    def verify_user(self):
        connection_bind = ldap.initialize(current_app.config['LDAP_AUTH_SERVER'])
        
        bind_account =  current_app.config['LDAP_BIND_ACCOUNT']
        bind_password = current_app.config['LDAP_BIND_PASSWORD']
        
        connection_bind.protocol_version = 3
        connection_bind.set_option(ldap.OPT_REFERRALS, 0)

        try:
            logger.debug('Attempting LDAP bind for account %s', bind_account)
            connection_bind.simple_bind_s(bind_account, bind_password)
            logger.info('LDAP bind for account %s successful', bind_account)
            
            result = connection_bind.search_s(
                current_app.config['LDAP_TOP_DN'],
                ldap.SCOPE_SUBTREE,
                '(sAMAccountName={})'.format(self.username)
                )
                            
            if not result:
                logger.error('User %s not found',self.username )
                return (UserAccess.NOT_FOUND, None)

            dn = result[0][0]

            usergroups = []
            try:
                #Byte array
                b_usergroups = result[0][1]['memberOf']
                
                #Covert elements in array from byte to stirng
                usergroups = [ x.decode() for x in b_usergroups ]
                
            except IndexError as  e:
                logger.warn('Error referencing array index for getting usergroups')
            except KeyError as e:
                logger.warn('memberOf key missing for user {0}'.format(dn))

            logger.debug("User is {0}".format(self.username))
            
            allowusers = json.loads (current_app.config.get('LDAP_ALLOW_USERS', '[]'))
            denyusers = json.loads (current_app.config.get('LDAP_DENY_USERS', '[]' ))
            
            allowgroups = json.loads (current_app.config.get('LDAP_ALLOW_GROUPS', '[]'))
            denygroups = json.loads (current_app.config.get('LDAP_DENY_GROUPS', '[]' ))
            
            #Check Deny
            if denyusers:
                #Check current user is in the list
                if self.username in denyusers:
                    logger.error('User %s is in deny list', dn)
                    return (UserAccess.DENY, dn)
                    
            if denygroups:
                #Check current user is in the memberOf list
                for dg in denygroups:
                    for ug in usergroups:
                        if  re.match("CN={0}".format(dg), ug, re.IGNORECASE):
                            logger.error('Group {0} for user {1} is in deny list'.format(dg,dn))
                            return (UserAccess.DENY_GROUP, dn)
                else:
                    logger.info('Groups for User {0} not in deny list'.format(dn))
                    
            #Check Allow                
            
            if allowusers:
                logger.debug("Allow user list is {0}".format(allowusers))
                #Check current user is in the list
                if self.username in allowusers:
                    logger.info('User %s is in allow list', dn)
                    return (UserAccess.ALLOW, dn)

            if allowgroups:
                #Check current user is in the memberOf list
                for ag in allowgroups:
                    for ug in usergroups:    
                        #logger.info('Allow group {0}. Use group {1}.'.format(ag,ug))
                        #logger.info('Allow group type {0}. Use group type {1}.'.format(type(ag),type(ug)))
                        if  re.match("CN={0}".format(ag), ug, re.IGNORECASE):


                            logger.info('Group {0} for user {1} is in allow list'.format(ag,dn))
                            return (UserAccess.ALLOW , dn)
                else:
                    logger.error('Groups for User {0} not in allow list'.format(dn))
                    return (UserAccess.DEFAULT_DENY, dn)
                    
            return (UserAccess.DEFAULT_ALLOW, dn)
        
        except ldap.INVALID_CREDENTIALS:
              logger.error('LDAP bind for account %s failed. Invalid credentials', bind_account)
              return (UserAccess.DEFAULT_DENY, dn)
        else:
            try:
                connection_bind.unbind_s()
            except:
                pass
                
    def verify_password(self, dn, password):
        connection_auth = ldap.initialize(current_app.config['LDAP_AUTH_SERVER'])
        connection_auth.protocol_version = 3
        connection_auth.set_option(ldap.OPT_REFERRALS, 0)
                
        try:
            logger.debug('Attempting LDAP bind for account %s', dn)
            connection_auth.bind_s(dn, password)
            logger.info('LDAP bind for account %s successful', dn)
            return UserAuth.SUCCESS
        except ldap.INVALID_CREDENTIALS:
            logger.error('LDAP bind for account %s failed. Invalid credentials', dn)
            return UserAuth.FAILURE
        else:
            try:
                connection_auth.unbind_s()
            except:
                pass

        return UserAuth.DEFAULT_FAILURE

    def generate_auth_token(self):
        s = Serializer(current_app.config['SECRET_KEY'], expires_in=3600)
        return s.dumps({'username': self.username}).decode('utf-8')

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except (BadSignature, SignatureExpired, TypeError):
            return None
        return User(data['username'])


def authenticate_401():
    message = {
        'error': 'unauthorized',
        'message': 'Please authenticate with a valid token',
        'status': 401
        }
    response = Response(
        json.dumps(message),
        401,
        {
            'WWW-Authenticate': 'Basic realm="Authentication Required"',
            'Location': url_for('token.request_token')
            }
        )
    return response
    
def authenticate_403():
    message = {
        'error': 'unauthorized',
        'message': 'Please authenticate with an authorized user account',
        'status': 403
        }
    response = Response(
        json.dumps(message),
        403,
        {
            'WWW-Authenticate': 'Basic realm="Authentication Required"',
            'Location': url_for('token.request_token')
            }
        )
    return response
    

def login_required(func):
    """LDAP authentication decorator"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or not User.verify_auth_token(auth.username):
            return authenticate_401()
        return func(*args, **kwargs)
    return wrapper


@token.route('/request-token', methods=['POST'])
def request_token():
    """Simple app to generate a token"""
    auth = request.authorization
    user = User(auth.username)
    print(auth.username)
    if auth:
        retverifyuser = user.verify_user()
        uservalidity = retverifyuser [0]
        dn  = retverifyuser [1]
        
        if uservalidity in (UserAccess.DEFAULT_ALLOW, UserAccess.ALLOW, UserAccess.ALLOW_GROUP):
            passwordvalidity = user.verify_password (dn,auth.password)
            
            if passwordvalidity in (UserAuth.DEFAULT_SUCCESS,UserAuth.SUCCESS):
                response = {
                'token': user.generate_auth_token() + ':'
                }
                return jsonify(response)
            else:
                return authenticate_401()
        else:
            return authenticate_403()
    else:
        return authenticate_401()
        

# EOF
