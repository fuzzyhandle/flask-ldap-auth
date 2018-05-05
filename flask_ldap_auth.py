#!/usr/bin/env python
# encoding: utf-8


from functools import wraps
from flask import Blueprint, current_app, jsonify, Response, request, url_for
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


class User(object):

    def __init__(self, username):
        self.username = username

    def verify_password(self, password):
        connection_bind = ldap.initialize(current_app.config['LDAP_AUTH_SERVER'])
        
        bind_account =  current_app.config['LDAP_BIND_ACCOUNT']
        bind_password = current_app.config['LDAP_BIND_PASSWORD']

        connection_auth = ldap.initialize(current_app.config['LDAP_AUTH_SERVER'])

        connection_bind.protocol_version = 3
        connection_bind.set_option(ldap.OPT_REFERRALS, 0)

        connection_auth.protocol_version = 3
        connection_auth.set_option(ldap.OPT_REFERRALS, 0)

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
                return False

            dn = result[0][0]

            usergroups = []
            try:
                usergroups = result[0][1]['memberOf']
            except IndexError, e:
                logger.warn('Error referencing array index for getting usergroups')
            except KeyError, e:
                logger.warn('memberOf key missing for user {0}'.format(dn))

            logger.debug("User is {0}".format(self.username))
            #logger.debug('User %s is member of %s groups', dn, usergroups)
            #logger.debug('Group list has %d elements', len(usergroups))
                
            allowusers = json.loads (current_app.config.get('LDAP_ALLOW_USERS', '[]'))
            denyusers = json.loads (current_app.config.get('LDAP_DENY_USERS', '[]' ))
            
            allowgroups = json.loads (current_app.config.get('LDAP_ALLOW_GROUPS', '[]'))
            denygroups = json.loads (current_app.config.get('LDAP_DENY_GROUPS', '[]' ))
            
            #Check Deny
            denyme = False
            if denyusers:
                #Check current user is in the list
                if self.username in denyusers:
                    denyme = True
                    logger.error('User %s is in deny list', dn)
                    
            if not denyme and denygroups:
                #Check current user is in the memberOf list
                for dg in denygroups:
                    for ug in usergroups:    
                        if  re.match("CN={0}".format(dg), ug, re.IGNORECASE):
                            denyme = True
                            logger.error('Group {0} for user {1} is in deny list'.format(dg,dn))
                            break
                    else:
                        continue
                        
                    break
                else:
                    logger.info('Groups for User {0} not in deny list'.format(dn))

            if denyme:
              logger.error('User {0} is denied'.format(dn))
              return False
                
            #Check Allow                
            allowme = False
            if allowusers:
                logger.debug("Allow user list is {0}".format(allowusers))
                #Check current user is in the list
                if self.username in allowusers:
                    allowme = True
                    logger.info('User %s is in allow list', dn)

            if not allowme and allowgroups:
                #Check current user is in the memberOf list
                for ag in allowgroups:
                    for ug in usergroups:    
                        if  re.match("CN={0}".format(ag), ug, re.IGNORECASE):
                            allowme = True
                            logger.info('Group {0} for user {1} is in allow list'.format(ag,dn))
                            break
                    else:
                        continue
                        
                    break
                else:
                    logger.error('Groups for User {0} not in allow list'.format(dn))

            
            if not allowme:
                logger.error('User {0} is not allowed'.format(dn))
                return False
            
                
            
                    
            try:
                logger.debug('Attempting LDAP bind for account %s', dn)
                connection_auth.bind_s(dn, password)
                logger.info('LDAP bind for account %s successful', dn)
                return True
            except ldap.INVALID_CREDENTIALS:
                logger.error('LDAP bind for account %s failed. Invalid credentials', dn)
                return False
            else:
                try:
                    connection_auth.unbind_s()
                except:
                    None
        except ldap.INVALID_CREDENTIALS:
            logger.error('LDAP bind for account %s failed. Invalid credentials', bind_account)
            return False
        else:
            try:
                connection_bind.unbind_s()
            except:
                None

        return False

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


def authenticate():
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


def login_required(func):
    """LDAP authentication decorator"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or not User.verify_auth_token(auth.username):
            return authenticate()
        return func(*args, **kwargs)
    return wrapper


@token.route('/request-token', methods=['POST'])
def request_token():
    """Simple app to generate a token"""
    auth = request.authorization
    user = User(auth.username)
    print(auth.username)
    if not auth or not user.verify_password(auth.password):
        return authenticate()
    response = {
        'token': user.generate_auth_token() + ':'
        }
    return jsonify(response)

# EOF
