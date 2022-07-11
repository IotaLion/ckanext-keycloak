# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import logging

from ckan import plugins
from ckan.plugins import toolkit
from urllib import request
from ckan.lib.helpers import redirect_to as redirect
import ckan.model as model
import json
import logging
import os
from six.moves.urllib.parse import urljoin
from base64 import b64encode, b64decode
from ckan.common import config
from keycloak.realm import KeycloakRealm

log = logging.getLogger(__name__)

class KeycloakHelper(object):

    def __init__(self):
        self.authorization_endpoint = config.get('ckan.keycloak.authorization_endpoint', None)
        self.client_id = config.get('ckan.keycloak.client_id', None)
        self.client_secret = config.get('ckan.keycloak.client_secret', None)
        self.realm = config.get('ckan.keycloak.realm', 'ckan')
        self.profile_username_field = config.get('ckan.keycloak.profile_username_field', None)
        self.profile_fullname_field = config.get('ckan.keycloak.profile_fullname_field', None)
        self.profile_email_field = config.get('ckan.keycloak.profile_email_field', None)
        self.profile_group_field = config.get('ckan.keycloak.profile_group_field', None)
        self.sysadmin_group_name = config.get('ckan.keycloak.sysadmin_group_name', None)
        realm = KeycloakRealm(server_url=self.authorization_endpoint, realm_name=self.realm)
        self.oidc_client = realm.open_id_connect(client_id=self.client_id,client_secret=self.client_secret)

    def identify(self, token):
        user_token = self.oidc_client.userinfo(token)
        user_data = self.oidc_client.decode_token(user_token, '', options={ 'verify_signature': False })
        try : email = user_data[self.profile_email_field]
        except :
            log.debug("Not Found Email.")
        try : user_name = user_data[self.profile_username_field]
        except :
            log.debug("Not Found User Name.")

        user = model.User.get(user_name)
        if user :
            return user.name
        user = None
        users = model.User.by_email(email)
        if len(users) == 1:
            user = users[0]
        if user is None:
            user = model.User(email=email)
        user.name = user_name
        if self.profile_fullname_field and self.profile_fullname_field in user_data:
            user.fullname = user_data[self.profile_fullname_field]
        if self.profile_group_field and self.profile_group_field in user_data:
            if self.sysadmin_group_name and self.sysadmin_group_name in user_data[self.profile_group_field]:
                user.sysadmin = True
            else:
                user.sysadmin = False
        model.Session.add(user)
        model.Session.commit()
        model.Session.remove()
        log.info('Add keycloak user into ckan database: %s'%user)
        return user.name


log = logging.getLogger(__name__)

class KeycloakPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IConfigurer)

    def __init__(self, name=None):
        self.keycloak_helper = KeycloakHelper()

    def update_config(self,config):
        return None

    def configure(self, config):
        required_keys = (
            'ckan.keycloak.authorization_endpoint',
            'ckan.keycloak.client_id',
            'ckan.keycloak.client_secret',
            'ckan.keycloak.realm',
            'ckan.keycloak.profile_username_field',
            'ckan.keycloak.profile_fullname_field',
            'ckan.keycloak.profile_email_field',
            'ckan.keycloak.profile_group_field',
            'ckan.keycloak.sysadmin_group_name'
        )
        for key in required_keys:
            if config.get(key) is None:
                raise RuntimeError('Required configuration option {0} not found.'.format(key))

    def identify(self):
        if not getattr(toolkit.c, u'user', None):
            self._identify_user_default()
        if toolkit.c.user and not getattr(toolkit.c, u'userobj', None):
            toolkit.c.userobj = model.User.by_name(toolkit.c.user)

    def _identify_user_default(self):
        toolkit.c.user = toolkit.request.environ.get(u'REMOTE_USER', u'')
        if toolkit.c.user:
            toolkit.c.user = toolkit.c.user.decode(u'utf8')
            toolkit.c.userobj = model.User.by_name(toolkit.c.user)
            if toolkit.c.userobj is None or not toolkit.c.userobj.is_active():
                ev = request.environ
                if u'repoze.who.plugins' in ev:
                    pth = getattr(ev[u'repoze.who.plugins'][u'friendlyform'],
                          u'logout_handler_path')
                redirect(pth)
        else:
            toolkit.c.userobj = self._get_user_info()
            if 'name' in dir(toolkit.c.userobj) :
                toolkit.c.user = toolkit.c.userobj.name
                toolkit.c.author = toolkit.c.userobj.name
                log.debug('toolkit.c.userobj.id :' + toolkit.c.userobj.id)
                log.debug('toolkit.c.userobj.name :' + toolkit.c.userobj.name)

    def _get_user_info(self):
        authorizationKey = toolkit.request.headers.get(u'Authorization', u'')
        if not authorizationKey:
            authorizationKey = toolkit.request.environ.get(u'Authorization', u'')
        if not authorizationKey:
            authorizationKey = toolkit.request.environ.get(u'HTTP_AUTHORIZATION', u'')
        if not authorizationKey:
            authorizationKey = toolkit.request.environ.get(u'Authorization', u'')
            if u' ' in authorizationKey:
                authorizationKey = u''
        if not authorizationKey:
            return None
        authorizationKey = authorizationKey.decode(u'utf8', u'ignore')
        user = None
        query = model.Session.query(model.User)
        user = query.filter_by(apikey=authorizationKey).first()
        if user == None : 
            try:
                user = self.keycloak_helper.identify(authorizationKey)
                user = query.filter_by(name=user).first()
            except Exception as e:
                log.error( e.message)
        return user
