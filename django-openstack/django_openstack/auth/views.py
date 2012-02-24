# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
# Copyright 2011 Nebula, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import os
import logging
import settings
import string
import json
import urllib
from django import template
from django import shortcuts
from django.contrib import messages

from django_openstack import api
from django_openstack import forms
from openstackx.api import exceptions as api_exceptions
from social_auth import context_processors
from social_auth.models import UserSocialAuth
from dash_billing.syspanel.models import AccountRecord

from random import choice

os.environ['NOVA_USERNAME'] = settings.NOVA_USERNAME
os.environ['NOVA_PASSWORD'] = settings.NOVA_PASSWORD

from dash_billing.billing.manager import FakeRequest
from django_openstack.middleware.keystone import User
from django.contrib.auth.models import User as AuthUser
LOG = logging.getLogger('django_openstack.auth')


class Login(forms.SelfHandlingForm):
    username = forms.CharField(max_length="20", label="User Name")
    password = forms.CharField(max_length="20", label="Password",
                               widget=forms.PasswordInput(render_value=False))

    def handle(self, request, data):

        def is_admin(token):
            for role in token.user['roles']:
                if role['name'].lower() == 'admin':
                    return True
            return False

        try:
            if data.get('tenant'):
                token = api.token_create(request,
                                         data.get('tenant'),
                                         data['username'],
                                         data['password'])

                tenants = api.tenant_list_for_token(request, token.id)
                tenant = None
                for t in tenants:
                    if t.id == data.get('tenant'):
                        tenant = t
            else:
                # We are logging in without tenant
                token = api.token_create(request,
                                         '',
                                         data['username'],
                                         data['password'])

                # Unscoped token
                request.session['unscoped_token'] = token.id

                def get_first_tenant_for_user():
                    tenants = api.tenant_list_for_token(request, token.id)
                    return tenants[0] if len(tenants) else None

                # Get the tenant list, and log in using first tenant
                # FIXME (anthony): add tenant chooser here?
                tenant = get_first_tenant_for_user()

                # Abort if there are no valid tenants for this user
                if not tenant:
                    messages.error(request, 'No tenants present for user: %s' %
                                            data['username'])
                    return

                # Create a token
                token = api.token_create_scoped_with_token(request,
                                         data.get('tenant', tenant.id),
                                         token.id)

            request.session['username'] = data['username']
            request.session['password'] = data['password']
            request.session['admin'] = is_admin(token)
            request.session['serviceCatalog'] = token.serviceCatalog

            LOG.info('Login form for user "%s". Service Catalog data:\n%s' %
                     (data['username'], token.serviceCatalog))

            request.session['tenant'] = tenant.name
            request.session['tenant_id'] = tenant.id
            request.session['token'] = token.id
            request.session['user'] = data['username']

            return shortcuts.redirect('dash_overview')

        except api_exceptions.Unauthorized as e:
            msg = 'Error authenticating: %s' % e.message
            LOG.exception(msg)
            messages.error(request, msg)
        except api_exceptions.ApiException as e:
            messages.error(request, 'Error authenticating with keystone: %s' %
                                     e.message)


class LoginWithTenant(Login):
    username = forms.CharField(max_length="20",
                       widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    tenant = forms.CharField(widget=forms.HiddenInput())


def _social_login(user_request, tenant_id, password):
    try:
        username = settings.NOVA_USERNAME
        admin_password = settings.NOVA_PASSWORD
        admin_tenant = settings.ADMIN_TENANT
        token = api.token_create(None, admin_tenant ,username , admin_password)
        admin_user = User(token.id,
                  username,
                  password,
                  True,
                  token.serviceCatalog
        )
        request = FakeRequest(admin_user)
        #TODO(nati):Fix this  there are no API to check tenant_Id on diablo version
        try:
            tenant = api.tenant_create(request,
                    tenant_id,
                    "Tenant",
                    True)
            LOG.info("tenant %s is created" % tenant_id)
            user = api.user_create(request,
                                   tenant_id,
                                   tenant_id + "@dammyemail",
                                   password,
                                   tenant.id,
                                   True)
            LOG.info("user %s is created" % tenant_id)
            api.role_add_for_tenant_user(
                request, tenant.id, user.id,
                settings.OPENSTACK_KEYSTONE_DEFAULT_ROLE)
            LOG.info("User role is added")
            accountRecord = AccountRecord(tenant_id=tenant.id,amount=int(1000),memo="Initial addtion")
            accountRecord.save()
            messages.success(user_request,"""
            Your Username/Password is created. Username %s Password %s
            """ % (tenant_id,password) )
        except Exception:
            pass

        LOG.debug("tenant id %s %s" % (tenant_id,password) )
        data={
            "username":tenant_id,
            "password": password }
        login_form = Login()
        login_form.handle(user_request,data)
    except api_exceptions.ApiException as e:
        messages.error(user_request,"Failed to login")
        LOG.error("Failed to login %s %r" % (tenant_id,e) )
        raise e

def login(request):
    if request.session.has_key('_auth_user_id'):
        user_id = request.session['_auth_user_id']
        social_user = UserSocialAuth.objects.get(user=user_id)
        django_user = AuthUser.objects.get(id=user_id)
        password = django_user.password
        tenant_id = social_user.provider + social_user.uid


        if not password or password == '!':
            password = "".join([choice(string.ascii_lowercase + string.digits) for i in range(8)])
            django_user.password = password
            django_user.save()

        if social_user.provider == "facebook":
            LOG.debug("%r" % social_user.extra_data['access_token'])
            try:
                group_url = "https://graph.facebook.com/269238013145112/members?access_token=%s" % social_user.extra_data['access_token']
                f = urllib.urlopen(group_url)
                graph_data_json = f.read()
                f.close()
                graph_data = json.loads(graph_data_json)
                if len(graph_data['data']) > 0 :
                    LOG.debug("graph_data %r" % graph_data)
                    _social_login(request,tenant_id,password)
                else:
                    messages.error(request, "Your facebookID is not in TryStack group yet.")
            except Exception as e:
                messages.error(request,"Failed to login facebookID")

    if request.user and request.user.is_authenticated():
        if request.user.is_admin():
            return shortcuts.redirect('syspanel_overview')
        else:
            return shortcuts.redirect('dash_overview')

    form, handled = Login.maybe_handle(request)
    if handled:
        return handled

    return shortcuts.render_to_response('splash.html', {
        'form': form,
    }, context_instance=template.RequestContext(request))


def switch_tenants(request, tenant_id):
    form, handled = LoginWithTenant.maybe_handle(
            request, initial={'tenant': tenant_id,
                              'username': request.user.username})
    if handled:
        return handled

    return shortcuts.render_to_response('switch_tenants.html', {
        'to_tenant': tenant_id,
        'form': form,
    }, context_instance=template.RequestContext(request))


def logout(request):
    request.session.clear()
    return shortcuts.redirect('splash')
