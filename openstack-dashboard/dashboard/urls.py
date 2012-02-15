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

"""
URL patterns for the OpenStack Dashboard.
"""

from django.conf.urls.defaults import *
from django.conf.urls.static import static
from django.conf import settings
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.views import generic as generic_views
import django.views.i18n

from django_openstack import urls as django_openstack_urls

urlpatterns = patterns('',
    url(r'^$', 'django.views.generic.simple.redirect_to',  {'url': 'https://trystack.org/'}),
    url(r'^dash/splash/$', 'dashboard.views.splash', name='splash'),
    url(r'^dash/$', 'django_openstack.dash.views.instances.usage',
        name='dash_overview'),
    url(r'^syspanel/$', 'django_openstack.syspanel.views.instances.usage',
        name='syspanel_overview'),
)

urlpatterns += patterns('dash_billing.dash.views',
    url(r'^dash/dash_billing/billing/$', 'index', name='dash_billing'),
    url(r'^dash/dash_billing/eventlog/$', 'eventlog', name='dash_eventlog'),
    url(r'^dash/dash_billing/eventlog/(?P<request_id>[^/]+)$', 'eventlog',name='dash_eventlog_by_request_id'),
)

urlpatterns += patterns('dash_billing.syspanel.views',
    url(r'^syspanel/billing/$', 'index', name='syspanel_billing'),
    url(r'^syspanel/billing/create/$', 'create', name='syspanel_billing_create'),
    url(r'^syspanel/billing/eventlog/$', 'eventlog', name='syspanel_eventlog'),
    url(r'^syspanel/billing/create_user_with_bill/$', 'create_user_with_bill', name='syspanel_create_user_with_bill')
)

# Development static app and project media serving using the staticfiles app.
urlpatterns += staticfiles_urlpatterns()

# Convenience function for serving user-uploaded media during
# development. Only active if DEBUG==True and the URL prefix is a local
# path. Production media should NOT be served by Django.
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# NOTE(termie): just append them since we want the routes at the root
urlpatterns += django_openstack_urls.urlpatterns
