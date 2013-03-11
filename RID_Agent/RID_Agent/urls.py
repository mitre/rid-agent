######################################################################################
#                                                                                    #
# Copyright (C) 2012-2013 - The MITRE Corporation. All Rights Reserved.              #
#                                                                                    #
# By using the software, you signify your aceptance of the terms and                 #
# conditions of use. If you do not agree to these terms, do not use the software.    #
#                                                                                    #
# For more information, please refer to the license.txt file.                        #
#                                                                                    #
######################################################################################

from django.conf.urls import patterns, include, url
from django.core.urlresolvers import resolve, reverse
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('RID_Agent.views',
	#RID Peer URL
	url(r'^$', 'rid', name='Home'),
	
	#Login/logout URLs
	url(r'^login/$', 'login', name='Login'),
	url(r'^logout/$', 'logout', name='Logout'),
	
	#Manage/docs urls.
	url(r'^manage/?(.*)/$', 'manage', name='Management'),
	url(r'^docs/?(.*)/$', 'docs', name='Documentation'),

	#Tools URLs	
	url(r'^tools/$', 'tools_index'),
	url(r'^tools/send_rid_message/$', 'tools_send_rid_message'),
	url(r'^tools/build_incoming_api_query/', 'tools_build_incoming_api_query'),
	url(r'^tools/build_outgoing_api_push/', 'tools_build_outgoing_api_push'),
	url(r'^tools/check_cert_chains/', 'tools_check_cert_chains'),

	url(r'^logs/$', 'logs', name='Logs'),
	
	#API 1.0 URLS
	url(r'^api/1.0/login/$', 'api_10_login', name='API Login'),
	url(r'^api/1.0/logout/$', 'api_10_logout', name='API Logout'),
	url(r'^api/1.0/pull_incoming_messages/$', 'api_10_pull_incoming_messages', name='API Pull Incoming Messages'),
	url(r'^api/1.0/push_outgoing_message/$', 'api_10_push_outgoing_message', name='API Push Outgoing Message'),
)

urlpatterns += patterns('',
	# Uncomment the admin/doc line below to enable admin documentation:
	#url(r'^admin/doc/', include('django.contrib.admindocs.urls')),
	
	# Uncomment the next line to enable the admin:
	url(r'^admin/', include(admin.site.urls)),

)
