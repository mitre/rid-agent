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


################## Begin RID_Agent Specific Settings ################
##### - These settings are specific to the RID Agent. Other settings are Django Settings
MAX_RID_MESSAGE_SIZE = 1024 * 1024 #In Bytes
KEY_FILE = '/etc/pki/tls/private/private_nopass.key'
CERT_FILE = '/etc/pki/tls/certs/public.crt'


####
################# End RID_Agent Specific Settings #############



DEBUG = True
TEMPLATE_DEBUG = DEBUG

ADMINS = (
    # ('Your Name', 'your_email@example.com'),
)

MANAGERS = ADMINS

DATE_FORMAT = 'Y-m-d' 
DATETIME_FORMAT = 'Y-m-d H:i:s.u'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql', # Add 'postgresql_psycopg2', 'mysql', 'sqlite3' or 'oracle'.
	#'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'rid_message_store',                      # Or path to database file if using sqlite3.
        'USER': 'PUT_USER_HERE',                      # Not used with sqlite3.
        'PASSWORD': 'PUT_PASSWORD_HERE',                  # Not used with sqlite3.
        'HOST': 'localhost',                      # Set to empty string for localhost. Not used with sqlite3.
        'PORT': '3306',                      # Set to empty string for default. Not used with sqlite3.
    }
}

APPEND_SLASHES=True

LOGIN_URL = '/login'
LOGIN_REDIRECT_URL = '/docs'
AUTH_PROFILE_MODULE = 'RID_Agent.user_profile'

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# On Unix systems, a value of None will cause Django to use the same
# timezone as the operating system.
# If running in a Windows environment this must be set to the same as your
# system time zone.
TIME_ZONE = 'America/Chicago'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale.
USE_L10N = True

# If you set this to False, Django will not use timezone-aware datetimes.
USE_TZ = True

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/home/media/media.lawrence.com/media/"
MEDIA_ROOT = ''

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://media.lawrence.com/media/", "http://example.com/media/"
MEDIA_URL = ''

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/home/media/media.lawrence.com/static/"
STATIC_ROOT = ''

# URL prefix for static files.
# Example: "http://media.lawrence.com/static/"
STATIC_URL = '/static/'

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
#    'django.contrib.staticfiles.finders.DefaultStorageFinder',
)

# Make this unique, and don't share it with anybody.
SECRET_KEY = 'nlhp6$(cwr9@v%q88-@2y^a=fe^0^=9!syadp9w5pt$d4f#8k#'

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
#     'django.template.loaders.eggs.Loader',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    # Uncomment the next line for simple clickjacking protection:
    # 'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

TEMPLATE_CONTEXT_PROCESSORS = (
    "django.contrib.auth.context_processors.auth",
    "django.core.context_processors.debug",
    "django.core.context_processors.i18n",
    "django.core.context_processors.media",
    "django.core.context_processors.static",
    "django.core.context_processors.tz",
    "django.contrib.messages.context_processors.messages",
)

ROOT_URLCONF = 'RID_Agent.urls'

# Python dotted path to the WSGI application used by Django's runserver.
#WSGI_APPLICATION = 'RID_Agent.wsgi.application'

TEMPLATE_DIRS = (
    '/var/www/RID_Agent/templates'
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'RID_Agent',
    # Uncomment the next line to enable the admin:
    'django.contrib.admin',
    # Uncomment the next line to enable admin documentation:
    # 'django.contrib.admindocs',
)

# A sample logging configuration. The only tangible logging
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error when DEBUG=False.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
	'verbose': {
	    'format': '%(levelname)s %(asctime)s %(name)s %(message)s'
	},
	'simple': {
	    'format': '%(levelname)s %(message)s'
	},
    },
    'handlers': {
	'rotating_file': {
		'level': 'DEBUG',
		'class': 'logging.handlers.RotatingFileHandler',
		'formatter': 'verbose',
		'filename': '/var/www/RID_Agent/RID_Agent/logs/rid_application_log.log',
		'maxBytes': '1048576',
		'backupCount': '3'
	},
    },
    'loggers': {
	'rid_agent': {
		'handlers': ['rotating_file'],
		'level': 'DEBUG',
		'propagate': True,
	},
    }
}
