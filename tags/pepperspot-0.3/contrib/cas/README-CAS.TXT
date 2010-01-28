---------------------------------------------------------------------
|        PepperSpot - The Next Generation Captive Portal            |
|                              with                                 |
|   Central Authentication Service - http://www.jasig.org/cas       |
---------------------------------------------------------------------

This document describes the use of PepperSpot with CAS authentication.

CAS is a Single Sign-On system (SSO).
Authenticated users can access to CASified applications without entering their IDs again.

The lists of supported applications is very long as CAS client is available on many platforms :
  Java/JSP, .Net/ASP, PHP, Perl, Apache, Ruby on Rails, ColdFusion, uPortal, ...
(See http://www.jasig.org/cas/client-integration/other-clients)

The CAS server can be configured to authenticate users with various systems such as :
  LDAP / Active Directory, RADIUS, SPNEGO, X.509 Certificates, JAAS, JDBC, ...
(See http://www.ja-sig.org/wiki/display/CASUM/Home)

+++++++++++++++++++++++
1) System Requirement +
+++++++++++++++++++++++

You need the following things to use CAS with PepperSpot:
  * A CAS server.
  * Add PHP support to UAM web server and use the new login script : hsl.php
  * Install PHP CAS client library on UAM web server.
  * A RADIUS server with CAS module (e.g. Free-RADIUS with rlm_cas).

If you have never install CAS before you can go directly to step 3.


+++++++++++++++++++++++++++++++++++
2) Configuring PepperSpot for CAS +
+++++++++++++++++++++++++++++++++++

We suppose here that your CAS server is running on https://cas.pepperspot.info:8443/.
The UAM web server supports PHP and phpCAS (see steps 4 and 5) and document root is /usr/local/apache2/htdocs/.
We suppose that UAM is located on the pepper's daemon machine at 192.168.182.1 or 2001:db8:1::1234.
The RADIUS server supports CAS ticket validation (see step 6).

1.1) Copying login script
-------------------------
You need to copy files from the extra directory:
  cd /usr/local/src/pepperspot-*
  cp -v extra/*.php /usr/local/apache2/htdocs/

1.2) Configuring login script
-----------------------------
You've just to edit /usr/local/apache2/htdocs/hsl.php.
1-You must set HS_UAMSECRET with a personal secret (when testing, you may use the default value).
  You can use the command below to generate a new random value:
    openssl rand -hex 10
  Copy this value in HS_UAMSECRET and in 'uamsecret' directive of /etc/pepper.conf.

2-(Optional) You may change HS_LANG to use proper translation messages.
  For the moment only 'en' and 'fr' are available (See *-msg-*.php files).

3-You must activate CAS (USE_CAS=true) and update the values corresponding to your architecture.
  For example, you have to set correctly the CAS_LIB_DIR constant with the right phpCAS version.
    define('USE_CAS',true);
    define('CAS_LIB_DIR','CAS-XXX');
    define('CAS_SERVER','cas.pepperspot.info');
    define('CAS_PORT',8443);
    # CAS_URL is the relative name of the CAS servlet URI
    # Set to '' if CAS servlet URI is /
    define('CAS_URL','');
    # CAS_SERVICE must be the same as "service" in RADIUS raddb/modules/cas.conf
    define('CAS_SERVICE','cas://PepperSpot');

  (Optional) If you want to verify CAS server certificate, you may configure CAS_CACERT with the right CA certificate.
  (Optional) You may set CAS_AUTO_SUBMIT_TIMEOUT if you want to enable automatic login form submission after the specified time in milliseconds.
  (Optional) You may set CAS_READONLY to true if you want to enable by default the readonly attribute for the values of the login form. The user will never be able to enter any value in the fields of the login form !

4-(Optional) You may enable debugging (HS_DEBUG) if you want to find why it is not working...
  In that case, you can set HS_REDIR_TIMEOUT to 10 or 30 seconds in order to let you analyse the problem.

1.3) (Optional) Securing login script
-------------------------------------
Change the ownner of PHP scripts:
  cd /usr/local/apache2/htdocs/
  egrep 'User|Group' ../conf/httpd.conf
  ...
  User daemon
  Group daemon
  ...
  chmod 644 hsl*
  chown daemon:daemon hsl*
  chmod 644 welcome*
  chown daemon:daemon welcome*

1.4) Update /etc/pepper.conf
----------------------------
There are only a few directives to check.
Here are the default values:
  uamserver https://192.168.182.1/hsl.php
  uamserver6 https://[2001:db8:1::1234]/hsl.php
  uamsecret testing234

If you want to use CAS, you must be sure that your UAM web server supports SSL (needed for CAS-proxy - see 4.2) and that the certificate you're using has a subjectAltName directive set with either IP:192.168.182.1 or IP:2001:db8:1::1234 or both to prevent users to see a security exception in their navigators (See 3.2.2-5).

Then you have to add the name of your CAS server to the list of allowed address:
uamallowed cas.pepperspot.info

If you want to introduce PepperSpot's captive portal to your users, you may activate uamhomepage with one of those lines:
    uamhomepage http://192.168.182.1/welcome.php
  or
    uamhomepage http://[2001:db8:1::1234]/welcome.php
If you use this directive with your own values, check welcome.php to see if you need to update UAM_PORT, UAM_HOST and UAM6_HOST.

That's all normally !!


+++++++++++++++++++
3) Installing CAS +
+++++++++++++++++++

3.1) CAS server
---------------
The easiest way to install a CAS server is to use CAS-toolbox/CAS-quickstart.
CAS-quickstart is a pre-configured bundle of all what's needed to have a CAS server (e.g. Apache TOMCAT + CAS web service).
CAS-toolbox is a set of tools that can be used to modify CAS authentication system and/or visual interface.

The only requirement is to have JAVA language installed on the system (e.g. Java Developpement Kit (JDK) - http://java.sun.com/javase/downloads/)
If you want to enhance security, you also need a certificate to enable HTTPS on Apache TOMCAT (see step 3.2).
If you want to use CAS-toolbox, you'll also need Apache ANT (http://ant.apache.org/).
For more informations, please refer to :
    http://sourcesup.cru.fr/projects/cas-toolbox/
    http://www.ja-sig.org/wiki/display/CAS/CAS-toolbox

In this document, i will only present the use of CAS-quickstart:

1-Download CAS-quickstart from http://sourcesup.cru.fr/frs/?group_id=401
  cd /usr/local
  tar xvf ~/cas-quickstart-x.y.z.tar.gz
  cd cas-quickstart-x.y.z

2-Set global variables:
  If JAVA_HOME does not exist on your system, you may set its value in env.sh:
    export JAVA_HOME=/usr/lib/java
  Normally you do not have to modify the other values.

3-(Optional) Check env.sh, start.sh and stop.sh file format
  Some old versions of CAS-quickstart won't work directly because of a wrong file format (See : file *.sh).
  You'll have to convert those file to UNIX's like file format (i.e. only LF at the end of a line, no CRLF).
  You may use one of those commands : fromdos, dos2unix or tr
  Here is an example for env.sh :
    fromdos < env.sh > env ; mv env env.sh
  or
    cat env.sh | tr -d '\015' > env ; mv env env.sh

4-Enable execution right:
  chmod a+x *.sh
  chmod a+x apache-tomcat-*/bin/*.sh

5-(Optional)Secure Tomcat server
  By default, only HTTP (port 8080) is enable on Tomcat server in CAS-quickstart.
  See step 3.2, if you want to enable HTTPS.

6-Start Tomcat
  cd /usr/local/cas-quickstart-x.y.z
  ./start.sh

7-(Optional)Check if it is running
  In the default configuration (not secured), you'll see:
    netstat -nltp
    ...
    tcp6 0 0 127.0.0.1:8005 :::* LISTEN 3629/java
    tcp6 0 0 :::8080 :::* LISTEN 3629/java
    ...

  If AJP is enabled (default), you'll see:
    tcp6 0 0 127.0.0.1:8009 :::* LISTEN 3629/java

  If SSL is enabled, you'll see:
    tcp6 0 0 :::8443 :::* LISTEN 3629/java

8-Navigate to Tomcat web URL
  By default : http://localhost:8080/
  If SSL is enabled : https://cas.pepperspot.info:8443/ (use offical DNS name associate to certificate CN to avoid security exception, see 3.2)
  If it not working got to 10.

9-Try to login:
  By default a simple authentication system is enabled.
  You have to enter the same value for the userID and the password.

10-(Optional)Check log files if there is an error:
  You may use cat, less, tail, ... to see what happened in apache-tomcat-*/logs/catalina.out

3.2) Securing CAS server
------------------------
There are many ways to secure Tomcat:
  *Enable SSL/TLS
    *Use a JAVA keystore (step 3.2.1)
    *Use Tomcat native library and APR (Apache Portable Runtime) with a common certificate and private key. (better solution, step 3.2.2)
  *Use AJP protocol on local loopback interface and link Tomcat with mod_jk on Apache+SSL FrontEnd (for experienced users)

I will only explain how to enable SSL on Tomcat in this document.
If you want to use of AJP, please refer to Tomcat's documentation (http://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html).

3.2.1) SSL with a JAVA keystore
-------------------------------
1-You have to use keytool to generate a keystore:
  cd /usr/local/cas-quickstart-*/apache-tomcat-*/conf
  keytool -genkey -alias tomcat -dname "CN=cas.pepperspot.info, O=PepperSpot" \
    -validity 3600 -keyalg RSA -keysize 1024 \
    -keypass changeit -keystore keystore -storepass changeit

2-(Optional) This generates a self-signed certificate.
  If you wich to use only one CA in your architecture, you may generate a certificate request (CSR), send it to your CA (or see 3.2.2-3), then import certificate signed by CA. See keytool --help for more informations.

3-Then update <Tomcat>/conf/server.xml:
  <!--Connector port="8443" protocol="HTTP/1.1"
          maxThreads="150" acceptCount="100"
          enableLookups="false" disableUploadTimeout="true"
          SSLEnabled="true" sslProtocol="TLS"
          scheme="https" secure="true"
          clientAuth="false"
          keystoreFile="conf/keystore" keystorePass="changeit"
          keyAlias="tomcat" keypass="changeit" /-->

4-(Optional) The address field may be used to specify witch interface to listen to:
  address="127.0.0.1" : for local loopback IPv4 interface
  address="0.0.0.0" : for all IPv4 interfaces
  address="::" : for all IPv6 interfaces
  no address field specified: for any interfaces

5-Go to 3.1-6

3.2.2) SSL with APR and Tomcat native library
---------------------------------------------
1-In this case, you need to create Tomcat native library witch requires APR (Apache Portable Runtime).
  Here, we suppose that APR is located in /usr/local/apr. Adapt this value for your system.
    cd /usr/local/src
    tar xvf cas-quickstart-*/apache-tomcat-*/bin/tomcat-native.tar.gz
    cd tomcat-native-*-src/jni/native
    ./configure --with-apr=/usr/local/apr
    make
    make install

2-Next step, you have to link the library in the JAVA lib directory. Enter something like:
  ln -s /usr/local/apr/lib/libtcnative-1.so $JAVA_HOME/jre/lib/i386/

3-(Optional) Generate a CA
  cd /usr/local/cas-quickstart-*/apache-tomcat-*/conf
  openssl genrsa -des3 -out ca.key 1024
  openssl req -new -x509 -key ca.key -days 3650 \
    -subj "/O=PepperSpot/CN=CA/" -out ca.crt

4-Generate key and CSR
  cd /usr/local/cas-quickstart-*/apache-tomcat-*/conf
  openssl req -newkey rsa:1024 -nodes \
    -subj "/O=PepperSpot/CN=cas.pepperspot.info/" \
    -keyout server.key -out server.csr

5-(Optional) Sign CSR directly if you've generate by yourself the CA (step 3.2.2-3).
  Edit a minimum config file for openssl:
    cat << EOF > config.cnf
    [ ca ]
    default_ca       = CA_default
    ####################################################################
    [ CA_default ]
    default_days     = 3650
    new_certs_dir    = .
    certificate      = ca.crt
    private_key      = ca.key
    database         = dbFile
    serial           = serialFile
    default_md       = sha1
    policy           = policy_match
    x509_extensions  = SERVER_SSL
    [ SERVER_SSL ]
    basicConstraints       = critical,CA:FALSE
    keyUsage               = digitalSignature,nonRepudiation,keyEncipherment
    extendedKeyUsage       = serverAuth
    subjectAltName         = DNS:cas.pepperspot.info,IP:192.168.182.1,IP:2001:db8:1::1234
    [ policy_match ]
    organizationName       = match
    commonName             = supplied
    emailAddress           = optional
    EOF
    echo -n >dbFile
    openssl rand -hex 16 >serialFile
    openssl ca -batch -notext -config config.cnf -out server.crt -infiles server.csr

6-(Optional) If you've skipped previous section, send your CSR file to your CA, and wait for your certificate

7-At this point, you should have 2 certificates and 1 key in your Tomcat's conf directory:
  *CA certificate (ca.crt)
  *Server certificate (server.crt)
  *Server private key (server.key)

8-Then update <Tomcat>/conf/server.xml:
  <!-- with TC native library (APR) -->
  <Connector port="8443" protocol="HTTP/1.1"
          maxThreads="150" acceptCount="100"
          enableLookups="false" disableUploadTimeout="true"
          SSLEnabled="true" sslProtocol="TLS"
          scheme="https" secure="true"
          SSLCipherSuite="ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP:+eNULL"
          SSLVerifyClient="none" SSLVerifyDepth="10"
          SSLCACertificateFile="${catalina.base}/conf/ca.crt"
          SSLCertificateFile="${catalina.base}/conf/server.crt"
          SSLCertificateKeyFile="${catalina.base}/conf/server.key" />

9-Go to 3.1-6


++++++++++++++++++++++++++++++++++++++
4) Add PHP support on UAM web server +
++++++++++++++++++++++++++++++++++++++

4.1) Install PHP
----------------
In general, you simply have to use a pre-build PHP packet (see apt-get, yum, slackpkg, ...).
If there is no packets for PHP in your LINUX distribution, you may try to install PHP from the sources (http://www.php.net/) and follow the installation procedure.

If your web server is Apache, you should have something like that in httpd.conf or mod_php.conf:
  LoadModule php5_module lib/http/modules/libphp5.so
  AddType application/x-httpd-php .php

4.2) Enable SSL on UAM web server to allow CAS-proxying
-------------------------------------------------------
1-You may use the same key and certificate created in 3.2.2 if your computer act as CAS server and UAM web server.
In the other cases, you have to create a new key an certificate for your UAM web server (see 3.2.2-4).

2-Copy key and crt files to Apache's configuration directory

3-Enable SSL in httpd.conf:
  In general, uncomment those lines:
    ...
    LoadModule ssl_module modules/mod_ssl.so
    ...
    Include conf/extra/httpd-ssl.conf
    ...

4-Edit conf/extra/httpd-ssl.conf and set the directives below with the correct value:
  ...
  SSLCertificateFile conf/server.crt
  SSLCertificateKeyFile conf/server.key
  SSLCACertificateFile conf/ca.crt
  ...

5-Restart httpd and verify listening ports:
  apachectl -k restart
  netstat -nltp
    ...
    tcp6 0 0 :::80 :::* LISTEN 1578/httpd
    tcp6 0 0 :::443 :::* LISTEN 1578/httpd
    ...


+++++++++++++++++++++++++++++++++++
5) Install PHP CAS client library +
+++++++++++++++++++++++++++++++++++

1-All the installation procedure is explained here:
  http://www.ja-sig.org/wiki/display/CASC/phpCAS
  http://www.ja-sig.org/wiki/display/CASC/phpCAS+installation+guide

2-You may test your installation with casClient.php.

3-You have to install your CA certificate in JAVA's cacerts file to enable CAS-proxying:
  JAVA_STORE=$JAVA_HOME/jre/lib/security/cacerts
  keytool -import -alias ca -keystore $JAVA_STORE -storepass changeit -trustcacerts -file ca.crt

4-You may test your installation with casProxy.php.


+++++++++++++++++++++++++++++++++
6) Installing RADIUS CAS module +
+++++++++++++++++++++++++++++++++

6.1) Installing Free-RADIUS server
----------------------------------
The RADIUS CAS module (rlm_cas) is only available for Free-RADIUS server.
  1-A typical installation is something like:
    cd /usr/local/src
    tar xvf ~/freeradius-server-*.tar.bz2
    cd freeradius-server-*
    ./configure
    make
    make install

  2-Then you have to copy rlm_cas source files to the modules directory:
    tar xvf ../pepperspot*/contrib/rlm_cas.tar.gz -C src/modules
    make -C src/modules/rlm_cas
    make -C src/modules/rlm_cas install

6.2) RADIUS CAS configuration
-----------------------------
The CAS module configuration is detailled in src/modules/rlm_cas/README file.

Enjoy !

2010 Christophe BORELLY - IUT de Béziers (France)
