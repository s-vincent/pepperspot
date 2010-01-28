<?php
define('LF',"\n");
define('CAS_LIB_DIR','CAS-1.0.1');
define('CAS_SERVER','cas.pepperspot.info');
define('CAS_PORT',8443);
define('CAS_URL','');
//define('CAS_CACERT','/usr/local/apache2/conf/ca.crt');

include_once(CAS_LIB_DIR.'/CAS.php');
phpCAS::client(CAS_VERSION_2_0,CAS_SERVER,CAS_PORT,CAS_URL);
if (defined('CAS_CACERT')) phpCAS::setCasServerCACert(CAS_CACERT);
else phpCAS::setNoCasServerValidation();
phpCAS::forceAuthentication();
echo '<h1>Authentication ok on '.$_SERVER['HTTP_HOST'].' (client CAS) !</h1>'.LF;
echo '<h2>User : '.phpCAS::getUser().'</h2>'.LF;
?>
