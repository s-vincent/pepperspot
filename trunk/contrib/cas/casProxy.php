<?php
define('LF',"\n");
define('CAS_LIB_DIR','CAS-1.0.1');
define('CAS_SERVER','cas.pepperspot.info');
define('CAS_PORT',8443);
define('CAS_URL','');
//define('CAS_CACERT','/usr/local/apache2/conf/ca.crt');
# Must be set on Windows Systems
define('CAS_PGT_STORAGE','C:/Tmp');

include_once(CAS_LIB_DIR.'/CAS.php');
// phpCAS logs in /tmp/phpCAS.log
phpCAS::setDebug();
phpCAS::proxy(CAS_VERSION_2_0,CAS_SERVER,CAS_PORT,CAS_URL);
if (defined('CAS_CACERT')) phpCAS::setCasServerCACert(CAS_CACERT);
else phpCAS::setNoCasServerValidation();
if (isset($_SERVER['WINDIR'])) phpCAS::setPGTStorageFile('',CAS_PGT_STORAGE);
phpCAS::forceAuthentication();

echo '<h1 >Authentication ok on '.$_SERVER['HTTP_HOST'].' (proxy CAS) !</h1>'.LF;
echo '<h2 >User : '.phpCAS::getUser().'</h2>'.LF;

$service='http://'.$_SERVER['HTTP_HOST'].'/casClient.php';
// Call service
if (phpCAS::serviceWeb($service,$err_code,$output))
{
   echo '<font style="color:green;">';
}
else
{
   echo '<font style="color:red;">';
}
echo $output;
echo '</font>';
echo '<p>'.LF;
echo 'getURL : <b>'.$PHPCAS_CLIENT->getURL().'</b>.<br/>'.LF;
echo 'getST : <b>'.$PHPCAS_CLIENT->getST().'</b>.<br/>'.LF;
echo 'getPT : <b>'.$PHPCAS_CLIENT->getPT().'</b>.<br/>'.LF;
echo 'getPGT : <b>'.$PHPCAS_CLIENT->getPGT().'</b>.<br/>'.LF;
echo '</p>'.LF;
?>
