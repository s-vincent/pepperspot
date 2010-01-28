<?php
# pepper - PepperSpot.info. A Wireless LAN Access Point Controller
# Copyright (C) 2006, 2009 Christophe BORELLY - IUT de Beziers (France)
#
# Example of welcome page of the captive portal
# See TAG uamhomepage in pepper.conf
###############################################################################
define('HS_DEBUG',false);
# Set HS_LANG (lower case) for messages translations
# See welcome-msg-*.php files
define('HS_LANG','en');
// Default values :
//    Port : 3990
//    IPv4 : 192.168.182.1 (First IP of net directive)
//    IPv6 : 2001:db8:1::1234 (staticipv6 directive)
// Or if defined : uamport, uamlisten values of pepper.conf
define('UAM_PORT','3990');
define('UAM_HOST','192.168.182.1');
define('UAM6_HOST','[2001:db8:1::1234]');
###############################################################################
# Constants
define('LF',"\n");
###############################################################################
# Style
$style='text-align:center;background-color:#FAD155;';
$contentType='text/html;charset=ISO-8859-1';
###############################################################################
# Variables
// Detects if current WEB server is IPv6 or not : to be used in the future ?
$HOST_IS_IPv6=preg_match('/^\[[^\[]+\]/',$_SERVER['HTTP_HOST']);
###############################################################################
# Messages translations
include_once('welcome-msg-'.HS_LANG.'.php');
###############################################################################
# HTML
header('Content-type: '.$contentType);
echo '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">'.LF;
echo '<html>'.LF;
echo '<head>'.LF;
echo '  <title>'.$WELCOME_TITLE.'</title>'.LF;
echo '  <meta http-equiv="Content-type" content="'.$contentType.'">'.LF;
echo '  <meta http-equiv="Cache-control" content="no-cache">'.LF;
echo '  <meta http-equiv="Pragma" content="no-cache">'.LF;
echo '</head>'.LF;
echo '<body style="'.$style.'">'.LF;
echo '  <h1 style="text-align:center;margin:auto;">'.$WELCOME_HDR.'</h1>'.LF;
echo '  <p style="text-align:center;">'.$WELCOME_MSG.'</p>'.LF;

if (HS_DEBUG)
{
	echo '<h2>$_SERVER :</h2>'.LF;
	echo '<pre style="background-color:silver;text-align:left;">'.LF;
	foreach ($_SERVER AS $key=>$val)
	{
	  printf('%25s=<b>%s</b>'.LF,$key,$val);
	}
	echo '</pre>'.LF;
}

echo '</body>'.LF;
echo '</html>'.LF;
exit(0);
?>
