<?php
###############################################################################
# Messages translations
define('HS_NAME','PepperSpot');

$WELCOME_TITLE='Welcome on '.HS_NAME;
$WELCOME_HDR=HS_NAME.'\'s captive portal';
$WELCOME_MSG='You need to login before';
$WELCOME_MSG.=' you can access to the Internet...<br/>'.LF;
$URL='http://'.UAM_HOST.':'.UAM_PORT.'/prelogin';
$WELCOME_MSG.='<a href="'.$URL.'"';
$WELCOME_MSG.=' title="Login with IPv4">';
$WELCOME_MSG.='Click here to <b>login</b> with IPv4</a>'.LF;

$WELCOME_MSG.='<br/>'.LF;
$URL='http://'.UAM6_HOST.':'.UAM_PORT.'/prelogin';
$WELCOME_MSG.='<a href="'.$URL.'"';
$WELCOME_MSG.=' title="Login with IPv6">';
$WELCOME_MSG.='Click here to <b>login</b> with IPv6</a>'.LF;

/*$WELCOME_MSG.='<br/>'.LF;
$URL='http://'.UAM_HOST.':'.UAM_PORT.'/logout';
$WELCOME_MSG.='<a href="'.$URL.'"';
$WELCOME_MSG.=' title="Logout with IPv4">';
$WELCOME_MSG.='Click here to <b>logout</b> with IPv4</a>'.LF;

$WELCOME_MSG.='<br/>'.LF;
$URL='http://'.UAM6_HOST.':'.UAM_PORT.'/logout';
$WELCOME_MSG.='<a href="'.$URL.'"';
$WELCOME_MSG.=' title="Logout with IPv6">';
$WELCOME_MSG.='Click here to <b>logout</b> with IPv6</a>'.LF;*/
?>
