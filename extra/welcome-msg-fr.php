<?php
###############################################################################
# Messages translations
define('HS_NAME','PepperSpot');

$WELCOME_TITLE='Bienvenue sur '.HS_NAME;
$WELCOME_HDR='Portail captif '.HS_NAME;
$WELCOME_MSG='Vous devez vous identifier';
$WELCOME_MSG.=' avant de pouvoir acc�der � Internet...<br/>'.LF;
$URL='http://'.UAM_HOST.':'.UAM_PORT.'/prelogin';
$WELCOME_MSG.='<a href="'.$URL.'"';
$WELCOME_MSG.=' title="Identification sur le portail captif en IPv4">';
$WELCOME_MSG.='Cliquez ici pour vous <b>identifier</b> en IPv4</a>'.LF;

$WELCOME_MSG.='<br/>'.LF;
$URL='http://'.UAM6_HOST.':'.UAM_PORT.'/prelogin';
$WELCOME_MSG.='<a href="'.$URL.'"';
$WELCOME_MSG.=' title="Identification sur le portail captif en IPv6">';
$WELCOME_MSG.='Cliquez ici pour vous <b>identifier</b> en IPv6</a>'.LF;

/*$WELCOME_MSG.='<br/>'.LF;
$URL='http://'.UAM_HOST.':'.UAM_PORT.'/logout';
$WELCOME_MSG.='<a href="'.$URL.'"';
$WELCOME_MSG.=' title="D�connexion du portail captif IPv4">';
$WELCOME_MSG.='Cliquez ici pour vous <b>d�connecter</b> en IPv4</a>'.LF;

$WELCOME_MSG.='<br/>'.LF;
$URL='http://'.UAM6_HOST.':'.UAM_PORT.'/logout';
$WELCOME_MSG.='<a href="'.$URL.'"';
$WELCOME_MSG.=' title="D�connexion du portail captif en IPv6">';
$WELCOME_MSG.='Cliquez ici pour vous <b>d�connecter</b> en IPv6</a>'.LF;*/
?>
