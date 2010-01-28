<?php
# pepper - PepperSpot.info. A Wireless LAN Access Point Controller
###############################################################################
# Messages translations
define('HS_NAME','PepperSpot'.(($HOST_IS_IPv6)?' (IPv6)':' (IPv4)'));

# Text displayed on submit button
define('HS_CONNECT','Connexion');

define('CAS_CONFIG_ERROR','Erreur de configuration CAS !!!');
$tmp='Pour activer l\'authentification CAS';
$tmp.=' (http://www.jasig.org/cas), il faut :';
define('CAS_CONFIG_ERROR_TEXT',$tmp);
$tmp='USE_CAS=true ['.(USE_CAS?'true':'false').']';
define('CAS_CONFIG_ERROR_MSG1',$tmp);
$tmp='Donner une valeur � HS_UAMSECRET ['.@constant('HS_UAMSECRET').']';
define('CAS_CONFIG_ERROR_MSG2',$tmp);
define('CAS_READONLY_TITLE','Autoriser les modifications');
define('CAS_READONLY_MSG',''); // Text following the checkbox
define('CAS_FOOTER_TITLE','Utilisateur CAS :');
$tmp='Cliquez ici pour vous d�connecter compl�tement de CAS';
define('CAS_FOOTER_LINK_TITLE',$tmp);
define('CAS_FOOTER_LINK_MSG','D�connexion de CAS');
define('CAS_FOOTER_MSG','Vous n\'�tes pas encore authentifi� !!!');

$TITLE_CNX_START='Connexion en cours sur '.HS_NAME;
$MSG_CNX_START='Merci de patienter';
if (HS_REDIR_TIMEOUT>0) $MSG_CNX_START.=' '.HS_REDIR_TIMEOUT.' secondes';
$MSG_CNX_START.=' avant la redirection...';

$TITLE_DEFAULT='Identification incorrecte !!!';
$MSG_DEFAULT='Vous devez vous identifier par l\'interm�diaire du d�mon pepper';
$MSG_DEFAULT.='Spot !!!<br/>Fermez votre navigateur et essayez � nouveau.';

$TITLE_SUCCESS='Vous �tes connect� sur '.HS_NAME;
$MSG_SUCCESS='Bienvenue sur '.HS_NAME.'.<br/>';
$MSG_SUCCESS.='<a href="'.$baseURL.'/logoff" title="D�connexion">';
$MSG_SUCCESS.='Cliquez ici pour vous <b>d�connecter</b></a>.';

$TITLE_FAILED='Identification incorrecte sur '.HS_NAME.' !!!';
$MSG_FAILED='Essayez � nouveau...';

$TITLE_LOGOFF='D�connexion de '.HS_NAME;
$MSG_LOGOFF='Vous avez bien �t� d�connect� de '.HS_NAME.'.<br/>';
$MSG_LOGOFF.='<a href="'.$baseURL.'/prelogin" title="Reconnexion">';
$MSG_LOGOFF.='Cliquez ici pour vous <b>reconnecter</b></a>.';

$TITLE_ALREADY='Vous �tes d�j� connect� sur '.HS_NAME;
$MSG_ALREADY='<a href="'.$baseURL.'/logoff" title="D�connexion">';
$MSG_ALREADY.='Cliquez ici pour vous <b>d�connecter</b></a>.';

$TITLE_NOTYET='Connexion sur '.HS_NAME;
$MSG_NOTYET='Entrez vos identifiants pour la connexion � '.HS_NAME.'...';

$TITLE_POPUP1='Connexion en cours sur '.HS_NAME;
$MSG_POPUP1=$MSG_CNX_START;
 
$TITLE_POPUP2='Vous �tes connect� sur '.HS_NAME;
$MSG_POPUP2='<a href="javascript:opener.location=\''.$baseURL.'/logoff\';';
$MSG_POPUP2.='self.close();" title="D�connexion">';
$MSG_POPUP2.='Cliquez ici pour vous <b>d�connecter</b></a>.';

$TITLE_POPUP3='Vous avez �t� d�connect� de '.HS_NAME;
$MSG_POPUP3='<a href="javascript:opener.location=\''.$baseURL.'/prelogin\';';
$MSG_POPUP3.='self.close();" title="Reconnexion">';
$MSG_POPUP3.='Cliquez ici pour vous <b>reconnecter</b></a>.';

if (defined('HS_HTTPS_TIMEOUT'))
{
	$TITLE_NO_HTTPS='Connexion incorrecte sur '.HS_NAME.' !!!';
	$MSG_NO_HTTPS='Vous devez utiliser une connexion s�curis�e (HTTPS) !!!';
	$MSG_NO_HTTPS.='<br/>Vous allez �tre redirig� dans '.HS_HTTPS_TIMEOUT;
	$MSG_NO_HTTPS.=' secondes sur le <a href="'.$secureURL.'"';
	$MSG_NO_HTTPS.=' title="Connexion au site s�curis�">site s�curis�</a>...';
}
?>
