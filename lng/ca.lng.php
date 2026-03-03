<?php

/**
 * This file is part of the froxlor project.
 * Copyright (c) 2010 the froxlor Team (see authors).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, you can also view it online at
 * https://files.froxlor.org/misc/COPYING.txt
 *
 * @copyright  the authors
 * @author     froxlor team <team@froxlor.org>
 * @license    https://files.froxlor.org/misc/COPYING.txt GPLv2
 */

return [
	'languages' => [
		'cz' => 'Txec',
		'de' => 'Alemany',
		'en' => 'Angles',
		'fr' => 'Frances',
		'it' => 'Italia',
		'nl' => 'Holandes',
		'pt' => 'Portugues',
		'se' => 'Suec',
		'es' => 'Espanyol',
		'ca' => 'Catala',
		'zh_CN' => 'Xines (Simplificat)',
	],
	'2fa' => [
		'2fa' => 'Opcions 2FA',
		'2fa_enabled' => 'Activar l\'autenticació de dos factors (2FA)',
		'2fa_removed' => '2FA eliminat correctament',
		'2fa_added' => '2FA activat correctament<br /><a class="alert-link" href="%s?page=2fa">Veure detalls de 2FA</a>',
		'2fa_add' => 'Activar 2FA',
		'2fa_delete' => 'Desactivar 2FA',
		'2fa_verify' => 'Verificar codi',
		'2fa_overview_desc' => 'Aquí podeu activar una autenticació de dos factors per al vostre compte.<br/><br/>Podeu utilitzar una aplicació d\'autenticació (contrasenya d\'un sol ús basada en el temps / TOTP) o deixar que froxlor us enviï un correu electrònic a l\'adreça del vostre compte després de cada inici de sessió correcte amb una contrasenya d\'un sol ús.',
		'2fa_email_desc' => 'El vostre compte està configurat per utilitzar contrasenyes d\'un sol ús per a cada correu electrònic. Per desactivar-la, feu clic a "Desactivar 2FA".',
		'2fa_ga_desc' => 'El vostre compte està configurat per utilitzar contrasenyes d\'un sol ús basades en el temps mitjançant una aplicació d\'autenticació. Escanegeu el codi QR que apareix a continuació amb l\'aplicació d\'autenticació que vulgueu per generar els codis. Per desactivar, feu clic a "Desactivar 2FA".'
	],
	'admin' => [
		'overview' => 'Visió general',
		'ressourcedetails' => 'Recursos utilitzats',
		'systemdetails' => 'Detalls del sistema',
		'froxlordetails' => 'Detalls de froxlor',
		'installedversion' => 'Versió instal·lada',
		'latestversion' => 'Última versió',
		'lookfornewversion' => [
			'clickhere' => 'Cerca mitjançant el servei web',
			'error' => 'Error de lectura'
		],
		'resources' => 'Recursos',
		'customer' => 'Client',
		'customers' => 'Clients',
		'customers_list_desc' => 'Gestioni els seus clients',
		'customer_add' => 'Crear client',
		'customer_edit' => 'Editar client',
		'username_default_msg' => 'Deixar buit per al valor autogenerat',
		'domains' => 'Dominis',
		'domain_add' => 'Crear domini',
		'domain_edit' => 'Editar domini',
		'subdomainforemail' => 'Subdominis com dominis de correu electrònic',
		'admin' => 'Administrador',
		'admins' => 'Administradors',
		'admin_add' => 'Crear administrador',
		'admin_edit' => 'Editar administrador',
		'customers_see_all' => 'Pot accedir als recursos d\'altres administradors/revenedors?',
		'change_serversettings' => 'Pot canviar la configuració del servidor?',
		'server' => 'Sistema',
		'serversettings' => 'Ajustos',
		'serversettings_desc' => 'Administrar el sistema froxlor',
		'rebuildconf' => 'Reconstruir arxius de configuració',
		'stdsubdomain' => 'Subdomini estàndard',
		'stdsubdomain_add' => 'Crear subdomini estàndard',
		'phpenabled' => 'PHP habilitat',
		'deactivated' => 'Desactivat',
		'deactivated_user' => 'Desactivar usuari',
		'sendpassword' => 'Enviar contrasenya',
		'ownvhostsettings' => 'Configuració vHost pròpia',
		'configfiles' => [
			'serverconfiguration' => 'Configuració',
			'overview' => 'Visió general',
			'wizard' => 'Assistent',
			'distribution' => 'Distribució',
			'service' => 'Servei',
			'daemon' => 'Dimoni',
			'http' => 'Servidor web (HTTP)',
			'dns' => 'Servidor de noms (DNS)',
			'mail' => 'Servidor de correu (IMAP/POP3)',
			'smtp' => 'Servidor de correu (SMTP)',
			'ftp' => 'Servidor FTP',
			'etc' => 'Altres (Sistema)',
			'choosedistribution' => '-- Esculli una distribució --',
			'chooseservice' => '-- Esculli un servei --',
			'choosedaemon' => '-- Esculli un dimoni --',
			'statistics' => 'Estadístiques',
			'compactoverview' => 'Vista general compacta',
			'legend' => '<h3>Està a punt de configurar un servei/dimoni</h3>',
			'commands' => '<span class="text-danger">Ordres:</span> Aquestes ordres han de ser executades línia per línia com a usuari root en una shell. És segur copiar tot el bloc i enganxar-lo a l\'intèrpret d\'ordres.',
			'files' => '<span class="text-danger">Fitxers de configuració:</span> Les ordres abans dels camps de text han d\'obrir un editor amb el fitxer de destí. Només has de copiar i enganxar el contingut a l\'editor i desar el fitxer.<br /><span class="text-danger">Nota:</span> La contrasenya MySQL no ha estat reemplaçada per raons de seguretat. Si us plau, reemplaça "FROXLOR_MYSQL_PASSWORD" pel teu compte o fes servir el formulari javascript de sota per reemplaçar-la in situ. Si has oblidat la teva contrasenya MySQL la trobaràs a "lib/userdata.inc.php".',
			'importexport' => 'Importar/Exportar',
			'finishnote' => 'Fitxer de paràmetres generat correctament. Ara executeu la següent ordre com a root:',
			'description' => 'Configurar els serveis del sistema',
			'minihowto' => 'En aquesta pàgina podeu veure les diferents plantilles de configuració per a cada servei, (re)configurar serveis específics si cal o exportar la selecció actual a un fitxer JSON per utilitzar-lo als scripts CLI o en un altre servidor.<br/><br/><b>Tingui en compte</b> que els serveis ressaltats no reflecteixen la configuració actual, sinó que mostren requisits/recomanacions dels seus valors de configuració actuals.',
			'skipconfig' => 'No (re)configurar',
			'recommendednote' => 'Serveis recomanats/requerits segons la configuració actual del sistema',
			'selectrecommended' => 'Seleccionar recomanats',
			'downloadselected' => 'Exportar seleccionat'
		],
		'templates' => [
			'templates' => 'Plantilles de correu electrònic',
			'template_add' => 'Afegir plantilla',
			'template_fileadd' => 'Afegir plantilla de fitxer',
			'template_edit' => 'Editar plantilla',
			'action' => 'Acció',
			'email' => 'Plantilles de correu electrònic i fitxers',
			'subject' => 'Assumpte',
			'mailbody' => 'Cos del correu',
			'createcustomer' => 'Correu de benvinguda per a nous clients',
			'pop_success' => 'Correu de benvinguda per a nous comptes de correu electrònic',
			'template_replace_vars' => 'Variables a substituir a la plantilla:',
			'SALUTATION' => 'Substituït per una correcta salutació (nom o empresa)',
			'FIRSTNAME' => 'Substituït pel nom del client.',
			'NAME' => 'Substituït pel nom complet del client.',
			'COMPANY' => 'Substituït pel nom de l\'empresa del client.',
			'USERNAME' => 'Substituït pel nom d\'usuari del compte del client.',
			'PASSWORD' => 'Substituït per la contrasenya del compte del client.',
			'EMAIL' => 'Substituït per l\'adreça de correu electrònic del compte POP3/IMAP.',
			'CUSTOMER_NO' => 'Substituït pel número de client.',
			'TRAFFIC' => 'Substituït pel trànsit assignat al client.',
			'TRAFFICUSED' => 'Substituït pel trànsit, que ha sigut esgotat pel client.',
			'pop_success_alternative' => 'Correu de benvinguda per a nous comptes de correu electrònic enviats a l\'adreça alternativa.',
			'EMAIL_PASSWORD' => 'Substituït per la contrasenya del compte POP3/IMAP.',
			'index_html' => 'Arxiu d\'índex per a directoris de clients acabats de crear',
			'SERVERNAME' => 'Substituït pel nom del servidor.',
			'CUSTOMER' => 'Substituït pel nom d\'usuari del client.',
			'ADMIN' => 'Substituït pel nom d\'usuari de l\'administrador.',
			'CUSTOMER_EMAIL' => 'Substituït per l\'adreça de correu electrònic del client.',
			'ADMIN_EMAIL' => 'Substituït per l\'adreça de correu electrònic de l\'administrador.',
			'filetemplates' => 'Plantilles de fitxers',
			'filecontent' => 'Contingut del fitxer',
			'new_database_by_customer' => 'Notificació al client de la creació d\'una base de dades',
			'new_ftpaccount_by_customer' => 'Notificació al client de la creació d\'un usuari ftp',
			'newdatabase' => 'Correus de notificació per a noves bases de dades',
			'newftpuser' => 'Correus de notificació per a nous usuaris ftp',
			'CUST_NAME' => 'Nom del client',
			'DB_NAME' => 'Nom de la base de dades',
			'DB_PASS' => 'Contrasenya de la base de dades',
			'DB_DESC' => 'Descripció de la base de dades',
			'DB_SRV' => 'Servidor de base de dades',
			'PMA_URI' => 'URL de phpMyAdmin (si s\'indica)',
			'USR_NAME' => 'Nom d\'usuari FTP',
			'USR_PASS' => 'Contrasenya FTP',
			'USR_PATH' => 'Directori HOME de l\'FTP (relatiu a customer-docroot)',
			'forgotpwd' => 'Correus de notificació de restabliment de contrasenya',
			'password_reset' => 'Notificació al client de restabliment de contrasenya',
			'trafficmaxpercent' => 'Correu de notificació per als clients quan s\'esgota un determinat percentatge màxim de trànsit',
			'MAX_PERCENT' => 'Substituït pel límit de l\'ús del disc/trànsit per a l\'enviament d\'informes en percentatge.',
			'USAGE_PERCENT' => 'Substituït amb l\'ús del disc/trànsit esgotat pel client en percentatge.',
			'diskmaxpercent' => 'Correu de notificació als clients quan s\'esgota el percentatge màxim d\'espai al disc.',
			'DISKAVAILABLE' => 'Substituït per l\'ús de disc assignat al client.',
			'DISKUSED' => 'Substituït per l\'ús de disc, que ha sigut esgotat pel client.',
			'LINK' => 'Substituït per l\'enllaç de restabliment de contrasenya del client.',
			'SERVER_HOSTNAME' => 'Reemplaça el nom del sistema (URL a froxlor)',
			'SERVER_IP' => 'Reemplaça l\'adreça IP per defecte del servidor ',
			'SERVER_PORT' => 'Reemplaça el port per defecte del servidor',
			'DOMAINNAME' => 'Reemplaça el subdomini estàndard del client (pot estar buit si no se\'n genera cap)'
		],
		'webserver' => 'Servidor web',
		'createzonefile' => 'Crear zona dns pel domini',
		'custombindzone' => 'Arxiu de zona personalitzatada / no gestionada',
		'bindzonewarning' => 'buit per defecte<br /><strong class="text-danger">ATENCIÓ:</strong> Si utilitza un fitxer de zones, haurà de gestionar també manualment tots els registres necessaris per a totes les subzones.',
		'ipsandports' => [
			'ipsandports' => 'IPs i Ports',
			'add' => 'Afegir IP/Port',
			'edit' => 'Editar IP/Port',
			'ipandport' => 'IP/Port',
			'ip' => 'IP',
			'ipnote' => '<div id="ipnote" class="invalid-feedback">Nota: Tot i que les adreces IP privades estan permeses, algunes característiques com DNS podrien no comportar-se correctament.<br />Només utilitzi adreces IP privades si està segur.</div>',
			'port' => 'Port',
			'create_listen_statement' => 'Crear sentència Listen',
			'create_namevirtualhost_statement' => 'Crear sentència NameVirtualHost',
			'create_vhostcontainer' => 'Crear vHost-Container',
			'create_vhostcontainer_servername_statement' => 'Crear sentència ServerName a vHost-Container',
			'enable_ssl' => 'Es tracta d\'un port SSL?',
			'ssl_cert_file' => 'Ruta del certificat SSL',
			'webserverdefaultconfig' => 'Configuració per defecte del servidor web',
			'webserverdomainconfig' => 'Configuració de domini del servidor web',
			'webserverssldomainconfig' => 'Configuració SSL del servidor web',
			'ssl_key_file' => 'Ruta del fitxer de claus SSL',
			'ssl_ca_file' => 'Ruta del certificat SSL CA',
			'default_vhostconf_domain' => 'Configuració vHost per defecte per a cada contenidor de domini',
			'ssl_cert_chainfile' => [
				'title' => 'Ruta del fitxer SSL CertificateChainFile',
				'description' => 'Normalment CA_Bundle, o similar, probablement vols configurar això si has comprat un certificat SSL.'
			],
			'docroot' => [
				'title' => 'Docroot personalizat (buit = apunta a froxlor)',
				'description' => 'Aquí podeu definir un document-root personalitzat (el destí d\'una petició) per a aquesta combinació ip/port.<br/><strong>ATENCIÓ:</strong> Si us plau, vés amb compte amb el que introdueixes aquí!'
			],
			'ssl_paste_description' => 'Enganxi el contingut complet del vostre certificat al quadre de text',
			'ssl_cert_file_content' => 'Contingut del certificat ssl',
			'ssl_key_file_content' => 'Contingut del fitxer de la clau ssl (privada)',
			'ssl_ca_file_content' => 'Contingut del fitxer ssl CA (opcional)',
			'ssl_ca_file_content_desc' => '<br/><br/>Autenticació del client, configuri això només si sap el que és.',
			'ssl_cert_chainfile_content' => 'Contingut del fitxer de cadena de certificats (opcional)',
			'ssl_cert_chainfile_content_desc' => '<br/><br/>Normalment CA_Bundle, o similar, probablement vols configurar això si has comprat un certificat SSL.',
			'ssl_default_vhostconf_domain' => 'Configuració SSL vHost per defecte per a cada contenidor de domini'
		],
		'memorylimitdisabled' => 'Desactivat',
		'valuemandatory' => 'Aquest valor és obligatori',
		'valuemandatorycompany' => 'O bé "nom" i "nom complet" o "empresa" ha de ser omplert',
		'serversoftware' => 'Programari del servidor',
		'phpversion' => 'Versió PHP',
		'mysqlserverversion' => 'Versió del servidor MySQL',
		'webserverinterface' => 'Interfície del servidor web',
		'accountsettings' => 'Configuració del compte',
		'panelsettings' => 'Configuració del panell',
		'systemsettings' => 'Configuració del sistema',
		'webserversettings' => 'Configuració del servidor web',
		'mailserversettings' => 'Configuració del servidor de correu',
		'nameserversettings' => 'Configuració del servidor de noms',
		'updatecounters' => 'Recalcular l\'ús de recursos',
		'subcanemaildomain' => [
			'never' => 'Mai',
			'choosableno' => 'Seleccionable, per defecte no',
			'choosableyes' => 'Seleccionable, per defecte sí',
			'always' => 'Sempre'
		],
		'wipecleartextmailpwd' => 'Esborrar contrasenyes en text pla',
		'webalizersettings' => 'Configuració de Webalizer',
		'webalizer' => [
			'normal' => 'Normal',
			'quiet' => 'Silenciós',
			'veryquiet' => 'No mostra res'
		],
		'domain_nocustomeraddingavailable' => 'Actualment no és possible afegir un domini. Primer ha d\'afegir almenys un client.',
		'loggersettings' => 'Configuració del registre',
		'logger' => [
			'normal' => 'normal',
			'paranoid' => 'paranoic'
		],
		'emaildomain' => 'Correu de domini',
		'email_only' => 'Només correu electrònic?',
		'wwwserveralias' => 'Afageix un "www." ServerAlias',
		'subject' => 'Assumpte',
		'recipient' => 'Destinatari',
		'message' => 'Escriure un missatge',
		'text' => 'Missatge',
		'sslsettings' => 'Configuració SSL',
		'specialsettings_replacements' => 'Pot utilitzar les següents variables:<br/><code>{DOMAIN}</code>, <code>{DOCROOT}</code>, <code>{CUSTOMER}</code>, <code>{IP}</code>, <code>{PORT}</code>, <code>{SCHEME}</code>, <code>{FPMSOCKET}</code> (si escau)<br/>',
		'dkimsettings' => 'Configuració de DKIM',
		'caneditphpsettings' => 'Pot canviar els paràmetres de domini relacionats amb php?',
		'allips' => 'Totes les IP',
		'awstatssettings' => 'Configuració de AWstats',
		'domain_dns_settings' => 'Configuració DNS del domini',
		'activated' => 'Activat',
		'statisticsettings' => 'Configuració d\'estadístiques',
		'or' => 'o',
		'sysload' => 'Càrrega del sistema',
		'noloadavailable' => 'no disponible',
		'nouptimeavailable' => 'no disponible',
		'nosubject' => '(Sense assumpte)',
		'security_settings' => 'Opcions de seguretat',
		'know_what_youre_doing' => 'Canviar només si sap el que fa!',
		'show_version_login' => [
			'title' => 'Mostra la versió de froxlor a l\'inici de sessió',
			'description' => 'Mostrar la versió de froxlor al peu de pàgina a la pàgina d\'inici de sessió'
		],
		'show_version_footer' => [
			'title' => 'Mostrar la versió de froxlor al peu de pàgina',
			'description' => 'Mostrar la versió de froxlor al peu de pàgina de la resta de pàgines'
		],
		'froxlor_graphic' => [
			'title' => 'Gràfic de capçalera per a froxlor',
			'description' => 'Quin gràfic s\'ha de mostrar a la capçalera'
		],
		'phpsettings' => [
			'title' => 'Configuració PHP',
			'description' => 'Breu descripció',
			'actions' => 'Accions',
			'activedomains' => 'En ús per domini(s)',
			'notused' => 'Configuració no en ús',
			'editsettings' => 'Canviar configuració PHP',
			'addsettings' => 'Crear nova configuració PHP',
			'viewsettings' => 'Veure la configuració PHP',
			'phpinisettings' => 'Configuració php.ini',
			'addnew' => 'Crear nova configuració PHP',
			'binary' => 'PHP Binari',
			'fpmdesc' => 'Configuració PHP-FPM',
			'file_extensions' => 'Extensions de fitxers',
			'file_extensions_note' => '(sense punt, separades per espais)',
			'enable_slowlog' => 'Activar slowlog (per domini)',
			'request_terminate_timeout' => 'Sol·licitar terminate-timeout',
			'request_slowlog_timeout' => 'Sol·licitar slowlog-timeout',
			'activephpconfigs' => 'En ús per php-config(s)',
			'pass_authorizationheader' => 'Afegeix les capçaleres HTTP AUTH BASIC/DIGEST de l\'Apache cap al PHP'
		],
		'misc' => 'Varis',
		'fpmsettings' => [
			'addnew' => 'Crear nova versió PHP',
			'edit' => 'Canviar versió PHP'
		],
		'phpconfig' => [
			'template_replace_vars' => 'Variables que seran reemplaçades a les configs',
			'pear_dir' => 'Serà reemplaçada amb la configuració global per al directori pear.',
			'open_basedir_c' => 'S\'inserirà un ; (punt i coma) per comentar/desactivar open_basedir quan s\'estableixi',
			'open_basedir' => 'Es substituirà per la configuració open_basedir del domini.',
			'tmp_dir' => 'Serà reemplaçat pel directori temporal del domini.',
			'open_basedir_global' => 'Es substituirà pel valor global de la ruta que s\'adjuntarà a open_basedir (veure configuració del servidor web).',
			'customer_email' => 'Es substituirà per l\'adreça de correu electrònic del client propietari del domini.',
			'admin_email' => 'Es substituirà per l\'adreça de correu electrònic de l\'administrador propietari del domini.',
			'domain' => 'Es substituirà pel domini.',
			'customer' => 'Es substituirà pel nom d\'usuari del client propietari del domini.',
			'admin' => 'Es substituirà pel nom d\'usuari de l\'administrador propietari del domini.',
			'docroot' => 'Es substituirà per l\'arrel del document del domini.',
			'homedir' => 'Es substituirà pel directori arrel del client.'
		],
		'expert_settings' => 'Configuració experta!',
		'mod_fcgid_starter' => [
			'title' => 'Processos PHP per a aquest domini (buit per defecte)'
		],
		'phpserversettings' => 'Configuracions de PHP',
		'mod_fcgid_maxrequests' => [
			'title' => 'Peticions php màximes per a aquest domini (buit per defecte)'
		],
		'spfsettings' => 'Configuració SPF del domini',
		'specialsettingsforsubdomains' => 'Aplicar configuració especial a tots els subdominis (*.exemple.com)',
		'accountdata' => 'Dades del compte',
		'contactdata' => 'Dades de contacte',
		'servicedata' => 'Dades de servei',
		'newerversionavailable' => 'Hi ha una nova versió de froxlor disponible.',
		'newerversiondetails' => 'Actualitzi ara a la versió <b>%s</b>?<br/>(La seva versió actual és: %s)',
		'extractdownloadedzip' => 'Extreure el fitxer descarregat "%s"?',
		'cron' => [
			'cronsettings' => 'Configuració de tasques de Cron',
			'add' => 'Afegir tasca cron'
		],
		'cronjob_edit' => 'Editar tasques de cron',
		'warning' => 'AVÍS - Tingueu en compte!',
		'lastlogin_succ' => 'Darrer inici de sessió',
		'ftpserver' => 'Servidor FTP',
		'ftpserversettings' => 'Configuració del servidor FTP',
		'webserver_user' => 'Nom d\'usuari del servidor web',
		'webserver_group' => 'Nom de grup del servidor web',
		'perlenabled' => 'Perl activat',
		'fcgid_settings' => 'FCGID',
		'mod_fcgid_user' => 'Usuari local a utilitzar per a FCGID (froxlor vHost)',
		'mod_fcgid_group' => 'Grup local a utilitzar per a FCGID (froxlor vHost)',
		'perl_settings' => 'Perl/CGI',
		'notgiven' => '[No indicat]',
		'store_defaultindex' => 'Emmagatzemar el fitxer d\'índex per defecte al docroot del client',
		'phpfpm_settings' => 'PHP-FPM',
		'traffic' => 'Trànsit',
		'traffic_sub' => 'Detalls sobre l\'ús del trànsit',
		'domaintraffic' => 'Dominis',
		'customertraffic' => 'Clients',
		'assignedmax' => 'Assignat / Màxim',
		'usedmax' => 'Utilitzat / Màxim',
		'used' => 'Utilitzat',
		'speciallogwarning' => '<div id="speciallogfilenote" class="invalid-feedback">AVÍS: En canviar aquesta configuració perdrà totes les antigues estadístiques per a aquest domini.</div>',
		'speciallogfile' => [
			'title' => 'Fitxer de registre separat',
			'description' => 'Activi aquesta opció per obtenir un fitxer de registre d\'accés independent per a aquest domini.'
		],
		'domain_editable' => [
			'title' => 'Permetre editar el domini',
			'desc' => 'Si s\'estableix en "si", el client pot canviar diversos paràmetres del domini.<br/>Si s\'estableix en "no", el client no pot canviar res.'
		],
		'writeaccesslog' => [
			'title' => 'Escriure un registre d\'accés',
			'description' => 'Activi aquesta opció per obtenir un fitxer de registre d\'accés per a aquest domini.'
		],
		'writeerrorlog' => [
			'title' => 'Escriure un registre d\'errors',
			'description' => 'Activi aquesta opció per obtenir un fitxer de registre d \'errors per a aquest domini.'
		],
		'phpfpm.ininote' => 'No tots els valors que voleu definir poden ser utilitzats en la configuració del pool php-fpm',
		'phpinfo' => 'PHPinfo()',
		'selectserveralias' => 'Valor ServerAlias per al domini',
		'selectserveralias_desc' => 'Triï si froxlor ha de crear una entrada comodí (*.domini.tld), un àlies WWW (www.domini.tld) o cap àlies.',
		'show_news_feed' => [
			'title' => 'Mostrar notícies al panell d\'administració',
			'description' => 'Activi aquesta opció per mostrar les notícies oficials de froxlor (https://inside.froxlor.org/news/) al teu tauler de control i no perdre\'t mai informació important o anuncis de llançaments.'
		],
		'cronsettings' => 'Configuració de tasques de Cron',
		'integritycheck' => 'Validació de la base de dades',
		'integrityname' => 'Nom',
		'integrityresult' => 'Resultat',
		'integrityfix' => 'Solució automàtica de problemes',
		'customer_show_news_feed' => 'Mostrar notícies al panell del client',
		'customer_news_feed_url' => [
			'title' => 'Utilitzar un canal RSS personalitzat',
			'description' => 'Especifiqui un canal RSS personalitzat que es mostrarà als vostres clients en el vostre tauler de control.<br/><small>Deixi aquest camp buit per utilitzar el canal de notícies oficial de froxlor (https://inside.froxlor.org/news/).</small>'
		],
		'movetoadmin' => 'Moure client',
		'movecustomertoadmin' => 'Mou el client a l\'administrador/revenedor seleccionat<br/><small>Deixa això buit per no fer canvis.<br/>Si l\'administrador desitjat no apareix a la llista, el seu límit de clients ha estat assolit.</small>',
		'note' => 'Nota',
		'mod_fcgid_umask' => [
			'title' => 'Màscara (per defecte: 022)'
		],
		'apcuinfo' => 'Informació APCu',
		'opcacheinfo' => 'Informació OPcache',
		'letsencrypt' => [
			'title' => 'Utilitzar Let\'s Encrypt',
			'description' => 'Obtingui un certificat gratuït de <a href="https://letsencrypt.org">Let\'s Encrypt</a>. El certificat es crearà i renovarà automàticament.<br /><strong class="text-danger">ATENCIÓ:</strong> Si els comodins estan activats, aquesta opció es desactivarà automàticament.'
		],
		'autoupdate' => 'Actualitza automàticament',
		'server_php' => 'PHP',
		'dnsenabled' => 'Habilitar editor DNS',
		'froxlorvhost' => 'Configuració VirtualHost de froxlor ',
		'hostname' => 'Nom de host',
		'memory' => 'Memòria en ús',
		'webserversettings_ssl' => 'Configuració SSL del servidor web',
		'domain_hsts_maxage' => [
			'title' => 'Seguretat estricta de transport HTTP (HSTS)',
			'description' => 'Especifiqui el valor d\'edat màxima per a la capçalera Strict-Transport-Security (STS)<br/>El valor <i>0</i> desactivarà HSTS per al domini. La majoria dels usuaris estableixen un valor de <i>31536000</i> (un any).'
		],
		'domain_hsts_incsub' => [
			'title' => 'Incloure HSTS per a qualsevol subdomini',
			'description' => 'La directiva opcional "includeSubDomains", si és present, indica a la UA que la Política HSTS s\'aplica a aquest Host HSTS així com a qualsevol subdomini del nom de domini del host.'
		],
		'domain_hsts_preload' => [
			'title' => 'Incloure domini a la <a href="https://hstspreload.org/" target="_blank">llista de precàrrega HSTS</a>',
			'description' => 'Si vol que aquest domini s\'inclogui a la llista de precàrrega HSTS mantinguda per Chrome (i utilitzada per Firefox i Safari), activeu aquesta opció.<br />L\'enviament de la directiva de precàrrega des del vostre lloc pot tenir CONSEQÜÈNCIES PERMANENTS i impedir que els usuaris accedeixin al seu lloc i a qualsevol dels seus subdominis.<br />Si us plau, llegiu els detalls a <a href="https://hstspreload.org/#removal" target="_blank">https://hstspreload .org/#removal</a> abans d\'enviar la capçalera amb "preload".'
		],
		'domain_ocsp_stapling' => [
			'title' => 'OCSP stapling',
			'description' => 'Consulti <a target="_blank" href="https://en.wikipedia.org/wiki/OCSP_stapling">Wikipedia</a> per a una explicació detallada del grapat OCSP',
			'nginx_version_warning' => '<br /><strong class="text-danger">AVÍS:</strong> Es requereix la versió 1.3.7 o superior de Nginx per al OCSP stapling. Si la vostra versió és anterior, el servidor web NO s\'iniciarà correctament mentre el grapat OCSP estigui activat!'
		],
		'domain_http2' => [
			'title' => 'Suport HTTP2',
			'description' => 'Consulti <a target="_blank" href="https://en.wikipedia.org/wiki/HTTP/2">Wikipedia</a> per a una explicació detallada de HTTP2'
		],
		'testmail' => 'Prova SMTP',
		'phpsettingsforsubdomains' => 'Aplicar php-config a tots els subdominis:',
		'plans' => [
			'name' => 'Nom del pla',
			'description' => 'Descripció',
			'last_update' => 'Última actualització',
			'plans' => 'Plans d\'allotjament',
			'plan_details' => 'Detalls del pla',
			'add' => 'Afegir nou pla',
			'edit' => 'Editar pla',
			'use_plan' => 'Aplicar pla'
		],
		'notryfiles' => [
			'title' => 'No s\'autogeneren try_files',
			'description' => 'Digui "sí" aquí si vol especificar una directiva try_files personalitzada en specialsettings (necessària per a alguns plugins de wordpress).'
		],
		'logviewenabled' => 'Habilitar accés als logs d\'accéss/error',
		'novhostcontainer' => '<br /><br /><small class="text-danger">Cap de les IPs i ports té activada l\'opció "Crear vHost-Container", molts ajustaments aquí no estaran disponibles</small>',
		'ownsslvhostsettings' => 'Configuració pròpia de SSL vHost',
		'domain_override_tls' => 'Anul·lar la configuració TLS del sistema',
		'domain_override_tls_addinfo' => '<br /><span class="text-danger">Només s\'utilitza si l\'opció "Override system TLS settings" està configurada com a "Sí".</span>',
		'domain_sslenabled' => 'Habilitar l\'ús de SSL',
		'domain_honorcipherorder' => 'Respecteu l\'ordre de xifrat (servidor), per defecte <strong>no</strong>',
		'domain_sessiontickets' => 'Habilitar TLS sessiontickets (RFC 5077), per defecte <strong>sí</strong>',
		'domain_sessionticketsenabled' => [
			'title' => 'Habilitar l\'ús de TLS sessiontickets globalment',
			'description' => 'Per defecte <strong>sí</strong><br/>Requereix apache-2.4.11+ o nginx-1.5.9+'
		],
		'domaindefaultalias' => 'Valor per defecte de ServerAlias per a nous dominis',
		'smtpsettings' => 'Configuració SMTP',
		'smtptestaddr' => 'Enviar correu de prova a',
		'smtptestnote' => 'Tingueu en compte que els valors següents reflecteixen la configuració actual i només es poden ajustar allà (vegeu l\'enllaç a la cantonada superior dreta)',
		'smtptestsend' => 'Enviar correu de prova',
		'mysqlserver' => [
			'mysqlserver' => 'Servidor MySQL',
			'dbserver' => 'Servidor #',
			'caption' => 'Descripció',
			'host' => 'Nom de host / IP',
			'port' => 'Port',
			'user' => 'Usuari privilegiat',
			'add' => 'Afegir nou servidor MySQL',
			'edit' => 'Editar servidor MySQL',
			'password' => 'Contrasenya d\'usuari privilegiat',
			'password_emptynochange' => 'Nova contrasenya, deixar buit per a cap canvi',
			'allowall' => [
				'title' => 'Permetre l\'ús d\'aquest servidor a tots els clients existents actualment',
				'description' => 'Estableix aquesta opció a "Cert" si voleu permetre l\'ús d\'aquest servidor de base de dades a tots els clients existents perquè hi puguin afegir bases de dades. Aquesta configuració no és permanent, però es pot executar diverses vegades.'
			],
			'testconn' => 'Provar la connexió en desar',
			'ssl' => 'Utilitzar SSL per a la connexió al servidor de base de dades',
			'ssl_cert_file' => 'La ruta del fitxer a l\'autoritat del certificat SSL',
			'verify_ca' => 'Habilitar la verificació del certificat SSL del servidor'
		],
		'settings_importfile' => 'Escollir fitxer d\'importació',
		'documentation' => 'Documentació',
		'adminguide' => 'Guia de l\'administrador',
		'userguide' => 'Guia de l\'usuari',
		'apiguide' => 'Guia de la API'
	],
	'apcuinfo' => [
		'clearcache' => 'Esborrar memòria cau d\'APCu',
		'generaltitle' => 'Informació general sobre la memòria cau',
		'version' => 'Versió d\'APCu',
		'phpversion' => 'Versió PHP',
		'host' => 'Host APCu',
		'sharedmem' => 'Memòria compartida',
		'sharedmemval' => '%d Segment(s) amb %s (%s memòria)',
		'start' => 'Hora d\'inici',
		'uptime' => 'Temps d\'activitat',
		'upload' => 'Suport de càrrega de fitxers',
		'cachetitle' => 'Informació de la memòria cau',
		'cvar' => 'Variables en memòria cau',
		'hit' => 'Encerts',
		'miss' => 'Errors',
		'reqrate' => 'Taxa de peticions (encerts, errors)',
		'creqsec' => 'Peticions de memòria cau/segon',
		'hitrate' => 'Taxa d\'encerts',
		'missrate' => 'Percentatge d\'errors',
		'insrate' => 'Taxa d\'insercions',
		'cachefull' => 'Recompte de memòria cau plena',
		'runtime' => 'Configuració de temps d\'execució',
		'memnote' => 'Ús de memòria',
		'total' => 'Total',
		'free' => 'Lliure',
		'used' => 'Utilitzat',
		'hitmiss' => 'Encerts i errors',
		'detailmem' => 'Ús detallat de memòria i fragmentació',
		'fragment' => 'Fragmentació',
		'nofragment' => 'Sense Fragmentació',
		'fragments' => 'Fragments'
	],
	'apikeys' => [
		'no_api_keys' => 'No s\'han trobat claus API',
		'key_add' => 'Afegir una nova clau',
		'apikey_removed' => 'La clau api amb l\'id #%s ha estat eliminada amb èxit',
		'apikey_added' => 'S\'ha generat correctament una nova clau api',
		'clicktoview' => 'Faci clic per veure',
		'allowed_from' => 'Permès des de',
		'allowed_from_help' => 'Llista separada per comes d\'adreces IP / xarxes.<br />Per defecte és buit (permetre des de tots).',
		'valid_until' => 'Vàlid fins',
		'valid_until_help' => 'Data fins a la qual és vàlid, format AAAA-MM-DDThh:mm'
	],
	'changepassword' => [
		'old_password' => 'Contrasenya antiga',
		'new_password' => 'Nova contrasenya',
		'new_password_confirm' => 'Confirmi la contrasenya',
		'new_password_ifnotempty' => 'Nova contrasenya (buida = sense canvis)',
		'also_change_ftp' => ' canviï també la contrasenya del compte FTP principal',
		'also_change_stats' => ' canviï també la contrasenya de la pàgina d\'estadístiques'
	],
	'cron' => [
		'cronname' => 'Nom de la tasca cron',
		'lastrun' => 'última execució',
		'interval' => 'interval',
		'isactive' => 'activat',
		'description' => 'descripció',
		'changewarning' => 'Canviar aquests valors pot tenir una causa negativa en el comportament de froxlor i les tasques automatitzades.<br/>Si us plau, només canviï els valors aquí, si està segur del que està fent.'
	],
	'crondesc' => [
		'cron_unknown_desc' => 'cap descripció especificada',
		'cron_tasks' => 'Generació d\'arxius de configuració',
		'cron_legacy' => 'Tasca cron heretadada (antic)',
		'cron_traffic' => 'Càlcul de trànsit',
		'cron_usage_report' => 'Informes web i de trànsit',
		'cron_mailboxsize' => 'Càlcul de la mida de la bústia',
		'cron_letsencrypt' => 'Actualització de certificats Let\'s Encrypt',
		'cron_backup' => 'Processar tasques de còpia de seguretat'
	],
	'cronjob' => [
		'cronjobsettings' => 'Configuració de Tasques Cron',
		'cronjobintervalv' => 'Valor de l\'interval de temps d\'execució',
		'cronjobinterval' => 'Interval d\'execució'
	],
	'cronjobs' => [
		'notyetrun' => 'Encara no executat'
	],
	'cronmgmt' => [
		'minutes' => 'minuts',
		'hours' => 'hores',
		'days' => 'dies',
		'weeks' => 'setmanes',
		'months' => 'mesos'
	],
	'customer' => [
		'documentroot' => 'Directori d\'inici',
		'name' => 'Nom complet',
		'firstname' => 'Nom',
		'lastname' => 'Cognoms',
		'company' => 'Empresa',
		'nameorcompany_desc' => 'Es requereix nom/cognom o empresa',
		'street' => 'Carrer',
		'zipcode' => 'Codi postal',
		'city' => 'Ciutat',
		'phone' => 'Telèfon',
		'fax' => 'Fax',
		'email' => 'Correu electrònic',
		'customernumber' => 'ID de client',
		'diskspace' => 'Espai web',
		'traffic' => 'Trànsit',
		'mysqls' => 'Bases de dades MySQL',
		'emails' => 'Adreces de correu electrònic',
		'accounts' => 'Comptes de correu electrònic',
		'forwarders' => 'Remitents de correu electrònic',
		'ftps' => 'Comptes FTP',
		'subdomains' => 'Subdominis',
		'domains' => 'Dominis',
		'mib' => 'MiB',
		'gib' => 'GiB',
		'title' => 'Títol',
		'country' => 'País',
		'email_quota' => 'Quota de correu electrònic',
		'email_imap' => 'Correu IMAP',
		'email_pop3' => 'Correu electrònic POP3',
		'sendinfomail' => 'Enviar dades per correu electrònic',
		'generated_pwd' => 'Suggeriment de contrasenya',
		'usedmax' => 'Utilitzat / Màxim',
		'services' => 'Serveis',
		'letsencrypt' => [
			'title' => 'Utilitzar Let\'s Encrypt',
			'description' => 'Obtingui un certificat gratuït de <a href="https://letsencrypt.org">Let\'s Encrypt</a>. El certificat es crearà i renovarà automàticament.'
		],
		'selectserveralias_addinfo' => 'Aquesta opció es pot configurar en editar el domini. El seu valor inicial s\'hereta del domini pare.',
		'total_diskspace' => 'Espai total en disc',
		'mysqlserver' => 'Servidor mysql utilitzable'
	],
	'diskquota' => 'Quota',
	'dns' => [
		'destinationip' => 'IP(s) del domini',
		'standardip' => 'IP estàndard del servidor',
		'a_record' => 'Registre A (IPv6 opcional)',
		'cname_record' => 'Registre CNAME',
		'mxrecords' => 'Definir registres MX',
		'standardmx' => 'Registre MX estàndard del servidor',
		'mxconfig' => 'Registres MX personalitzats',
		'priority10' => 'Prioritat 10',
		'priority20' => 'Prioritat 20',
		'txtrecords' => 'Definir registres TXT',
		'txtexample' => 'Exemple (entrada SPF):<br/>v=spf1 ip4:xxx.xxx.xx.0/23 -all',
		'howitworks' => 'Aquí podeu gestionar les entrades DNS per al vostre domini. Tingueu en compte que froxlor generarà automàticament els registres NS/MX/A/AAAA per tu. Les entrades personalitzades són preferibles, només les entrades que faltin seran generades automàticament.'
	],
	'dnseditor' => [
		'edit' => 'editar DNS',
		'records' => 'Registres',
		'notes' => [
			'A' => 'Adreça IPv4 de 32 bits, utilitzada per mapejar noms de host a una adreça IP del host.',
			'AAAA' => 'Adreça IPv6 de 128 bits, utilitzada per mapejar noms de host a una adreça IP del host.',
			'CAA' => 'El registre de recursos CAA permet al titular d\'un nom de domini DNS especificar una o diverses Autoritats de Certificació (CA) autoritzades a emetre certificats per a aquest domini.<br/>Estructura: <code>flag tag[issue|issuewild|iodef|contactmail|contactphone] value</code><br/>Exemple: <code>0 issue "ca.example.net"<br/></code> 0 <code>iodef "mailto:security@example.com"< /code>',
			'CNAME' => 'Àlies del nom de domini, la cerca DNS continuarà reintentant la cerca amb el nou nom. Només és possible per a subdominis.',
			'DNAME' => 'Crea un àlies per a tot un subarbre de l\'arbre de noms de domini',
			'LOC' => 'Informació sobre la ubicació geogràfica d\'un nom de domini.<br/>Estructura: <code>( d1 [m1 [s1]] { d2 [m2 [s2]] { alt["m"] [siz["m"] [hp["m"] [vp["m"]]]] )</code><br/>Descripció: <code>d1</code>: [0 . <code>. 90] (graus de latitud)
			d2: [0 .. 180] (graus de longitud)
			m1, m2: [0 .. 59] (minuts latitud/longitud)
			s1, s2: [0 .. 59,999] (segons latitud/longitud)
			alt: [-100000.00 .. 42849672.95] POR .01 (altitud en metres)
			siz, hp, vp: [0 .. 90000000.00] (mida/precisió en metres)</code><br/>Exemple: <code>52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m</code>',
			'MX' => 'Registre d\'intercanvi de correu, assigna un nom de domini a un servidor de correu per a aquest domini.<br/>Exemple: <code>10 mail.example.com</code><br/>Nota : Per a la prioritat, utilitzeu el camp anterior.',
			'NS' => 'Delega una zona DNS perquè utilitzi els servidors de noms autoritatius indicats.',
			'RP' => 'Registre de persona responsable<br/>Estructura: <code>mailbox[substituir @ per un punt] txt-record-name</code><br/>Exemple: <code>team.froxlor.org . froxlor.org.</code>',
			'SRV' => 'Registre d\'ubicació de servei, utilitzat per a protocols més recents en lloc de crear registres específics de protocol com MX.<br/>Estructura: <code>priority weight port target</code><br/>Exemple : <code>0 5 5060 sipserver.example.com.</code><br/>Nota: Per a la prioritat, utilitzeu el camp anterior.',
			'SSHFP' => 'El registre de recursos SSHFP s\'utilitza per publicar empremtes digitals de claus d\'intèrpret d\'ordres segur (SSH) al DNS.<br/>Estructura: <code>tipus d\'algorisme empremta digital</code><br/ >Algorismes: 0: reservat <code>, 1: RSA, 2: DSA, 3: ECDSA, 4: Ed25519, 6: Ed448</code><br/>Tipus: 0 <code>: reservat, 1: SHA- 1, 2: SHA-256</code><br/>Exemple: <code>2 1 123456789abcdef67890123456789abcdef67890</code>',
			'TXT' => 'Text descriptiu de lliure definició.'
		]
	],
	'domain' => [
		'openbasedirpath' => 'Ruta OpenBasedir',
		'docroot' => 'Ruta del camp anterior',
		'homedir' => 'Directori d\'inici',
		'docparent' => 'Directori pare de la ruta del camp anterior',
    'ssl_certificate_placeholder' => '---- BEGIN CERTIFICATE---' . PHP_EOL . '[...]' . PHP_EOL . '----END CERTIFICATE----',
    'ssl_key_placeholder' => '---- BEGIN RSA PRIVATE KEY-----' . PHP_EOL . '[...]' . PHP_EOL . '-----END RSA PRIVATE KEY-----',
	],
	'domains' => [
		'description' => 'Aquí pot crear (sub)dominis i canviar les seves rutes.<br/>El sistema necessitarà algun temps per aplicar la nova configuració després de cada canvi.',
		'domainsettings' => 'Configuració del domini',
		'domainname' => 'Nom de domini',
		'subdomain_add' => 'Crear subdomini',
		'subdomain_edit' => 'Editar (sub)domini',
		'wildcarddomain' => 'Crear com a domini comodí?',
		'aliasdomain' => 'Àlies per a domini',
		'noaliasdomain' => 'Sense àlies de domini',
		'hasaliasdomains' => 'Té domini(s) àlies',
		'statstics' => 'Estadístiques d\'ús',
		'isassigneddomain' => 'Domini assignat',
		'add_date' => 'Afegit a froxlor',
		'registration_date' => 'Afegit al registre',
		'topleveldomain' => 'Domini Top-Level',
		'associated_with_domain' => 'Associat',
		'aliasdomains' => 'Dominis d\'àlies',
		'redirectifpathisurl' => 'Codi de redirecció (per defecte: buit)',
		'redirectifpathisurlinfo' => 'Només ha de seleccionar una d\'aquestes opcions si heu introduït un URL com a ruta<br/><strong class="text-danger">NOTA:</strong> Els canvis només s\'apliquen si la ruta indicada és una URL.',
		'issubof' => 'Aquest domini és un subdomini d\'un altre domini',
		'issubofinfo' => 'Si vol afegir un subdomini com a domini complet, haureu d\'establir-lo al domini correcte (per exemple, si voleu afegir "www.domini.tld", haureu de seleccionar "domini.tld").',
		'nosubtomaindomain' => 'No és subdomini d\'un domini complet',
		'ipandport_multi' => [
			'title' => 'Adreces IP',
			'description' => 'Especifica una o més adreces IP per al domini.<br/><br/><div class="text-danger">NOTA: Les adreces IP no es poden canviar quan el domini està configurat com a <strong>àlies-domini</ strong> d\'un altre domini.</div>'
		],
		'ipandport_ssl_multi' => [
			'title' => 'Adreça(es) IP SSL'
		],
		'ssl_redirect' => [
			'title' => 'Redirecció SSL',
			'description' => 'Aquesta opció crea redireccionaments per a vhosts no SSL de manera que totes les peticions són redirigides al vhost SSL.<br/><br/>p.e. una petició a <strong>http://domini.tld/</strong> us redirigirà a <strong>https://domini.tld/</strong>'
		],
		'serveraliasoption_wildcard' => 'Comodí (*.domini.tld)',
		'serveraliasoption_www' => 'WWW (www.domini.tld)',
		'serveraliasoption_none' => 'Sense àlies',
		'domain_import' => 'Importar dominis',
		'import_separator' => 'Separador',
		'import_offset' => 'Desplaçament',
		'import_file' => 'Arxiu CSV',
		'import_description' => 'Per obtenir informació detallada sobre l\'estructura del fitxer d\'importació i sobre com fer la importació correctament, visiti <a href="https://docs.froxlor.org/latest/admin-guide/domain-import/" target="_blank" class="alert-link">https://docs.froxlor.org/latest/admin-guide/domain-import/</a>.',
		'ssl_redirect_temporarilydisabled' => '<br/>La redirecció SSL es desactiva temporalment mentre es genera un certificat Let\'s Encrypt nou. Es tornarà a activar un cop generat el certificat.',
		'termination_date' => 'Data de terminació',
		'termination_date_overview' => 'acabat a partir de ',
		'ssl_certificates' => 'Certificats SSL',
		'ssl_certificate_removed' => 'El certificat amb l\'id #%s s\'ha eliminat amb èxit',
		'ssl_certificate_error' => 'Error en llegir el certificat per al domini: %s',
		'no_ssl_certificates' => 'No hi ha dominis amb certificat SSL',
		'isaliasdomainof' => 'És àlies de domini per a %s',
		'isbinddomain' => 'Crear zona DNS',
		'dkimenabled' => 'DKIM activat',
		'openbasedirenabled' => 'Restricció de Openbasedir',
		'hsts' => 'HSTS habilitat',
		'aliasdomainid' => 'ID de àlies de domini'
	],
	'emails' => [
		'description' => 'Aquí pots crear i modificar les teves adreces de correu electrònic.<br/>Un compte és com la bústia que tens davant de casa. Si algú us envia un correu electrònic, aquest caurà al compte.<br/><br/>Per descarregar els vostres correus electrònics utilitzeu la següent configuració al vostre programa de correu: (Les dades en <i>cursiva</i> s\'han de canviar pels equivalents que heu escrit!)<br/>Hostname: <b><i>nom del domini</i></b><br/>Username: <b><i>nom del compte / adreça de correu electrònic</i></b><br/>password: <b><i>la contrasenya que heu triat</i></b>',
		'emailaddress' => 'Adreça de correu electrònic',
		'emails_add' => 'Crear adreça de correu electrònic',
		'emails_edit' => 'Editar adreça de correu electrònic',
		'catchall' => 'Catchall',
		'iscatchall' => 'Definir com a adreça "catchall"?',
		'account' => 'Compte',
		'account_add' => 'Crear compte',
		'account_delete' => 'Eliminar compte',
		'from' => 'Origen',
		'to' => 'Destí',
		'forwarders' => 'Transitaris',
		'forwarder_add' => 'Crear expedidor',
		'alternative_emailaddress' => 'Adreça de correu electrònic alternativa',
		'quota' => 'Quota',
		'noquota' => 'Sense quota',
		'updatequota' => 'Actualitzar quota',
		'quota_edit' => 'Modificar quota de correu electrònic',
		'noemaildomainaddedyet' => 'Encara no té un domini (de correu electrònic) al vostre compte.',
		'back_to_overview' => 'Tornar a la vista general de dominis',
		'accounts' => 'Comptes',
		'emails' => 'Adreces'
	],
	'error' => [
		'error' => 'Error',
		'directorymustexist' => 'El directori %s ha d\'existir. Si us plau, crea\'l amb el teu client FTP.',
		'filemustexist' => 'El fitxer %s ha d\'existir.',
		'allresourcesused' => 'Ja ha utilitzat tots els seus recursos.',
		'domains_cantdeletemaindomain' => 'No pot suprimir un domini assignat.',
		'domains_canteditdomain' => 'No pot editar aquest domini. Ha estat desactivat per l\'administrador.',
		'domains_cantdeletedomainwithemail' => 'No pot suprimir un domini que s\'utilitza com a domini de correu electrònic. Elimineu primer totes les adreces de correu electrònic.',
		'firstdeleteallsubdomains' => 'Abans de crear un domini comodí, heu d\'eliminar tots els subdominis.',
		'youhavealreadyacatchallforthisdomain' => 'Ja ha definit un domini comodí per a aquest domini.',
		'ftp_cantdeletemainaccount' => 'No pot suprimir el vostre compte FTP principal',
		'login' => 'El nom d\'usuari o la contrasenya que heu introduït són incorrectes. Intenta-ho de nou.',
		'login_blocked' => 'Aquest compte ha estat suspès a causa de masses errors d\'inici de sessió. <br/>Intenteu-ho de nou en %s segons.',
		'notallreqfieldsorerrors' => 'No ha emplenat tots els camps o n\'ha omplert alguns incorrectament.',
		'oldpasswordnotcorrect' => 'La contrasenya antiga no és correcta.',
		'youcantallocatemorethanyouhave' => 'No es pot assignar més recursos dels que té.',
		'mustbeurl' => 'No heu escrit una URL vàlida o completa (per exemple http://algundomini.com/error404.htm)',
		'invalidpath' => 'No ha triat una URL vàlida (potser té problemes amb la llista d\'adreces?)',
		'stringisempty' => 'Falta informació al camp',
		'stringiswrong' => 'Camp incorrecte',
		'newpasswordconfirmerror' => 'La nova contrasenya i la de confirmació no coincideixen',
		'mydomain' => 'Domini',
		'mydocumentroot' => 'Documentroot',
		'loginnameexists' => 'El nom d\'usuari %s ja existeix',
		'emailiswrong' => 'L\'adreça de correu %s conté caràcters no vàlids o està incomplet',
		'alternativeemailiswrong' => 'Les %s adreces de correu electrònic alternatives donades per enviar les credencials semblen no ser vàlides',
		'loginnameiswrong' => 'El nom d\'usuari "%s" conté caràcters il·legals.',
		'loginnameiswrong2' => 'El nom d\'usuari conté massa caràcters. Només es permeten %s caràcters.',
		'userpathcombinationdupe' => 'La combinació de nom d\'usuari i ruta ja existeix',
		'patherror' => 'Error general. La ruta no pot estar buida',
		'errordocpathdupe' => 'L\'opció per a la ruta %s ja existeix',
		'adduserfirst' => 'Si us plau, creï primer un client',
		'domainalreadyexists' => 'El domini %s ja està assignat a un client',
		'nolanguageselect' => 'No s\'ha seleccionat cap idioma.',
		'nosubjectcreate' => 'Ha de definir un tema per a aquesta plantilla de correu.',
		'nomailbodycreate' => 'Ha de definir un text de correu per a aquesta plantilla de correu.',
		'templatenotfound' => 'La plantilla no s\'ha trobat.',
		'alltemplatesdefined' => 'No pot definir més plantilles, tots els idiomes ja estan suportats.',
		'wwwnotallowed' => 'www no està permès per a subdominis.',
		'subdomainiswrong' => 'El subdomini %s conté caràcters no vàlids.',
		'domaincantbeempty' => 'El nom de domini no pot estar buit.',
		'domainexistalready' => 'El domini %s ja existeix.',
		'domainisaliasorothercustomer' => 'L\'àlies de domini seleccionat és en ell mateix un àlies de domini, té una combinació ip/port diferent o pertany a un altre client.',
		'emailexistalready' => 'L\'adreça de correu electrònic %s ja existeix.',
		'maindomainnonexist' => 'El domini principal %s no existeix.',
		'destinationnonexist' => 'Si us plau, creeu el vostre redireccionador al camp "Destí".',
		'destinationalreadyexistasmail' => 'El remitent a %s ja existeix com a adreça de correu electrònic activa.',
		'destinationalreadyexist' => 'Ja ha definit un reenviador per "%s".',
		'destinationiswrong' => 'La redirecció %s conté caràcters no vàlids o està incompleta.',
		'backupfoldercannotbedocroot' => 'La carpeta per a les còpies de seguretat no pot ser la vostra carpeta d\'inici, escolliu una carpeta dins de la vostra carpeta d\'inici, per exemple, /backups.',
		'templatelanguagecombodefined' => 'La combinació idioma/plantilla seleccionada ja ha estat definida.',
		'templatelanguageinvalid' => 'L\'idioma seleccionat no existeix.',
		'ipstillhasdomains' => 'La combinació IP/Port que vol eliminar encara té dominis assignats, si us plau reassigneu-los a altres combinacions IP/Port abans d\'eliminar aquesta combinació IP/Port.',
		'cantdeletedefaultip' => 'No pot esborrar la combinació IP/Port per defecte, si us plau fes una altra combinació IP/Port per defecte abans d\'esborrar aquesta combinació IP/Port.',
		'cantdeletesystemip' => 'No pot suprimir la última IP del sistema, creeu una nova combinació IP/Port per a la IP del sistema o canvieu la IP del sistema.',
		'myipaddress' => 'IP',
		'myport' => 'Port',
		'myipdefault' => 'Ha de seleccionar una combinació IP/Port que es converteixi en predeterminada.',
		'myipnotdouble' => 'Aquesta combinació IP/Port ja existeix.',
		'admin_domain_emailsystemhostname' => 'El nom de host del servidor no es pot utilitzar com a domini del client.',
		'cantchangesystemip' => 'No pot canviar la última IP del sistema, creeu una nova combinació IP/Port per a la IP del sistema o canvieu la IP del sistema.',
		'sessiontimeoutiswrong' => 'Només es permet un temps d\'espera de sessió numèric.',
		'maxloginattemptsiswrong' => 'Només es permeten "intents d\'inici de sessió màxims" numèrics.',
		'deactivatetimiswrong' => 'Només es permet "temps de desactivació" numèric.',
		'accountprefixiswrong' => 'El "prefix del client" és incorrecte.',
		'mysqlprefixiswrong' => 'El "prefix SQL" és incorrecte.',
		'ftpprefixiswrong' => 'El "prefix FTP" és incorrecte.',
		'ipiswrong' => 'L\'"adreça IP" és incorrecte. Només es permet una adreça IP vàlida.',
		'vmailuidiswrong' => 'El "mails-uid" és incorrecte. Només es permet un UID numèric.',
		'vmailgidiswrong' => 'El "mails-gid" és incorrecte. Només es permet un GID numèric.',
		'adminmailiswrong' => 'La direcció del remitent és incorrecte. Només es permet una adreça de correu electrònic vàlida.',
		'pagingiswrong' => 'El valor "entries per page" és incorrecte. Només es permeten caràcters numèrics.',
		'phpmyadminiswrong' => 'L\'enllaç phpMyAdmin no és un enllaç vàlid.',
		'webmailiswrong' => 'L\'enllaç webmail no és un enllaç vàlid.',
		'webftpiswrong' => 'L\'enllaç WebFTP no és un enllaç vàlid.',
		'stringformaterror' => 'El valor del camp "%s" no té el format esperat.',
		'loginnameisusingprefix' => 'No pot crear comptes que comencen per "%s", ja que aquest prefix està configurat per ser utilitzat a l\'assignació automàtica de noms de compte. Introduïu un altre nom de compte.',
		'loginnameissystemaccount' => 'El compte "%s" ja existeix al sistema i no es pot utilitzar. Si us plau, introduïu un altre nom de compte.',
		'youcantdeleteyourself' => 'No es pot esborrar per raons de seguretat.',
		'youcanteditallfieldsofyourself' => 'Nota: No pot editar tots els camps del vostre compte per raons de seguretat.',
		'documentrootexists' => 'El directori "%s" ja existeix per a aquest client. Si us plau, elimineu-lo abans d\'afegir el client de nou.',
		'norepymailiswrong' => 'L\'adreça "Noreply-address" és incorrecta. Només es permet una adreça de correu electrònic vàlida.',
		'logerror' => 'Registre d\'error: %s',
		'nomessagetosend' => 'No ha introduït cap missatge.',
		'norecipientsgiven' => 'No ha especificat cap destinatari',
		'errorsendingmail' => 'El missatge a "%s" ha fallat',
		'errorsendingmailpub' => 'El missatge a l\'adreça de correu electrònic indicada ha fallat',
		'cannotreaddir' => 'No s\'ha pogut llegir el directori "%s".',
		'invalidip' => 'Adreça IP no vàlida: %s',
		'invalidmysqlhost' => 'Adreça de host MySQL no vàlida: %s',
		'cannotuseawstatsandwebalizeratonetime' => 'No pot activar Webalizer i AWstats al mateix temps, si us plau escolliu un d\'ells.',
		'cannotwritetologfile' => 'No es pot obrir el fitxer de registre %s per escriure',
		'vmailquotawrong' => 'La mida de la quota ha de ser un número positiu.',
		'allocatetoomuchquota' => 'Ha intentat assignar %s MB de quota, però no en té suficients.',
		'missingfields' => 'No s\'han omplert tots els camps obligatoris.',
		'requiredfield' => 'Aquest camp és obligatori.',
		'accountnotexisting' => 'El compte de correu electrònic indicat no existeix.',
		'nopermissionsorinvalidid' => 'No té permisos suficients per canviar aquesta configuració o s\'ha introduït un identificador no vàlid.',
		'phpsettingidwrong' => 'No hi ha una configuració PHP amb aquest id.',
		'descriptioninvalid' => 'La descripció és massa curta, massa llarga o conté caràcters il·legals.',
		'info' => 'Informació',
		'filecontentnotset' => 'El fitxer no pot estar buit.',
		'index_file_extension' => 'L\'extensió del fitxer índex ha de tenir entre 1 i 6 caràcters. L\'extensió només pot contenir caràcters com a-z, A-Z y 0-9',
		'customerdoesntexist' => 'El client seleccionat no existeix.',
		'admindoesntexist' => 'L\'administrador escollit no existeix.',
		'ipportdoesntexist' => 'La combinació ip/port que ha triat no existeix.',
		'usernamealreadyexists' => 'El nom d\'usuari %s ja existeix.',
		'plausibilitychecknotunderstood' => 'No s\'ha entès la resposta de la comprovació de plausibilitat.',
		'errorwhensaving' => 'S\'ha produït un error en desar els %s camps',
		'hiddenfieldvaluechanged' => 'El valor del camp ocult "%s" ha canviat en editar la configuració.<br/><br/>Això no sol ser un gran problema, però la configuració no s\'ha pogut desar per aquest motiu.',
		'notrequiredpasswordlength' => 'La contrasenya introduïda és massa curta. Si us plau, introduïu almenys %s caràcters.',
		'overviewsettingoptionisnotavalidfield' => 'Ups, un camp que s\'hauria de mostrar com una opció a la vista de configuració no és un tipus exceptuat. Pots culpar els desenvolupadors per això. Això no hauria de passar.',
		'pathmaynotcontaincolon' => 'La ruta introduïda no ha de contenir dos punts (":"). Introduïu un valor de ruta correcte.',
		'exception' => '%s',
		'notrequiredpasswordcomplexity' => 'La complexitat de la contrasenya especificada no s\'ha complert.<br/>Poseu-vos en contacte amb el vostre administrador si teniu algun dubte sobre la complexitat especificada.',
		'invaliderrordocumentvalue' => 'El valor donat com a ErrorDocument no sembla ser un fitxer, URL o cadena vàlids.',
		'intvaluetoolow' => 'El número donat és massa baix (camp %s))',
		'intvaluetoohigh' => 'El número donat és massa alt (camp %s)',
		'phpfpmstillenabled' => 'PHP-FPM està actualment actiu. Desactiveu-lo abans d\'activar FCGID.',
		'fcgidstillenabled' => 'FCGID està actualment actiu. Desactiveu-lo abans d\'activar PHP-FPM.',
		'domains_cantdeletedomainwithaliases' => 'No es pot suprimir un domini que s\'utilitza per a àlies. Primer heu d\'eliminar els àlies.',
		'user_banned' => 'El vostre compte ha estat bloquejat. Si us plau, contacteu amb el vostre administrador per a més informació.',
		'session_timeout' => 'Valor massa baix',
		'session_timeout_desc' => 'El temps d\'espera de la sessió no ha de ser inferior a 1 minut.',
		'invalidhostname' => 'El nom de host ha de ser un domini vàlid. No pot estar buit ni estar format només per espais en blanc.',
		'operationnotpermitted' => 'Operació no permesa',
		'featureisdisabled' => 'La funció %s està desactivada. Poseu-vos en contacte amb el vostre proveïdor de serveis.',
		'usercurrentlydeactivated' => 'L\'usuari %s està desactivat actualment',
		'setlessthanalreadyused' => 'No pot establir menys recursos de \'%s\' dels que aquest usuari ja ha utilitzat<br/>',
		'stringmustntbeempty' => 'El valor del camp %s no ha d\'estar buit',
		'sslcertificateismissingprivatekey' => 'Necessita especificar una clau privada per al vostre certificat',
		'sslcertificatewrongdomain' => 'El certificat indicat no pertany a aquest domini',
		'sslcertificateinvalidcert' => 'El contingut del certificat indicat no sembla un certificat vàlid.',
		'sslcertificateinvalidcertkeypair' => 'La clau privada indicada no pertany al certificat en qüestió.',
		'sslcertificateinvalidca' => 'Les dades del certificat de la CA no semblen ser un certificat vàlid.',
		'sslcertificateinvalidchain' => 'Les dades de la cadena del certificat no semblen ser un certificat vàlid.',
		'givendirnotallowed' => 'El directori indicat al camp %s no està permès.',
		'sslredirectonlypossiblewithsslipport' => 'L\'ús de Let\'s Encrypt només és possible quan el domini té assignada almenys una combinació IP/port habilitada per a ssl.',
		'fcgidstillenableddeadlock' => 'FCGID està actualment actiu.<br/>Si us plau, desactiveu-lo abans de canviar a un altre servidor web que no sigui Apache2',
		'send_report_title' => 'Enviar informe d\'error',
		'send_report_desc' => 'Gràcies per informar d\'aquest error i ajudar-nos a millorar froxlor.<br/>Aquest és el correu electrònic que s\'enviarà a l\'equip de desenvolupadors de froxlor:',
		'send_report' => 'Enviar informe',
		'send_report_error' => 'Error en enviar l\'informe: <br/>%s',
		'notallowedtouseaccounts' => 'El vostre compte no permet utilitzar IMAP/POP3. No podeu afegir comptes de correu.',
		'cannotdeletehostnamephpconfig' => 'Aquesta configuració PHP és utilitzada pel froxlor-vhost i no pot ser esborrada.',
		'cannotdeletedefaultphpconfig' => 'Aquesta configuració PHP està establerta per defecte i no es pot esborrar.',
		'passwordshouldnotbeusername' => 'La contrasenya no pot ser la mateixa que el nom dusuari.',
		'no_phpinfo' => 'Ho sentim, no puc llegir phpinfo()',
		'moveofcustomerfailed' => 'El canvi del client a l\'administrador/revenedor seleccionat ha fallat. Tingui en compte que tots els altres canvis en el client s\'han aplicat amb èxit en aquesta etapa.<br/><br/>Missatge d\'error: %s',
		'domain_import_error' => 'S\'ha produït el següent error en importar dominis: %s',
		'fcgidandphpfpmnogoodtogether' => 'FCGID i PHP-FPM no poden estar activats alhora',
		'no_apcuinfo' => 'No hi ha informació de memòria cau disponible. APCu no sembla que s\'està executant.',
		'no_opcacheinfo' => 'No hi ha informació de memòria cau disponible. OPCache no sembla que s\'està executant.',
		'nowildcardwithletsencrypt' => 'Let\'s Encrypt no pot manejar dominis comodí usant ACME a froxlor (requereix dns-challenge), ho sento. Si us plau, establiu el ServerAlias a WWW o desactiveu-lo completament.',
		'customized_version' => 'Sembla que la teva instal·lació de froxlor ha estat modificada, no hi ha suport, ho sentim.',
		'autoupdate_0' => 'Error desconegut',
		'autoupdate_1' => 'El paràmetre de PHP allow_url_fopen està desactivat. Autoupdate necessita que aquest paràmetre estigui habilitat a php.ini',
		'autoupdate_2' => 'Extensió PHP zip no trobada, si us plau assegureu-vos que està instal·lada i activada',
		'autoupdate_4' => 'El fitxer froxlor no ha pogut ser emmagatzemat al disc :(',
		'autoupdate_5' => 'version.froxlor.org ha tornat valors inacceptables :(',
		'autoupdate_6' => 'Whoops, no hi havia una versió (vàlida) donada per descarregar :(',
		'autoupdate_7' => 'No s\'ha pogut trobar el fitxer descarregat :(',
		'autoupdate_8' => 'No s\'ha pogut extreure el fitxer :(',
		'autoupdate_9' => 'El fitxer descarregat no ha passat la comprovació de la integritat. Si us plau, intenteu tornar a actualitzar.',
		'autoupdate_10' => 'La versió mínima suportada de PHP és 7.4.0',
		'autoupdate_11' => 'Webupdate està desactivat',
		'mailaccistobedeleted' => 'Un altre compte amb el mateix nom (%s) està sent eliminat i per tant no es pot afegir en aquest moment.',
		'customerhasongoingbackupjob' => 'Ja hi ha un treball de còpia de seguretat esperant a ser processat, si us plau sigui pacient.',
		'backupfunctionnotenabled' => 'La funció de còpia de seguretat no està habilitada',
		'dns_domain_nodns' => 'DNS no està habilitat per a aquest domini',
		'dns_content_empty' => 'No hi ha contingut',
		'dns_content_invalid' => 'El contingut DNS no és vàlid',
		'dns_arec_noipv4' => 'No s\'ha proporcionat cap adreça IP vàlida per al registre A.',
		'dns_aaaarec_noipv6' => 'No s\'ha indicat una adreça IP vàlida per al registre AAAA',
		'dns_mx_prioempty' => 'Prioritat MX no vàlida',
		'dns_mx_needdom' => 'El valor de contingut MX ha de ser un nom de domini vàlid.',
		'dns_mx_noalias' => 'El valor de contingut MX no pot ser una entrada CNAME.',
		'dns_cname_invaliddom' => 'Nom de domini no vàlid per al registre CNAME',
		'dns_cname_nomorerr' => 'Ja hi ha un resource-record amb el mateix nom de registre. No es pot utilitzar com a CNAME.',
		'dns_other_nomorerr' => 'Ja hi ha un registre CNAME amb el mateix nom de registre. No es pot utilitzar per a cap altre tipus.',
		'dns_ns_invaliddom' => 'Nom de domini no vàlid per al registre NS',
		'dns_srv_prioempty' => 'Prioritat SRV no vàlida',
		'dns_srv_invalidcontent' => 'Contingut SRV no vàlid, ha de contenir els camps weight, port i target, p.ex: 5 5060 servidorsip.exemple.com.',
		'dns_srv_needdom' => 'El valor SRV target ha de ser un nom de domini vàlid',
		'dns_srv_noalias' => 'El valor SRV-target no pot ser una entrada CNAME.',
		'dns_duplicate_entry' => 'El registre ja existeix',
		'dns_notfoundorallowed' => 'Domini no trobat o sense permís',
		'domain_nopunycode' => 'No heu d\'especificar punycode (IDNA). El domini es convertirà automàticament',
		'dns_record_toolong' => 'Els registres/etiquetes només poden tenir un màxim de 63 caràcters',
		'noipportgiven' => 'No s\'ha especificat IP/port',
		'jsonextensionnotfound' => 'Aquesta funció requereix una extensió php json.',
		'cannotdeletesuperadmin' => 'El primer administrador no es pot eliminar.',
		'no_wwwcnamae_ifwwwalias' => 'No es pot establir un registre CNAME per a "www" perquè el domini està configurat per generar un àlies www. Canvieu la configuració a "Sense àlies" o "Àlies comodí".',
		'local_group_exists' => 'El grup indicat ja existeix al sistema.',
		'local_group_invalid' => 'El nom del grup no és vàlid',
		'invaliddnsforletsencrypt' => 'El DNS del domini no inclou cap de les adreces IP seleccionades. La generació del certificat Let\'s Encrypt no és possible.',
		'notallowedphpconfigused' => 'Intentant utilitzar php-config que no està assignat al client',
		'pathmustberelative' => 'L\'usuari no té permís per especificar directoris fora del directori personal del client. Si us plau, especifiqueu una ruta relativa (sense /).',
		'mysqlserverstillhasdbs' => 'No es pot eliminar el servidor de base de dades de la llista de clients permesos, ja que encara hi ha bases de dades.',
		'domaincannotbeedited' => 'No se us permet editar la %s domini.',
		'invalidcronjobintervalvalue' => 'L\'interval de la tasca Cron ha de ser un dels següents: %s'
	],
	'extras' => [
		'description' => 'Aquí podeu afegir alguns extres, per exemple protecció de directoris.<br/>El sistema necessitarà algun temps per aplicar la nova configuració després de cada canvi.',
		'directoryprotection_add' => 'Afegir protecció de directori',
		'view_directory' => 'Mostra el contingut del directori',
		'pathoptions_add' => 'Afegir opcions de ruta',
		'directory_browsing' => 'Exploració del contingut del directori',
		'pathoptions_edit' => 'Editar opcions de ruta',
		'error404path' => '404',
		'error403path' => '403',
		'error500path' => '500',
		'error401path' => '401',
		'errordocument404path' => 'DocumentError 404',
		'errordocument403path' => 'DocumentError 403',
		'errordocument500path' => 'DocumentError 500',
		'errordocument401path' => 'DocumentError 401',
		'execute_perl' => 'Executar perl/CGI',
		'htpasswdauthname' => 'Raó d\'autenticació (AuthName)',
		'directoryprotection_edit' => 'Editar protecció de directori',
		'backup' => 'Crear còpia de seguretat',
		'backup_web' => 'Còpia de seguretat de dades web',
		'backup_mail' => 'Còpia de seguretat de les dades de correu',
		'backup_dbs' => 'Còpia de seguretat de bases de dades',
		'path_protection_label' => '<strong class="text-danger">Important</strong>',
		'path_protection_info' => 'Us recomanem encaridament que protegeixi la ruta indicada, consulteu "Extres" -> "Protecció de directoris".'
	],
	'ftp' => [
		'description' => 'Aquí podeu crear i modificar els vostres comptes FTP.<br/>Els canvis es fan a l\'instant i els comptes es poden utilitzar immediatament.',
		'account_add' => 'Crear compte',
		'account_edit' => 'Editar compte ftp',
		'editpassdescription' => 'Estableixi una nova contrasenya o deixeu-la en blanc per no canviar-la.'
	],
	'gender' => [
		'title' => 'Títol',
		'male' => 'Sr.',
		'female' => 'Sra.',
		'undef' => ''
	],
	'imprint' => 'Avís legal',
	'index' => [
		'customerdetails' => 'Dades del client',
		'accountdetails' => 'Dades del compte'
	],
	'integrity_check' => [
		'databaseCharset' => 'Joc de caràcters de la base de dades (ha de ser UTF-8)',
		'domainIpTable' => 'Referències IP <-> domini',
		'subdomainSslRedirect' => 'Bandera falsa SSL-redirect per a dominis no SSL',
		'froxlorLocalGroupMemberForFcgidPhpFpm' => 'Usuari froxlor als grups de clients (per a FCGID/php-fpm)',
		'webserverGroupMemberForFcgidPhpFpm' => 'Usuari Webserver als grups de clients (per a FCGID/php-fpm)',
		'subdomainLetsencrypt' => 'Els dominis principals sense port SSL assignat no tenen subdominis amb redirecció SSL activa'
	],
	'logger' => [
		'date' => 'Data',
		'type' => 'Tipus',
		'action' => 'Acció',
		'user' => 'Usuari',
		'truncate' => 'Registre buit',
		'reseller' => 'Revenedor',
		'admin' => 'Administrador',
		'cron' => 'Tasca Cron',
		'login' => 'Inici de sessió',
		'intern' => 'Intern',
		'unknown' => 'Desconegut'
	],
	'login' => [
		'username' => 'Nom d\'usuari',
		'password' => 'Contrasenya',
		'language' => 'Idioma',
		'login' => 'Inici de sessió',
		'logout' => 'Finalitzar sessió',
		'profile_lng' => 'Idioma del perfil',
		'welcomemsg' => 'Iniciï sessió per accedir al vostre compte.',
		'forgotpwd' => 'Heu oblidat la contrasenya?',
		'presend' => 'Restablir contrasenya',
		'email' => 'Correu electrònic',
		'remind' => 'Restablir la contrasenya',
		'usernotfound' => 'No s\'ha trobat l\'usuari',
		'backtologin' => 'Tornar a l\'inici de sessió',
		'combination_not_found' => 'No s\'ha trobat cap combinació d\'usuari i adreça electrònica.',
		'2fa' => 'Autenticació de dos factors (2FA)',
		'2facode' => 'Introdueixi el codi 2FA'
	],
	'mails' => [
		'pop_success' => [
			'mailbody' => 'Hola,\\nel vostre compte de correu {EMAIL} s\'ha configurat correctament.\\nAquest és un correu creat \\nautomàticament, si us plau no contesteu!\\nAtentament, el vostre administrador',
			'subject' => 'Compte de correu configurat correctament'
		],
		'createcustomer' => [
			'mailbody' => 'Hola {SALUTATION}, aquí hi ha les dades del vostre compte: Nom d\'usuari: {USERNAME}: {PASSWORD}, el seu administrador.',
			'subject' => 'Informació del compte'
		],
		'pop_success_alternative' => [
			'mailbody' => 'Hola {SALUTATION}, el vostre compte de correu {EMAIL} s\'ha configurat correctament. La contrasenya és {PASSWORD}. Aquest és un correu creat automàticament, si us plau no el contesteu. Atentament, el vostre administrador.',
			'subject' => 'Compte de correu configurat correctament'
		],
		'password_reset' => [
			'subject' => 'Restablir contrasenya',
			'mailbody' => 'Hola {SALUTATION}, aquí està el vostre enllaç per establir una nova contrasenya. Aquest enllaç és vàlid durant les següents 24 hores. {LINK}, el vostre administrador.'
		],
		'new_database_by_customer' => [
			'subject' => '[froxlor] Nova base de dades creada',
			'mailbody' => 'Hola {CUST_NAME},

acabes d\'afegir una nova base de dades. Aquí hi ha la informació introduïda:

Nom de la base de dades: {DB_NAME}
Contrasenya: {DB_PASS}
Descripció: {DB_DESC}
Nom de host de la base de dades: {DB_SRV}
phpMyAdmin: {PMA_URI}
Atentament, el vostre administrador'
		],
		'new_ftpaccount_by_customer' => [
			'subject' => 'Nou usuari ftp creat',
			'mailbody' => 'Hola {CUST_NAME}

acabes d\'afegir un nou usuari ftp. Aquí hi ha la informació introduïda:

Nom d\'usuari: {USR_NAME}
Contrasenya: {USR_PASS}
Ruta: {USR_PATH}

Atentament, el vostre administrador'
		],
		'trafficmaxpercent' => [
			'mailbody' => 'Estimat {SALUTATION}, ha utilitzat el {TRAFFICUSED} del seu {TRAFFIC} disponible de trànsit. Això és més del {MAX_PERCENT}%%',
			'subject' => 'Arribant al límit de trànsit'
		],
		'diskmaxpercent' => [
			'mailbody' => 'Estimat {SALUTATION}, ha utilitzat el {DISKUSED} de su {DISKAVAILABLE} disponible d\'espai en disc. Això és més del {MAX_PERCENT}.',
			'subject' => 'Arribant al límit d\'espai de disc'
		],
		'2fa' => [
			'mailbody' => 'Hola, el vostre codi d\'accés 2FA és..: {CODE}. Aquest és un correu creat automàticament, si us plau no el respongui. Atentament, el vostre administrador.',
			'subject' => 'froxlor - Codi 2FA'
		]
	],
	'menue' => [
		'main' => [
			'main' => 'Principal',
			'changepassword' => 'Canviar contrasenya',
			'changelanguage' => 'Canviar idioma',
			'username' => 'Iniciar sessió com ',
			'changetheme' => 'Canviar tema',
			'apihelp' => 'Ajuda d\'API',
			'apikeys' => 'Claus d\'API'
		],
		'email' => [
			'email' => 'Correu electrònic',
			'emails' => 'Adreces',
			'webmail' => 'Correu web',
			'emailsoverview' => 'Vista general de dominis de correu electrònic'
		],
		'mysql' => [
			'mysql' => 'MySQL',
			'databases' => 'Bases de dades',
			'phpmyadmin' => 'phpMyAdmin'
		],
		'domains' => [
			'domains' => 'Dominis',
			'settings' => 'Vista general de dominis'
		],
		'ftp' => [
			'ftp' => 'FTP',
			'accounts' => 'Comptes',
			'webftp' => 'WebFTP'
		],
		'extras' => [
			'extras' => 'Extres',
			'directoryprotection' => 'Protecció de directoris',
			'pathoptions' => 'Opcions de ruta',
			'backup' => 'Còpia de seguretat'
		],
		'traffic' => [
			'traffic' => 'Trànsit',
			'current' => 'Mes en curs',
			'overview' => 'Trànsit total'
		],
		'phpsettings' => [
			'maintitle' => 'Configuracions PHP',
			'fpmdaemons' => 'Versions de PHP-FPM'
		],
		'logger' => [
			'logger' => 'Registre del sistema'
		]
	],
	'message' => [
		'norecipients' => 'No s\'ha enviat cap correu electrònic perquè no hi ha destinataris a la base de dades',
		'success' => 'Missatge enviat correctament als destinataris de %s',
	],
	'mysql' => [
		'databasename' => 'Usuari/Nom de la base de dades',
		'databasedescription' => 'Descripció de la base de dades',
		'database_create' => 'Crear base de dades',
		'description' => 'Aquí podeu crear i modificar les vostres bases de dades MySQL.<br/>Els canvis es realitzen a l\'instant i la base de dades es pot utilitzar immediatament.<br/>Al menú de l\'esquerra trobareu l\'eina phpMyAdmin amb la qual podeu administrar fàcilment la vostra base de dades.<br/><br/>Per utilitzar les vostres bases de dades en els vostres propis scripts php utilitzeu els següents ajustaments: (Les dades en <i>cursiva</i> s\'han de canviar pels equivalents que hagi escrit!)<br/>Nom de host: <b><sql_host/></b><br/>Nom d\'usuari: <b><i>databasename</i></b><br/> Contrasenya: <b><i>la contrasenya que heu triat</i></b><br/>Base de dades: <b><i>databasename</i></b>',
		'mysql_server' => 'Servidor MySQL',
		'database_edit' => 'Editar base de dades',
		'size' => 'Mida',
		'privileged_user' => 'Usuari privilegiat de la base de dades',
		'privileged_passwd' => 'Contrasenya per a usuari privilegiat',
		'unprivileged_passwd' => 'Contrasenya per a usuari sense privilegis',
		'mysql_ssl_ca_file' => 'Certificat del servidor SSL',
		'mysql_ssl_verify_server_certificate' => 'Verificar certificat de servidor SSL'
	],
	'opcacheinfo' => [
		'generaltitle' => 'Informació general',
		'resetcache' => 'Restablir OPcache',
		'version' => 'Versió de OPCache',
		'phpversion' => 'Versió de PHP',
		'runtimeconf' => 'Configuració de temps d\'execució',
		'start' => 'Hora d\'inici',
		'lastreset' => 'Últim reinici',
		'oomrestarts' => 'Recompte de reinicis OOM',
		'hashrestarts' => 'Recompte de reinicis Hash',
		'manualrestarts' => 'Recompte de reinicis manuals',
		'hitsc' => 'Nombre d\'encerts',
		'missc' => 'Nombre de faltes',
		'blmissc' => 'Llista negra del nombre de faltes',
		'status' => 'Estat',
		'never' => 'mai',
		'enabled' => 'OPcache activat',
		'cachefull' => 'Memòria cau plena',
		'restartpending' => 'Reinici pendent',
		'restartinprogress' => 'Reinici en curs',
		'cachedscripts' => 'Recompte d\'scripts en memòria cau',
		'memusage' => 'Ús de memòria',
		'totalmem' => 'Memòria total',
		'usedmem' => 'Memòria utilitzada',
		'freemem' => 'Memòria lliure',
		'wastedmem' => 'Memòria desaprofitada',
		'maxkey' => 'Tecles màximes',
		'usedkey' => 'Tecles utilitzades',
		'wastedkey' => 'Tecles desaprofitades',
		'strinterning' => 'Intercalació de cadenes',
		'strcount' => 'Recompte de cadenes',
		'keystat' => 'Estadística de claus en memòria cau',
		'used' => 'Utilitzat',
		'free' => 'Lliure',
		'blacklist' => 'Llista negra',
		'novalue' => '<i>sense valor</i>',
		'true' => '<i>cert</i>',
		'false' => '<i>fals</i>',
		'funcsavail' => 'Funcions disponibles'
	],
	'panel' => [
		'edit' => 'Editar',
		'delete' => 'Eliminar',
		'create' => 'Crear',
		'save' => 'Desar',
		'yes' => 'Sí',
		'no' => 'No',
		'emptyfornochanges' => 'buit per a cap canvi',
		'emptyfordefault' => 'buit per a valors per defecte',
		'path' => 'Ruta',
		'toggle' => 'Commutar',
		'next' => 'Següent',
		'dirsmissing' => 'No es pot trobar o llegir el directori!',
		'unlimited' => '∞',
		'urloverridespath' => 'URL (anul·la la ruta)',
		'pathorurl' => 'Ruta o URL',
		'ascending' => 'ascendent',
		'descending' => 'descendent',
		'search' => 'Cercar',
		'used' => 'utilitzada',
		'translator' => 'Traductor',
		'reset' => 'Descartar canvis',
		'pathDescription' => 'Si el directori no existeix, es crearà automàticament.',
		'pathDescriptionEx' => '<br/><br/><span class="text-danger">Nota:</span> La ruta <code>/</code> no està permesa a causa de la configuració administrativa, s\'establirà automàticament a <code>/elegit.subdomini.tld/</code> si no s\'estableix en un altre directori.',
		'pathDescriptionSubdomain' => 'Si el directori no existeix, es crearà automàticament.<br/><br/>Si voleu una redirecció a un altre domini, aquesta entrada ha de començar per http:// o https://.<br/><br/>Si la URL acaba en / es considera una carpeta, si no, es tracta com a fitxer.',
		'back' => 'Tornar',
		'reseller' => 'revenedor',
		'admin' => 'administrador',
		'customer' => 'client/s',
		'send' => 'enviar',
		'nosslipsavailable' => 'Actualment no hi ha combinacions ip/port ssl per a aquest servidor',
		'backtooverview' => 'Tornar a la vista general',
		'dateformat' => 'AAAA-MM-DD',
		'dateformat_function' => 'A-m-d',
		'timeformat_function' => 'H:i:s',
		'default' => 'Per defecte',
		'never' => 'Mai',
		'active' => 'Actiu',
		'please_choose' => 'Seleccioni una opció',
		'allow_modifications' => 'Permetre modificacions',
		'megabyte' => 'MegaByte',
		'not_supported' => 'No suportat en: ',
		'view' => 'veure',
		'toomanydirs' => 'Massa subdirectoris. Tornar a la selecció manual de ruta.',
		'abort' => 'Avortar',
		'not_activated' => 'no activat',
		'off' => 'desactivat',
		'options' => 'Opcions',
		'neverloggedin' => 'Encara no s\'ha iniciat sessió',
		'descriptionerrordocument' => 'Pot ser una URL, la ruta a un fitxer o simplement una cadena envoltada de ""<br/>Deixeu-lo buit per utilitzar el valor predeterminat del servidor.',
		'unlock' => 'Desbloquejar',
		'theme' => 'Tema',
		'variable' => 'Variable',
		'description' => 'Descripció',
		'cancel' => 'Cancel·lar',
		'ssleditor' => 'Configuració SSL per a aquest domini',
		'ssleditor_infoshared' => 'Actualment utilitzant el certificat del domini pare',
		'ssleditor_infoglobal' => 'Actualment utilitzant el certificat global',
		'dashboard' => 'Panell de control',
		'assigned' => 'Assignat',
		'available' => 'Disponible',
		'news' => 'Notícies',
		'newsfeed_disabled' => 'La font de notícies està desactivada. Feu clic a la icona d\'edició per anar a la configuració.',
		'ftpdesc' => 'Descripció d\'FTP',
		'letsencrypt' => 'Utilitzant Let\'s encrypt',
		'set' => 'Aplicar',
		'shell' => 'Shell',
		'backuppath' => [
			'title' => 'Ruta de destí de la còpia de seguretat',
			'description' => 'Aquesta és la ruta on s\'emmagatzemaran les còpies de seguretat. Si seleccioneu la còpia de seguretat de les dades web, tots els fitxers de la carpeta d\'inici s\'emmagatzemen excloent-hi la carpeta de còpia de seguretat especificada aquí.'
		],
		'none_value' => 'Cap',
		'viewlogs' => 'Veure fitxers de registre',
		'not_configured' => 'El sistema encara no està configurat. Feu clic aquí per anar a la configuració.',
		'ihave_configured' => 'He configurat els serveis',
		'system_is_configured' => '<i class="fa-solid fa-circle-exclamation me-1"/>El sistema ja està configurat',
		'settings_before_configuration' => 'Assegureu-vos d\'ajustar la configuració abans de configurar els serveis aquí',
		'image_field_delete' => 'Esborrar la imatge actual existent',
		'usage_statistics' => 'Ús de recursos',
		'security_question' => 'Pregunta de seguretat',
		'listing_empty' => 'No s\'han trobat entrades',
		'unspecified' => 'sense especificar',
		'settingsmode' => 'Mode',
		'settingsmodebasic' => 'Bàsic',
		'settingsmodeadvanced' => 'Avançat',
		'settingsmodetoggle' => 'Faci clic per canviar el mode',
		'modalclose' => 'Tancar',
		'managetablecolumnsmodal' => [
			'title' => 'Administrar columnes de la taula',
			'description' => 'Aquí pot personalitzar les columnes visibles'
		],
		'mandatoryfield' => 'Camp obligatori',
		'select_all' => 'Selecciona-ho tot',
		'unselect_all' => 'Desselecciona-ho tot',
		'searchtablecolumnsmodal' => [
			'title' => 'Cerca en els camps',
			'description' => 'Seleccioni el camp on vol cercar'
		],
		'upload_import' => 'Carregar e importar'
	],
	'phpfpm' => [
		'vhost_httpuser' => 'Usuari local a utilitzar per PHP-FPM (froxlor vHost)',
		'vhost_httpgroup' => 'Grup local a utilitzar per PHP-FPM (froxlor vHost)',
		'ownvhost' => [
			'title' => 'Habilitar PHP-FPM per al vHost de froxlor',
			'description' => 'Si està habilitat, froxlor també s\'executarà sota un usuari local'
		],
		'use_mod_proxy' => [
			'title' => 'Utilitzar mod_proxy / mod_proxy_fcgi',
			'description' => '<strong class="text-danger">S\'ha d\'activar quan utilitzeu Debian 9.x (Stretch) o posterior</strong>. Activar per utilitzar php-fpm via mod_proxy_fcgi. Com a mínim es requereix apache-2.4.9'
		],
		'ini_flags' => 'Introdueixi possibles <strong>php_flags</strong>per a php.ini. Una entrada per línia',
		'ini_values' => 'Introdueixi possibles <strong>php_values</strong>per a  php.ini. Una entrada per línia',
		'ini_admin_flags' => 'Introdueixi possibles <strong>php_admin_flags</strong>per a  php.ini. Una entrada per línia',
		'ini_admin_values' => 'Introdueixi possibles <strong>php_admin_values</strong>per a  php.ini. Una entrada per línia'
	],
	'privacy' => 'Política de privadesa',
	'pwdreminder' => [
		'success' => 'Restabliment de contrasenya sol·licitat amb èxit. Seguiu les instruccions del correu electrònic que heu rebut.',
		'notallowed' => 'Usuari desconegut o el restabliment de contrasenya està desactivat',
		'changed' => 'La vostra contrasenya s\'ha actualitzat correctament. Ja podeu iniciar sessió amb la nova contrasenya.',
		'wrongcode' => 'Ho sentim, el vostre codi d\'activació no existeix o ja ha caducat.',
		'choosenew' => 'Establir nova contrasenya'
	],
	'question' => [
		'question' => 'Pregunta de seguretat',
		'admin_customer_reallydelete' => 'Realment vol eliminar el client %s? No es podrà desfer.',
		'admin_domain_reallydelete' => 'Realment vol esborrar el domini %s?',
		'admin_domain_reallydisablesecuritysetting' => 'Realment vol desactivar aquesta configuració de seguretat OpenBasedir?',
		'admin_admin_reallydelete' => 'Realment vol esborrar l\'admin %s? Tots els clients i dominis seran reassignats al vostre compte.',
		'admin_template_reallydelete' => 'Realment vol esborrar la plantilla \'%s\'?',
		'domains_reallydelete' => 'Realment vol esborrar el domini %s?',
		'email_reallydelete' => 'Realment vol esborrar l\'adreça de correu electrònic %s?',
		'email_reallydelete_account' => 'Realment vol esborrar el compte de correu de %s?',
		'email_reallydelete_forwarder' => 'Realment vol esborrar el forwarder %s?',
		'extras_reallydelete' => 'Realment vol esborrar la protecció de directori de %s?',
		'extras_reallydelete_pathoptions' => 'Realment vol esborrar les opcions de ruta de %s?',
		'extras_reallydelete_backup' => 'Realment vol avortar el treball de la còpia de seguretat planificat?',
		'ftp_reallydelete' => 'Realment vol esborrar el compte FTP %s?',
		'mysql_reallydelete' => 'Realment vol esborrar la base de dades %s? No es podrà desfer.',
		'admin_configs_reallyrebuild' => 'Realment vol reconstruir tots els fitxers de configuració?',
		'admin_customer_alsoremovefiles' => 'Treure també els fitxers d\'usuari?',
		'admin_customer_alsoremovemail' => 'Eliminar completament les dades de correu electrònic del sistema de fitxers?',
		'admin_customer_alsoremoveftphomedir' => 'Treure també el directori de l\'usuari FTP?',
		'admin_ip_reallydelete' => 'Realment vol esborrar l\'adreça IP %s?',
		'admin_domain_reallydocrootoutofcustomerroot' => 'Estàs segur que vol que l\'arrel del document per a aquest domini no estigui dins l\'arrel del client?',
		'admin_counters_reallyupdate' => 'Realment vol recalcular l\'ús de recursos?',
		'admin_cleartextmailpws_reallywipe' => 'Realment vol esborrar totes les contrasenyes no encriptades dels comptes de correu de la taula mail_users? Això no es pot revertir. L\'opció d\'emmagatzemar les contrasenyes de correu electrònic sense xifrar també es desactivarà.',
		'logger_reallytruncate' => 'Realment vol truncar la taula "%s"?',
		'admin_quotas_reallywipe' => 'Realment vol esborrar totes les quotes de la taula mail_users? Això no es pot revertir.',
		'admin_quotas_reallyenforce' => 'Realment vol aplicar la quota per defecte a tots els usuaris? Això no es pot revertir.',
		'phpsetting_reallydelete' => 'Realment vol suprimir aquesta configuració? Tots els dominis que utilitzen aquesta configuració seran canviats a la configuració per defecte.',
		'fpmsetting_reallydelete' => 'Realment vol eliminar aquesta configuració de php-fpm? Totes les configuracions de php que utilitzin aquests paràmetres es canviaran a la configuració per defecte.',
		'remove_subbutmain_domains' => 'Treure també els dominis que s\'afegeixen com a dominis complets però que són subdominis d\'aquest domini?',
		'customer_reallyunlock' => 'Realment vol desbloquejar el client %s?',
		'admin_integritycheck_reallyfix' => 'Realment vol intentar arreglar tots els problemes d\'integritat de la base de dades automàticament?',
		'plan_reallydelete' => 'Realment vol eliminar el pla d\'allotjament %s?',
		'apikey_reallydelete' => 'Realment vol esborrar aquesta api-key?',
		'apikey_reallyadd' => 'Realment vol crear una nova api-key?',
		'dnsentry_reallydelete' => 'Realment vol suprimir aquesta entrada dns?',
		'certificate_reallydelete' => 'Realment vol esborrar aquest certificat?',
		'cache_reallydelete' => 'Realment vol esborrar la memòria cau?'
	],
	'redirect_desc' => [
		'rc_default' => 'per defecte',
		'rc_movedperm' => 'mogut permanentment',
		'rc_found' => 'trobat',
		'rc_seeother' => 'veure\'n un altre',
		'rc_tempred' => 'redirecció temporal'
	],
	'serversettings' => [
		'session_timeout' => [
			'title' => 'Temps d\'espera de la sessió',
			'description' => 'Quant de temps ha d\'estar inactiu un usuari perquè s\'invalidi la sessió (segons)?'
		],
		'accountprefix' => [
			'title' => 'Prefix de client',
			'description' => 'Quin prefix han de tenir els comptes de client?'
		],
		'mysqlprefix' => [
			'title' => 'Prefix SQL',
			'description' => 'Quin prefix han de tenir els comptes MySQL?<br/>Utilitzeu "RANDOM" com a valor per obtenir un prefix aleatori de 3 dígits<br/>Utilitzeu "DBNAME" com a valor, s\'utilitza un camp de nom de base de dades juntament amb el nom del client com a prefix.'
		],
		'ftpprefix' => [
			'title' => 'Prefix FTP',
			'description' => 'Quin prefix han de tenir els comptes ftp?<br/><b>Si canvies això, també hauràs de canviar la consulta SQL Quota al fitxer de configuració del servidor FTP en cas que l\'utilitzis</b>. '
		],
		'documentroot_prefix' => [
			'title' => 'Directori d\'inici',
			'description' => 'On s\'han d\'emmagatzemar tots els directoris d\'inici?'
		],
		'logfiles_directory' => [
			'title' => 'Directori Logfiles',
			'description' => 'On s\'han d\'emmagatzemar tots els fitxers de registre?'
		],
		'logfiles_script' => [
			'title' => 'Script personalitzat per enviar els fitxers de registre',
			'description' => 'Pot especificar un script aquí i utilitzar els marcadors de posició <strong>{LOGFILE}, {DOMAIN} i {CUSTOMER}</strong> si cal. En cas que vulgui utilitzar-lo, ha d\'activar també l\'opció <strong>Pipe webserver logfiles</strong>. No cal el prefix pipe.'
		],
		'logfiles_format' => [
			'title' => 'Format de registre d\'accés',
			'description' => 'Introduïu aquí un format de registre personalitzat d\'acord amb les especificacions del vostre servidor web, deixi buit per defecte. Depenent del seu format, la cadena ha d\'estar entre cometes.<br/>Si s\'utilitza amb nginx, es veurà com a <i>log_format</i> <i>frx_custom</i> <i> {CONFIGURED_VALUE}</i >.<br/>Si s\'utilitza amb Apache, es veurà com a <i>LogFormat {CONFIGURED_VALUE} frx_custom</i>.<br/><strong>Atenció</strong>: No es comprovarà si el codi conté errors. Si conté errors, el servidor web podria no tornar a arrencar!'
		],
		'logfiles_type' => [
			'title' => 'Tipus de registre d\'accés',
			'description' => 'Trieu aquí entre <strong>combinat</strong> o <strong>vhost_combinat</strong>.'
		],
		'logfiles_piped' => [
			'title' => 'Canalitzar els fitxers de registre del servidor web a l\'script especificat (veure a dalt)',
			'description' => 'Si utilitzeu un script personalitzat per als fitxers de registre, haureu d\'activar-lo perquè s\'executi.'
		],
		'ipaddress' => [
			'title' => 'Adreça IP',
			'description' => 'Quina és l\'adreça IP principal d\'aquest servidor?'
		],
		'hostname' => [
			'title' => 'Nom de host',
			'description' => 'Quin és el nom de host d\'aquest servidor?'
		],
		'apachereload_command' => [
			'title' => 'Ordre de recàrrega del servidor web',
			'description' => 'Quina és l\'ordre del servidor web per recarregar els fitxers de configuració?'
		],
		'bindenable' => [
			'title' => 'Habilitar servidor de noms',
			'description' => 'Aquí es pot habilitar i deshabilitar globalment el servidor de noms.'
		],
		'bindconf_directory' => [
			'title' => 'Directori de configuració del servidor DNS',
			'description' => 'On s\'han de desar els fitxers de configuració del servidor DNS?'
		],
		'bindreload_command' => [
			'title' => 'Ordre de recàrrega del servidor DNS',
			'description' => 'Quina és la comanda per recarregar el dimoni del servidor DNS?'
		],
		'vmail_uid' => [
			'title' => 'Mails-UID',
			'description' => 'Quin UserID han de tenir els correus?'
		],
		'vmail_gid' => [
			'title' => 'Mails-GID',
			'description' => 'Quin GroupID ha de tenir Mails?'
		],
		'vmail_homedir' => [
			'title' => 'Mails-homedir',
			'description' => 'On s\'haurien d\'emmagatzemar tots els correus?'
		],
		'adminmail' => [
			'title' => 'Remitent',
			'description' => 'Quina és l\'adreça del remitent per als correus electrònics enviats des del Panell?'
		],
		'phpmyadmin_url' => [
			'title' => 'URL de phpMyAdmin',
			'description' => 'Quina és la URL de phpMyAdmin? (ha de començar per http(s)://)'
		],
		'webmail_url' => [
			'title' => 'URL de Webmail',
			'description' => 'Quina és la URL de webmail? (ha de començar per http(s)://)'
		],
		'webftp_url' => [
			'title' => 'URL de WebFTP',
			'description' => 'Quina és la URL de WebFTP? (ha de començar per http(s)://)'
		],
		'language' => [
			'description' => 'Quin és el llenguatge estàndard del vostre servidor?'
		],
		'maxloginattempts' => [
			'title' => 'Nombre màxim d\'intents d\'inici de sessió',
			'description' => 'Nombre màxim d\'intents d\'inici de sessió després dels quals es desactiva el compte.'
		],
		'deactivatetime' => [
			'title' => 'Temps de desactivació',
			'description' => 'Temps (segons) que es desactiva un compte després de massa intents d\'inici de sessió.'
		],
		'pathedit' => [
			'title' => 'Tipus d\'entrada de ruta',
			'description' => 'S\'ha de seleccionar una ruta amb un menú desplegable o amb un camp d\'entrada?'
		],
		'nameservers' => [
			'title' => 'Servidors de noms',
			'description' => 'Una llista separada per comes que conté els noms de host de tots els servidors de noms. El primer serà el principal.'
		],
		'mxservers' => [
			'title' => 'Servidors MX',
			'description' => 'Una llista separada per comes que conté un parell d\'un nombre i un nom de sistema principal separats per espais en blanc (per exemple, \'10 mx.exemple.com\') que conté els servidors mx.'
		],
		'paging' => [
			'title' => 'Entrades per pàgina',
			'description' => 'Quantes entrades es mostraran a una pàgina? (0 = desactivar la paginació)'
		],
		'defaultip' => [
			'title' => 'IP/Port per defecte',
			'description' => 'Seleccioni totes les adreces IP que voleu utilitzar com a predeterminades per als nous dominis.'
		],
		'defaultsslip' => [
			'title' => 'IP/Port SSL per defecte',
			'description' => 'Seleccioni totes les adreces IP amb ssl habilitat que voleu utilitzar per defecte per als nous dominis'
		],
		'phpappendopenbasedir' => [
			'title' => 'Rutes a afegir a OpenBasedir',
			'description' => 'Aquestes rutes (separades per dos punts) s\'afegiran a la declaració OpenBasedir a cada contenidor vHost.'
		],
		'natsorting' => [
			'title' => 'Utilitzar ordenació humana natural a la vista de llista',
			'description' => 'Ordena les llistes com a web1 -> web2 -> web11 en lloc de web1 -> web11 -> web2.'
		],
		'deactivateddocroot' => [
			'title' => 'Docroot per a usuaris desactivats',
			'description' => 'Quan un usuari és desactivat aquesta ruta és utilitzada com el seu docroot. Deixar buit per no crear cap vHost.'
		],
		'mailpwcleartext' => [
			'title' => 'Desar també les contrasenyes dels comptes de correu sense xifrar a la base de dades',
			'description' => 'Si aquesta opció està activada, totes les contrasenyes seran guardades sense encriptar (text clar, llegible per a qualsevol amb accés a la base de dades) a la taula mail_users. Activeu aquesta opció només si voleu utilitzar SASL.'
		],
		'ftpdomain' => [
			'title' => 'Comptes FTP @domini',
			'description' => 'Els clients poden crear comptes FTP user@customerdomain?'
		],
		'mod_fcgid' => [
			'title' => 'Activar FCGID',
			'description' => 'Utilitzi això per executar PHP amb el compte d\'usuari corresponent.<br/><br/><b>Això necessita una configuració especial del servidor web per a Apache, vegeu <a target="_blank" href="https://docs.froxlor.org/latest/admin-guide/configuration/fcgid/">FCGID - manual</a></b>',
			'configdir' => [
				'title' => 'Directori de configuració',
				'description' => 'On s\'han de desar tots els fitxers de configuració fcgid? Si no utilitzeu un binari suexec autocompilat, que és la situació normal, aquesta ruta ha d\'estar sota /var/www/<br/><br/><div class="text-danger">NOTA: El contingut d\'aquesta carpeta s\'esborra regularment, així que eviteu emmagatzemar dades allà manualment.</div>'
			],
			'tmpdir' => [
				'title' => 'Directori temporal',
				'description' => 'On s\'han d\'emmagatzemar els directoris temporals'
			],
			'starter' => [
				'title' => 'Processos per domini',
				'description' => 'Quants processos s\'haurien d\'iniciar/permetre per domini? Es recomana el valor 0 perquè PHP gestionarà llavors la quantitat de processos per si mateix de forma molt eficient.'
			],
			'wrapper' => [
				'title' => 'Wrapper en Vhosts',
				'description' => 'Com s\'ha d\'incloure el wrapper als Vhosts'
			],
			'peardir' => [
				'title' => 'Directoris globals de PEAR',
				'description' => 'Quins directoris globals de PEAR han de ser reemplaçats a cada configuració php.ini? Els directoris diferents han d\'estar separats per dos punts.'
			],
			'maxrequests' => [
				'title' => 'Nombre màxim de peticions per domini',
				'description' => 'Quantes peticions cal permetre per domini?'
			],
			'defaultini' => 'Configuració PHP per defecte per a nous dominis',
			'defaultini_ownvhost' => 'Configuració PHP per defecte per a froxlor-vHost',
			'idle_timeout' => [
				'title' => 'Temps d\'espera',
				'description' => 'Configuració de temps d\'espera per a FastCGI Mod.'
			]
		],
		'sendalternativemail' => [
			'title' => 'Utilitzar una adreça de correu electrònic alternativa',
			'description' => 'Enviar la contrasenya a una adreça diferent durant la creació del compte de correu electrònic.'
		],
		'apacheconf_vhost' => [
			'title' => 'Fitxer/nom de directori de configuració del servidor web vHost',
			'description' => 'On s\'ha de desar la configuració del vHost? Podeu especificar aquí un fitxer (tots els vHosts en un fitxer) o un directori (cada vHost al vostre propi fitxer).'
		],
		'apacheconf_diroptions' => [
			'title' => 'Fitxer/nom de directori de configuració de diroptions del servidor web',
			'description' => 'On s\'ha d\'emmagatzemar la configuració de diroptions? Podeu especificar un fitxer (totes les diroptions en un fitxer) o directori (cada diroption en el vostre propi fitxer) aquí.'
		],
		'apacheconf_htpasswddir' => [
			'title' => 'Nom de directori per a htpasswd Webserver',
			'description' => 'On s\'han de desar els fitxers htpasswd per a la protecció de directoris?'
		],
		'mysql_access_host' => [
			'title' => 'MySQL-Access-Hosts',
			'description' => 'Una llista separada per comes dels hosts des dels quals s\'ha de permetre als usuaris connectar-se al servidor MySQL. Per permetre una subxarxa és vàlida la sintaxi netmask o cidr.'
		],
		'webalizer_quiet' => [
			'title' => 'Sortida de Webalizer',
			'description' => 'Verbositat del programa webalizer'
		],
		'logger' => [
			'enable' => 'Registre activat/desactivat',
			'severity' => 'Nivell de registre',
			'types' => [
				'title' => 'Tipus de registre',
				'description' => 'Especifiqueu els tipus de registre. Per seleccionar diversos tipus, mantingueu premuda la tecla CTRL mentre selecciona.<br/>Els tipus de registre disponibles són: syslog, file, mysql'
			],
			'logfile' => [
				'title' => 'Nom del fitxer de registre',
				'description' => 'Només s\'utilitza si el log-type inclou "file". Aquest fitxer es crearà a froxlor/logs/. Aquesta carpeta està protegida contra l\'accés públic.'
			],
			'logcron' => 'Log cronjobs',
			'logcronoption' => [
				'never' => 'Mai',
				'once' => 'Un cop',
				'always' => 'Sempre'
			]
		],
		'ssl' => [
			'use_ssl' => [
				'title' => 'Activar ús de SSL',
				'description' => 'Marqui aquesta opció si vol utilitzar SSL per al seu servidor web'
			],
			'ssl_cert_file' => [
				'title' => 'Ruta al certificat SSL',
				'description' => 'Especifiqui la ruta incloent el nom del fitxer .crt o .pem (certificat principal)'
			],
			'openssl_cnf' => 'Valors predeterminats per crear el fitxer Cert',
			'ssl_key_file' => [
				'title' => 'Ruta al fitxer de claus SSL',
				'description' => 'Especifiqui la ruta incloent el nom de fitxer per al fitxer de clau privada (.key principalment)'
			],
			'ssl_ca_file' => [
				'title' => 'Ruta al certificat SSL CA (opcional)',
				'description' => 'Autenticació del client, configuri això només si sap el que és.'
			],
			'ssl_cipher_list' => [
				'title' => 'Configuri els xifrats SSL permesos',
				'description' => 'Aquesta és una llista de xifradors que vol (o no vol) utilitzar quan parli SSL. Per a una llista de xifradors i com incloure\'ls/excloure\'ls, vegeu les seccions "CIPHER LIST FORMAT" i "CIPHER STRINGS" a <a href="https://www.openssl.org/docs/manmaster/man1/openssl-ciphers.html">la pàgina man de xifradors</a>.<br/><br/><b>El valor per defecte és:</b><pre>ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305</pre>'
			],
			'apache24_ocsp_cache_path' => [
				'title' => 'Apache 2.4: ruta a la memòria cau de grapat OCSP',
				'description' => 'Configura la memòria cau utilitzada per emmagatzemar les respostes OCSP que s\'inclouen als handshakes TLS.'
			],
			'ssl_protocols' => [
				'title' => 'Configurar la versió del protocol TLS',
				'description' => 'Aquesta és una llista de protocols ssl que vol (o no vol) utilitzar quan utilitzeu SSL. <b>Nota:</b> És possible que alguns navegadors antics no admetin les versions de protocol més recents.<br/><br/><b>El valor per defecte és:</b><pre>TLSv1.2</pre>'
			],
			'tlsv13_cipher_list' => [
				'title' => 'Configurar xifrats explícits TLSv1.3 si es fan servir',
				'description' => 'Aquesta és una llista de xifradors que voleu (o no voleu) utilitzar quan parleu TLSv1.3. Per a una llista de xifradors i com incloure\'ls/excloure\'ls, vegeu <a href="https://wiki.openssl.org/index.php/TLS1.3">els documents per a TLSv1.3</a>.<br/ ><br/><b>El valor per defecte és buit</b>'
			]
		],
		'default_vhostconf' => [
			'title' => 'Configuració vHost per defecte',
			'description' => 'El contingut d\'aquest camp s\'inclourà directament en aquest contenidor ip/port vHost. Podeu utilitzar les variables següents:<br/><code>{DOMAIN}</code>, <code>{DOCROOT}</code>, <code>{CUSTOMER}</code>, <code>{IP}< /code>, <code>{PORT}</code>, <code>{SCHEME}</code>, <code>{FPMSOCKET}</code> (si escau)<br/> Atenció: No es comprovarà si el codi conté errors. Si conté errors, el servidor web podria no tornar a arrencar!'
		],
		'apache_globaldiropt' => [
			'title' => 'Opcions de directori per a customer-prefix',
			'description' => 'El contingut d\'aquest camp s\'inclourà a la configuració d\'apache 05_froxlor_dirfix_nofcgid.conf. Si està buit, es farà servir el valor per defecte:<br/><br/>apache >=2.4<br/><code>Require all granted<br/>AllowOverride All</code><br/><br/>apache <=2.2<br/><code>Order allow,deny<br/>allow from all</code>'
		],
		'default_vhostconf_domain' => [
			'description' => 'El contingut d\'aquest camp s\'inclou directament al contenidor vHost del domini. Podeu utilitzar les variables següents:<br/><code>{DOMAIN}</code>, <code>{DOCROOT}</code>, <code>{CUSTOMER}</code>, <code>{IP}< /code>, <code>{PORT}</code>, <code>{SCHEME}</code>, <code>{FPMSOCKET}</code> (si escau)<br/> Atenció: No es comprovarà si el codi conté errors. Si conté errors, el servidor web podria no tornar a arrencar!'
		],
		'decimal_places' => 'Nombre de decimals a la sortida de trànsit/espai web',
		'selfdns' => [
			'title' => 'Configuració dns del domini del client'
		],
		'selfdnscustomer' => [
			'title' => 'Permetre als clients editar la configuració dns del domini'
		],
		'unix_names' => [
			'title' => 'Utilitzar noms d\'usuari compatibles amb UNIX',
			'description' => 'Permet utilitzar <strong>-</strong> i <strong>_</strong> als noms d\'usuari si <strong>No</strong>'
		],
		'allow_password_reset' => [
			'title' => 'Permetre que els clients restableixin la contrasenya',
			'description' => 'Els clients poden restablir la contrasenya i se\'ls enviarà un enllaç d\'activació a la seva adreça de correu electrònic.'
		],
		'allow_password_reset_admin' => [
			'title' => 'Permetre que els administradors restableixin la contrasenya',
			'description' => 'Els administradors/revenedors poden restablir la contrasenya i se\'ls enviarà un enllaç d\'activació a la seva adreça de correu electrònic.'
		],
		'mail_quota' => [
			'title' => 'Quota de bústia',
			'description' => 'La quota per defecte per a les noves bústies creades (MegaByte).'
		],
		'mail_quota_enabled' => [
			'title' => 'Utilitzar mailbox-quota per a clients',
			'description' => 'Activar per utilitzar quotes a les bústies de correu. Per defecte és <b>No</b> ja que això requereix una configuració especial.',
			'removelink' => 'Faci clic aquí per esborrar totes les quotes dels comptes de correu.',
			'enforcelink' => 'Faci clic aquí per aplicar la quota per defecte a tots els comptes de correu dels usuaris.'
		],
		'index_file_extension' => [
			'description' => 'Quina extensió de fitxer s\'ha d\'utilitzar per al fitxer d\'índex als directoris de clients acabats de crear? Aquesta extensió de fitxer s\'utilitzarà si vosté o un dels seus administradors ha creat la seva pròpia plantilla de fitxer d\'índex.',
			'title' => 'Extensió de fitxer per al fitxer d\'índex en directoris de clients acabats de crear'
		],
		'session_allow_multiple_login' => [
			'title' => 'Permetre l\'inici de sessió múltiple',
			'description' => 'Si s\'activa, un usuari pot iniciar sessió diverses vegades.'
		],
		'panel_allow_domain_change_admin' => [
			'title' => 'Permetre moure dominis entre administradors',
			'description' => 'Si està activat pot canviar l\'admin d\'un domini a domainsettings.<br/><b>Atenció:</b> Si un client no està assignat al mateix administrador que el domini, l\'administrador pot veure tots els altres dominis d\'aquest client!'
		],
		'panel_allow_domain_change_customer' => [
			'title' => 'Permetre moure dominis entre clients',
			'description' => 'Si està activat pots canviar el client d\'un domini a domainsettings.<br/><b>Atenció:</b> froxlor canvia el documentroot al homedir per defecte del nou client (+ carpeta de domini si està activat)'
		],
		'specialsettingsforsubdomains' => [
			'description' => 'En cas afirmatiu, aquests paràmetres personalitzats de vHost s\'afegiran a tots els subdominis; en cas negatiu, s\'eliminaran els ajustaments especials de subdomini.'
		],
		'panel_password_min_length' => [
			'title' => 'Longitud mínima de contrasenya',
			'description' => 'Aquí pot establir una longitud mínima per a les contrasenyes. 0\' vol dir que no es requereix longitud mínima.'
		],
		'system_store_index_file_subs' => [
			'title' => 'Emmagatzemar el fitxer índex per defecte també a les noves subcarpetes',
			'description' => 'Si s\'activa, el fitxer d\'índex per defecte s\'emmagatzema a cada ruta de subdomini creada recentment (no si la carpeta ja existeix).'
		],
		'adminmail_return' => [
			'title' => 'Adreça de resposta',
			'description' => 'Defineix una adreça de correu electrònic com a adreça de resposta per als correus electrònics enviats pel panell.'
		],
		'adminmail_defname' => 'Nom del remitent del correu electrònic del panell',
		'stdsubdomainhost' => [
			'title' => 'Subdomini estàndard del client',
			'description' => 'Quin nom de host s\'ha de fer servir per crear subdominis estàndard per al client. Si està buit, s\'utilitza el nom de sistema principal del sistema.'
		],
		'awstats_path' => 'Ruta a AWStats \'awstats_buildstaticpages.pl\'',
		'awstats_conf' => 'Ruta de configuració d\'AWStats',
		'defaultttl' => 'TTL de domini per a bind en segons (per defecte \'604800\' = 1 setmana)',
		'defaultwebsrverrhandler_enabled' => 'Habilitar documents d\'error per defecte per a tots els clients',
		'defaultwebsrverrhandler_err401' => [
			'title' => 'Fitxer/URL per a l\'error 401',
			'description' => '',
		],
		'defaultwebsrverrhandler_err403' => [
			'title' => 'Fitxer/URL per a l\'error 403',
			'description' => '',
		],
		'defaultwebsrverrhandler_err404' => 'Fitxer/URL per a l\'error 404',
		'defaultwebsrverrhandler_err500' => [
			'title' => 'Fitxer/URL per a l\'error 500',
			'description' => '',
		],
		'ftpserver' => [
			'desc' => 'Si seleccioneu pureftpd, els fitxers .ftpquota per a quotes d\'usuari es creen i s\'actualitzen diàriament'
		],
		'customredirect_enabled' => [
			'title' => 'Permetre redireccionaments de clients',
			'description' => 'Permetre als clients triar el codi http-status per a les redireccions que es faran servir'
		],
		'customredirect_default' => [
			'title' => 'Redirecció per defecte',
			'description' => 'Estableix el codi de redirecció per defecte que s\'utilitzarà si el client no ho estableix per si mateix'
		],
		'mail_also_with_mxservers' => 'Crear mail-, imap-, pop3- y smtp-"A record" també amb MX-Servers set',
		'froxlordirectlyviahostname' => 'Accedir a froxlor directament a través del nom de host',
		'panel_password_regex' => [
			'title' => 'Expressió regular per a contrasenyes',
			'description' => 'Aquí pot establir una expressió regular per a la complexitat de les contrasenyes.<br/>Buit = cap requeriment'
		],
		'mod_fcgid_ownvhost' => [
			'title' => 'Habilita FCGID per al vHost de froxlor',
			'description' => 'Si està habilitat, froxlor també s\'executarà sota un usuari local'
		],
		'perl' => [
			'suexecworkaround' => [
				'title' => 'Habilitar solució SuExec',
				'description' => 'Habilitar només si els directoris del client no estan dins de la ruta apache suexec.<br/>Si està habilitat, froxlor generarà un enllaç simbòlic des del directori del client habilitat per a perl + /cgi-bin/ a la ruta donada.<br />Tingueu en compte que perl només funcionarà al subdirectori de carpetes /cgi-bin/ i no a la carpeta en si (com ho fa sense aquesta solució!)'
			],
			'suexeccgipath' => [
				'title' => 'Ruta per als enllaços simbòlics de directori habilitats per a perl del client',
				'description' => 'Només heu de configurar això si la solució de SuExec està activada.<br/>ATENCIÓ: Assegureu-vos que aquesta ruta està dins de la ruta de suexec o en cas contrari aquesta solució és inútil.'
			]
		],
		'awstats_awstatspath' => 'Ruta a AWStats \'awstats.pl\'.',
		'awstats_icons' => [
			'title' => 'Ruta a la carpeta d\'icones d\'AWstats',
			'description' => 'Exemple: /usr/share/awstats/htdocs/icon/'
		],
		'login_domain_login' => 'Permetre login amb dominis',
		'perl_server' => [
			'title' => 'Ubicació del socket del servidor Perl',
			'description' => 'Pot trobar una guia senzilla a: <a target="blank" href="https://www.nginx.com/resources/wiki/start/topics/examples/fcgiwrap/">nginx.com</a>'
		],
		'nginx_php_backend' => [
			'title' => 'Nginx PHP backend',
			'description' => 'aquí és on el procés PHP està escoltant peticions de nginx, pot ser un socket unix de combinació ip:port<br/>*NO s\'utilitza amb php-fpm'
		],
		'phpreload_command' => [
			'title' => 'Ordre de reinici de PHP',
			'description' => 's\'utilitza per recarregar el backend PHP si se n\'utilitza algun<br/>Per defecte: en blanc<br/>*NO s\'utilitza amb php-fpm'
		],
		'phpfpm' => [
			'title' => 'Habilitar php-fpm',
			'description' => '<b>Això necessita una configuració especial del servidor web veure <a target="_blank" href="https://docs.froxlor.org/latest/admin-guide/configuration/php-fpm/">manual PHP-FPM</a></b>'
		],
		'phpfpm_settings' => [
			'configdir' => 'Directori de configuració de php-fpm',
			'aliasconfigdir' => 'Directori Àlies de configuració de php-fpm',
			'reload' => 'Ordre de reinici de php-fpm',
			'pm' => 'Control del gestor de processos (pm)',
			'max_children' => [
				'title' => 'Nombre de processos fill',
				'description' => 'El nombre de processos fill a ser creats quan pm està en \'static\' i el nombre màxim de processos fill a ser creats quan pm està en \'dynamic/ondemand\'<br/>Equivalent a PHP_FCGI_CHILDREN'
			],
			'start_servers' => [
				'title' => 'El nombre de processos fill creats a l\'inici',
				'description' => 'Nota: Només es fa servir quan pm està configurat com a \'dynamic'
			],
			'min_spare_servers' => [
				'title' => 'El nombre mínim desitjat de processos de servidor inactius',
				'description' => 'Nota: Només es fa servir quan pm és \'dynamic\'<br/>Nota: Obligatori quan pm és \'dynamic'
			],
			'max_spare_servers' => [
				'title' => 'El nombre màxim desitjat de processos inactius de servidor',
				'description' => 'Nota: només s\'utilitza quan pm té el valor "dynamic".<br/>Nota: obligatori quan pm té el valor "dynamic".'
			],
			'max_requests' => [
				'title' => 'Peticions per fill abans de respawning',
				'description' => 'Per a un processament infinit de peticions especifiqueu \'0\'. Equivalent a PHP_FCGI_MAX_REQUESTS.'
			],
			'idle_timeout' => [
				'title' => 'Temps d\'espera',
				'description' => 'Configuració de temps d\'espera per a PHP FPM FastCGI.'
			],
			'ipcdir' => [
				'title' => 'Directori IPC FastCGI',
				'description' => 'El directori on els sockets php-fpm seran emmagatzemats pel servidor web.<br/>Aquest directori ha de ser llegible per al servidor web.'
			],
			'limit_extensions' => [
				'title' => 'Extensions permeses',
				'description' => 'Limita les extensions de l\'script principal que FPM permetrà analitzar. Això pot evitar errors de configuració al servidor web. Només heu de limitar FPM a extensions .php per evitar que usuaris maliciosos utilitzin altres extensions per executar codi php. Valor per defecte: .php'
			],
			'envpath' => 'Rutes per afegir a l\'entorn PATH. Deixeu-lo buit per a cap variable d\'entorn PATH',
			'override_fpmconfig' => 'Anul·lar la configuració de FPM-daemon (pm, max_children, etc.)',
			'override_fpmconfig_addinfo' => '<br/><span class="text-danger">Només es fa servir si "Override FPM-daemon settings" està en "Sí"</span>',
			'restart_note' => 'Atenció: La configuració no serà revisada per errors. Si conté errors, PHP-FPM podria no tornar a arrencar.',
			'custom_config' => [
				'title' => 'Configuració personalitzada',
				'description' => 'Afegeix configuració personalitzada a cada instància de versió de PHP-FPM, per exemple <i>pm.status_path = /status</i> per a monitoratge. Les variables de sota poden ser utilitzades aquí. <strong>Atenció: La configuració no serà revisada per errors. Si conté errors, PHP-FPM podria no tornar a arrencar!</strong>'
			],
			'allow_all_customers' => [
				'title' => 'Assigneu aquesta configuració a tots els clients existents',
				'description' => 'Establiu-lo a "cert" si voleu assignar aquesta configuració a tots els clients existents perquè puguin utilitzar-la. Aquesta configuració no és permanent, però es pot executar diverses vegades.'
			]
		],
		'report' => [
			'report' => 'Habilitar l\'enviament d\'informes sobre l\'ús de la web i el trànsit',
			'webmax' => [
				'title' => 'Nivell d\'advertència en percentatge per a l\'espai web',
				'description' => 'Els valors vàlids són 0-150. Establir aquest valor a 0 desactiva aquest informe.'
			],
			'trafficmax' => [
				'title' => 'Nivell d\'advertència en percentatge per al trànsit',
				'description' => 'Els valors vàlids són de 0 a 150. El valor 0 desactiva aquest informe.'
			]
		],
		'dropdown' => 'Desplegable',
		'manual' => 'Manual',
		'default_theme' => 'Tema per defecte',
		'validate_domain' => 'Validar noms de domini',
		'diskquota_enabled' => 'Quota activada?',
		'diskquota_repquota_path' => [
			'description' => 'Ruta a repquota'
		],
		'diskquota_quotatool_path' => [
			'description' => 'Ruta a quotatool'
		],
		'diskquota_customer_partition' => [
			'description' => 'Partició en què s\'emmagatzemen els fitxers del client'
		],
		'vmail_maildirname' => [
			'title' => 'Nom del maildir',
			'description' => 'Directori maildir al compte de l\'usuari. Normalment \'Maildir\', en algunes implementacions \'.maildir\', i directament al directori de l\'usuari si es deixa en blanc.'
		],
		'catchall_enabled' => [
			'title' => 'Utilitzar Catchall',
			'description' => 'Vol proporcionar als seus clients la funció catchall?'
		],
		'apache_24' => [
			'title' => 'Utilitzi les modificacions per Apache 2.4',
			'description' => '<strong class="text-danger">ATENCIÓ:</strong> utilitzeu-lo només si teniu instal·lada la versió 2.4 o superior d\'apache<br/>en cas contrari el vostre servidor web no podrà arrencar'
		],
		'nginx_fastcgiparams' => [
			'title' => 'Ruta al fitxer fastcgi_params',
			'description' => 'Especifiqui la ruta al fitxer fastcgi_params de nginx incloent el nom de fitxer'
		],
		'documentroot_use_default_value' => [
			'title' => 'Utilitzar el nom de domini com a valor per defecte per a la ruta DocumentRoot',
			'description' => 'Si està habilitat i la ruta DocumentRoot és buida, el valor per defecte serà el (sub)nom de domini.<br/><br/>Exemples: <br/>/var/clients/nom_client/exemple.com/<br />/var/clients/nom_client/subdomini.exemple.com/'
		],
		'panel_phpconfigs_hidesubdomains' => [
			'title' => 'Amagar subdominis a la vista general de configuració PHP',
			'description' => 'Si s\'activa, els subdominis dels clients no es mostraran a la vista general de configuracions PHP, només es mostrarà el número de subdominis.<br/><br/>Nota: Això només serà visible si heu activat FCGID o PHP-FPM .'
		],
		'panel_phpconfigs_hidestdsubdomain' => [
			'title' => 'Amagar subdominis estàndard a la vista general de configuracions PHP',
			'description' => 'Si s\'activa, els subdominis estàndard dels clients no es mostraran a la vista general de configuracions php<br/><br/>Nota: Això només serà visible si heu activat FCGID o PHP-FPM.'
		],
		'passwordcryptfunc' => [
			'title' => 'Triï el mètode de xifratge de contrasenyes a utilitzar'
		],
		'systemdefault' => 'Sistema per defecte',
		'panel_allow_theme_change_admin' => 'Permetre als administradors canviar el tema',
		'panel_allow_theme_change_customer' => 'Permetre als clients canviar el tema',
		'axfrservers' => [
			'title' => 'Servidors AXFR',
			'description' => 'Una llista separada per comes d\'adreces IP permeses per transferir (AXFR) zones dns.'
		],
		'powerdns_mode' => [
			'title' => 'Mode de funcionament PowerDNS',
			'description' => 'Seleccioni el mode PoweDNS: Natiu si no es necessita replicació DNS (Predeterminat) / Mestre si es necessita replicació DNS.'
		],
		'customerssl_directory' => [
			'title' => 'Webserver customer-ssl certificates-directory',
			'description' => 'On s\'han de crear els certificats ssl especificats pel client?<br/><br/><div class="text-danger">NOTA: El contingut d\'aquesta carpeta s\'esborra amb regularitat, així que eviteu emmagatzemar dades allà manualment. </div>'
		],
		'allow_error_report_admin' => [
			'title' => 'Permetre als administradors/revenedors informar d\'errors a la base de dades a froxlor',
			'description' => 'Nota: Mai ens enviïs dades personals (de clients)!'
		],
		'allow_error_report_customer' => [
			'title' => 'Permetre als clients informar d\'errors a la base de dades a froxlor',
			'description' => 'Nota: Mai ens enviïs dades personals (de clients)!'
		],
		'mailtraffic_enabled' => [
			'title' => 'Analitzar el trànsit de correu',
			'description' => 'Permetre l\'anàlisi dels registres del servidor de correu per calcular el trànsit'
		],
		'mdaserver' => [
			'title' => 'Tipus de MDA',
			'description' => 'Tipus de servidor de lliurament de correu'
		],
		'mdalog' => [
			'title' => 'Registre MDA',
			'description' => 'Fitxer de registre del Mail Delivery Server'
		],
		'mtaserver' => [
			'title' => 'Tipus de MTA',
			'description' => 'Tipus d\'agent de transferència de correu'
		],
		'mtalog' => [
			'title' => 'Registre MTA',
			'description' => 'Fitxer de registre de l\'agent de transferència de correu'
		],
		'system_cronconfig' => [
			'title' => 'Fitxer de configuració de cron',
			'description' => 'Ruta al fitxer de configuració del servei cron. Aquest fitxer serà actualitzat regularment i automàticament per froxlor.<br/>Nota: Si us plau <b>assegureu-vos</b> d\'utilitzar el mateix nom de fitxer que per al froxlor cronjob principal (per defecte: /etc/cron.d/froxlor)!<br/><br/>Si utilitzeu <b>FreeBSD</b>, si us plau especifiqueu <i>/etc/crontab</i> aquí!'
		],
		'system_crondreload' => [
			'title' => 'Ordre de recàrrega pel domini Cron',
			'description' => 'Especifiqui l\'ordre a executar per recarregar el dimoni cron del vostre sistema'
		],
		'system_croncmdline' => [
			'title' => 'Ordre d\'execució de cron (php-binari)',
			'description' => 'Ordre per executar les nostres tasques cron. Canvieu-ho només si sabeu el que esteu fent (per defecte: "/usr/bin/nice -n 5 /usr/bin/php -q").'
		],
		'system_cron_allowautoupdate' => [
			'title' => 'Permetre actualitzar automàticament la base de dades',
			'description' => '<div class="text-danger"><b>ATENCIÓ:</b></div> Aquesta configuració permet al cronjob saltar-se la comprovació de versió dels fitxers froxlors i la base de dades i executa l\'actualització de la base de dades en cas que passi un desajust de versió.<br/><br/><div class= "text-danger">Auto-update sempre establirà valors per defecte per a noves configuracions o canvis. Això pot no ser sempre adequat per al vostre sistema. Si us plau, penseu-ho dues vegades abans d\'activar aquesta opció</div>'
		],
		'dns_createhostnameentry' => 'Crear bind-zone/config per al nom de host del sistema',
		'panel_password_alpha_lower' => [
			'title' => 'Minúscules',
			'description' => 'La contrasenya ha de contenir com a mínim una lletra minúscula (a-z).'
		],
		'panel_password_alpha_upper' => [
			'title' => 'Majúscules',
			'description' => 'La contrasenya ha de contenir com a mínim una lletra majúscula (A-Z).'
		],
		'panel_password_numeric' => [
			'title' => 'Números',
			'description' => 'La contrasenya ha de contenir almenys un número (0-9).'
		],
		'panel_password_special_char_required' => [
			'title' => 'Caràcter especial',
			'description' => 'La contrasenya ha de contenir com a mínim un dels caràcters definits a continuació.'
		],
		'panel_password_special_char' => [
			'title' => 'Llista de caràcters especials',
			'description' => 'Es requereix un d\'aquests caràcters si s\'estableix l\'opció anterior.'
		],
		'apache_itksupport' => [
			'title' => 'Modificacions d\'ús per Apache ITK-MPM',
			'description' => '<strong class="text-danger">ATENCIÓ:</strong> utilitzeu-la només si teniu apache itk-mpm habilitat<br/>, altrament el vostre servidor web no es podrà iniciar.'
		],
		'letsencryptca' => [
			'title' => 'Entorn ACME',
			'description' => 'Entorn que s\'utilitzarà per als certificats Let\'s Encrypt / ZeroSSL.'
		],
		'letsencryptchallengepath' => [
			'title' => 'Ruta per als desafiaments Let\'s Encrypt',
			'description' => 'Directori des del qual s\'oferiran els reptes Let\'s Encrypt a través d\'un àlies global.'
		],
		'letsencryptkeysize' => [
			'title' => 'Mida de la clau per a nous certificats Let\'s Encrypt',
			'description' => 'Mida de la clau en Bits per a nous certificats Let\'s Encrypt.'
		],
		'letsencryptreuseold' => [
			'title' => 'Reutilitzar clau Let\'s Encrypt',
			'description' => 'Si s\'activa, s\'utilitzarà la mateixa clau per a cada renovació, altrament es generarà una clau nova cada vegada.'
		],
		'leenabled' => [
			'title' => 'Activar Let\'s Encrypt',
			'description' => 'Si s\'activa, els clients poden deixar que automàticament froxlor generi i renovi certificats ssl Let\'s Encrypt per a dominis amb una IP/port ssl.<br/><br/>Si us plau recorda que necessites anar a través de la configuració del servidor web quan s\'activa perquè aquesta característica necessita una configuració especial.'
		],
		'caa_entry' => [
			'title' => 'Generar registres DNS CAA',
			'description' => 'Genera automàticament registres CAA per a dominis habilitats per a SSL que utilitzen Let\'s Encrypt.'
		],
		'caa_entry_custom' => [
			'title' => 'Registres DNS CAA addicionals',
			'description' => 'DNS Certification Authority Authorization (CAA) és un mecanisme de política de seguretat a Internet que permet als titulars de noms de domini indicar a les autoritats de certificació<br/>si estan autoritzades a emetre certificats digitals per a un nom de domini concret. Ho fa mitjançant un nou registre de recursos del sistema de noms de domini (DNS) "CAA".<br/><br/>El contingut d\'aquest camp s\'inclourà a la zona DNS directament (cada línia dóna lloc a un registre CAA ).<br/>Si Let\'s Encrypt està habilitat per a aquest domini, aquesta entrada sempre s\'afegirà automàticament i no caldrà afegir-la manualment:<br/> 0<code>issue "letsencrypt.org"</code> ( Si el domini és un domini comodí, s\'utilitzarà issuewild al seu lloc).<br/>Per habilitar l\'informe d\'incidents, podeu afegir un registre <code>iodef</code>. Un exemple per enviar aquest informe a <code>me@example.com</code> seria:<br/> 0<code>iodef "mailto:me@example.com"</code><br/><br/ ><strong>Atenció:</strong> No es comprovarà si el codi conté errors. Si conté errors, és possible que els vostres registres CAA no funcionin!'
		],
		'backupenabled' => [
  			'title' => 'Activar còpia de seguretat per a clients',
			'description' => 'Si s\'activa, el client podrà programar treballs de còpia de seguretat (cron-backup) que generen un fitxer dins del seu docroot (subdirectori a elecció del client)'
		],
		'dnseditorenable' => [
			'title' => 'Habilitar editor DNS',
			'description' => 'Permet als administradors i als clients gestionar les entrades DNS del domini'
		],
		'dns_server' => [
			'title' => 'Dimoni del servidor DNS',
			'description' => 'Recordi que els dimonis han de ser configurats usant les plantilles de configuració de froxlors'
		],
		'panel_customer_hide_options' => [
			'title' => 'Amagar elements de menú i gràfics de trànsit al panell de client',
			'description' => 'Seleccioni els elements que vol amagar al panell de client. Per seleccionar diverses opcions, mantingueu premuda la tecla CTRL mentre seleccioneu.'
		],
		'allow_allow_customer_shell' => [
			'title' => 'Permetre als clients habilitar l\'accés shell per a usuaris ftp',
			'description' => '<strong class="text-danger">Atenció: L\'accés Shell permet a l\'usuari executar diversos binaris al vostre sistema. Utilitzeu-lo amb extrema precaució. Si us plau, activeu això només si REALMENT sap el que està fent!!!</strong>'
		],
		'available_shells' => [
			'title' => 'Llista de shells disponibles',
			'description' => 'Llista separada per comes dels intèrprets d\'ordres disponibles perquè el client esculli per als seus usuaris ftp.<br/><br/>Tingueu en compte que l\'intèrpret d\'ordres predeterminat <strong>/bin/false</strong> sempre serà una opció (si està habilitat), fins i tot si aquesta configuració és buida. És el valor per defecte per als usuaris ftp en qualsevol cas.'
		],
		'le_froxlor_enabled' => [
			'title' => 'Activar Let\'s Encrypt per al froxlor vhost',
			'description' => 'Si s\'activa, el froxlor vhost s\'assegurarà automàticament utilitzant un certificat Let\'s Encrypt.'
		],
		'le_froxlor_redirect' => [
			'title' => 'Activar SSL-redirect per a froxlor vhost',
			'description' => 'Si s\'activa, totes les peticions http al vostre froxlor seran redirigides al lloc SSL corresponent.'
		],
		'option_unavailable_websrv' => '<br/><em class="text-danger">Disponible només per a: %s</em>',
		'option_unavailable' => '<br/><em class="text-danger">Opció no disponible degut a altres paràmetres.</em>',
		'letsencryptacmeconf' => [
			'title' => 'Ruta al fragment acme.conf',
			'description' => 'Nom de fitxer del fragment de configuració que permet al servidor web utilitzar el desafiament acme.'
		],
		'mail_use_smtp' => 'Configurar mailer per utilitzar SMTP',
		'mail_smtp_host' => 'Especifiqui el servidor SMTP',
		'mail_smtp_usetls' => 'Activar el xifratge TLS',
		'mail_smtp_auth' => 'Activar l\'autenticació SMTP',
		'mail_smtp_port' => 'Port TCP al qual connectar-se',
		'mail_smtp_user' => 'Nom d\'usuari SMTP',
		'mail_smtp_passwd' => 'Contrasenya SMTP',
		'http2_support' => [
			'title' => 'Suport HTTP2',
			'description' => 'habiliti el suport HTTP2 per a ssl.<br/><em class="text-danger">HABILITAR NOMÉS SI EL SEU WEBSERVER SUPORTA AQUESTA CARACTERÍSTICA (nginx versió 1.9.5+, apache2 versió 2.4.17+)</em>'
		],
		'nssextrausers' => [
			'title' => 'Utilitzar libnss-extrausers en lloc de libnss-mysql',
			'description' => 'No llegir usuaris de la base de dades sinó de fitxers. Si us plau, activa-ho només si ja has realitzat els passos de configuració necessaris (system -><strong class="text-danger">libnss-extrausers).</strong><br/><strong class="text-danger" >Només per a Debian/Ubuntu (o si ha compilat libnss-extrausers vostè mateix!)</strong>'
		],
		'le_domain_dnscheck' => [
			'title' => 'Validar DNS de dominis en utilitzar Let\'s Encrypt',
			'description' => 'Si està activat, froxlor validarà si el domini que sol·licita un certificat Let\'s Encrypt resol almenys una de les adreces ip del sistema.'
		],
		'le_domain_dnscheck_resolver' => [
			'title' => 'Utilitzar un servidor de noms extern per a la validació DNS',
			'description' => 'Si s\'estableix, froxlor utilitzarà aquest DNS per validar els DNS dels dominis quan utilitzeu Let\'s Encrypt. Si està buit, s\'utilitzarà el solucionador DNS per defecte del sistema.'
		],
		'phpsettingsforsubdomains' => [
			'description' => 'En cas afirmatiu s\'actualitzarà el php-config triat a tots els subdominis'
		],
		'leapiversion' => [
			'title' => 'Escollir la implementació ACME de Let\'s Encrypt',
			'description' => 'Actualment només es suporta la implementació ACME v2 per a Let\'s Encrypt.'
		],
		'enable_api' => [
			'title' => 'Habilitar ús d\'API externa',
			'description' => 'Per utilitzar la API froxlor cal activar aquesta opció. Per obtenir informació més detallada, vegeu <a href="https://docs.froxlor.org/latest/api-guide/" target="_new">https://docs.froxlor.org/</a>'
		],
		'api_customer_default' => '"Permetre accés a la API" valor per defecte per a nous clients',
		'dhparams_file' => [
			'title' => 'Fitxer DHParams (intercanvi de claus Diffie-Hellman)',
			'description' => 'Si s\'especifica aquí un fitxer dhparams.pem, s\'inclourà a la configuració del servidor web. Deixeu-lo buit per desactivar-lo.<br/>Exemple: <code>/etc/ssl/webserver/dhparams</code>.pem<br/><br/>Si el fitxer no existeix, es crearà automàticament amb la següent ordre: <code>openssl dhparam -out /etc/ssl/webserver/dhparams.pem 4096</code>. Es recomana crear el fitxer abans d\'especificar-lo aquí, ja que la creació triga força i bloqueja el cronjob.'
		],
		'errorlog_level' => [
			'title' => 'Nivell de registre d\'errors',
			'description' => 'Especifiqui el nivell de registre d\'errors. Per defecte és "warn" per a usuaris apache i "error" per a usuaris nginx.'
		],
		'letsencryptecc' => [
			'title' => 'Emetre certificat ECC / ECDSA',
			'description' => 'Si s\'estableix una mida de clau vàlida, el certificat emès utilitzarà ECC/ECDSA.'
		],
		'froxloraliases' => [
			'title' => 'Àlies de domini per a froxlor vhost',
			'description' => 'Llista separada per comes de dominis per afegir com a àlies de servidor al froxlor vhost'
		],
		'default_sslvhostconf' => [
			'title' => 'SSL per defecte vHost-settings',
			'description' => 'El contingut d\'aquest camp s\'inclourà directament en aquest contenidor ip/port vHost. Podeu utilitzar les variables següents:<br/><code>{DOMAIN}</code>, <code>{DOCROOT}</code>, <code>{CUSTOMER}</code>, <code>{IP}< /code>, <code>{PORT}</code>, <code>{SCHEME}</code>, <code>{FPMSOCKET}</code> (si escau)<br/> Atenció: No es comprovarà si el codi conté errors. Si conté errors, el servidor web podria no tornar a arrencar!'
		],
		'includedefault_sslvhostconf' => 'Incloure configuració de vHost no SSL a SSL-vHost',
		'apply_specialsettings_default' => [
			'title' => 'Valor per defecte per a "Aplicar configuracions especials a tots els subdominis (*.exemple.com)\' en editar un domini'
		],
		'apply_phpconfigs_default' => [
			'title' => 'Valor per defecte per a "Aplicar php-config a tots els subdominis:\' en editar un domini'
		],
		'awstats' => [
			'logformat' => [
				'title' => 'Configuració de LogFormat',
				'description' => 'Si utilitzeu un format de registre personalitzat per al vostre servidor web, necessiteu canviar també l\'awstats LogFormat.<br/>Per defecte és 1. Per a més informació consulta la documentació <a target="_blank" href="https://awstats.sourceforge.io/docs/awstats_config.html#LogFormat">aquí</a>.'
			]
		],
		'hide_incompatible_settings' => 'Amagar configuracions incompatibles',
		'soaemail' => 'Adreça de correu a utilitzar en registres SOA (per defecte l\'adreça del remitent de la configuració del panell si és buida)',
		'imprint_url' => [
			'title' => 'URL a notes legals / impressió',
			'description' => 'Especifiqui una URL al vostre lloc de notes legals / impressió. L\'enllaç serà visible a la pantalla d\'inici de sessió i al peu de pàgina un cop iniciada la sessió.'
		],
		'terms_url' => [
			'title' => 'URL a les condicions d\'ús',
			'description' => 'Especifiqui una URL al vostre lloc de condicions d\'ús. L\'enllaç serà visible a la pantalla d\'inici de sessió i al peu de pàgina en iniciar sessió.'
		],
		'privacy_url' => [
			'title' => 'URL a la política de privadesa',
			'description' => 'Especifiqui una URL al vostre lloc de política de privadesa / lloc d\'impressió. L\'enllaç serà visible a la pantalla d\'inici de sessió i al peu de pàgina en iniciar sessió.'
		],
		'logo_image_header' => [
			'title' => 'Imatge de logotip (capçalera)',
			'description' => 'Carregui la vostra pròpia imatge de logotip perquè es mostri a la capçalera després de l\'inici de sessió (alçada recomanada 30px)'
		],
		'logo_image_login' => [
			'title' => 'Imatge del logotip (inici de sessió)',
			'description' => 'Carregui la vostra pròpia imatge de logotip perquè es mostri durant l\'inici de sessió'
		],
		'logo_overridetheme' => [
			'title' => 'Sobreescriu el logotip definit en el tema per "Logo Image" (Capçalera i Login, veure més a avall)',
			'description' => 'Aquesta opció s\'ha d\'establir com a "cert" si vol utilitzar el logotip que ha carregat; com a alternativa, pot continuar utilitzant les possibilitats basades en el tema "logo_custom.png" i "logo_custom_login.png".'
		],
		'logo_overridecustom' => [
			'title' => 'Sobreescriure el logotip personalitzat (logo_custom.png i logo_custom_login.png) definit al tema per "Imatge del logotip" (Capçalera i Inici de sessió, veure més avall).',
			'description' => 'Estableixi aquest valor a "cert" si vol ignorar els logotips personalitzats específics del tema per a la capçalera i l\'inici de sessió i utilitzar "Logo Image".'
		],
		'createstdsubdom_default' => [
			'title' => 'Valor preseleccionat per a "Crear subdomini estàndard" en crear un client',
			'description' => ''
		],
		'froxlorusergroup' => [
			'title' => 'Grup de sistema personalitzat per a tots els usuaris del client',
			'description' => 'Cal utilitzar libnss-extrausers (system-settings) perquè això tingui efecte. Un valor buit omet la creació o elimina el grup existent.'
		],
		'acmeshpath' => [
			'title' => 'Ruta a acme.sh',
			'description' => 'Establiu-lo on s\'instal·la acme.sh, incloent l\'script acme.sh<br/>Per defecte és <b>/root/.acme.sh/acme.sh</b>'
		],
		'update_channel' => [
			'title' => 'Actualitzar canal froxlor',
			'description' => 'Seleccioni el canal d\'actualització de froxlor. Per defecte és "estable"'
		],
		'uc_stable' => 'estable',
		'uc_testing' => 'tests',
		'traffictool' => [
			'toolselect' => 'Analitzador de trànsit',
			'webalizer' => 'Webalizer',
			'awstats' => 'AWStats',
			'goaccess' => 'goacccess'
		],
		'requires_reconfiguration' => 'El canvi d\'aquesta configuració podria requerir una reconfiguració dels serveis següents:<br/><strong>%s</strong>'
	],
	'spf' => [
		'use_spf' => 'Activar SPF per a dominis?',
		'spf_entry' => 'Entrada SPF per a tots els dominis'
	],
	'ssl_certificates' => [
		'certificate_for' => 'Certificat per a',
		'valid_from' => 'Vàlid des de',
		'valid_until' => 'Vàlid fins a',
		'issuer' => 'Emissor'
	],
	'success' => [
		'success' => 'Informació',
		'clickheretocontinue' => 'Feu clic aquí per a continuar',
		'settingssaved' => 'La configuració s\'ha guardat correctament.',
		'rebuildingconfigs' => 'Tasques inserides amb èxit per reconstruir fitxers de configuració',
		'domain_import_successfully' => 'S\'han importat correctament els dominis %s.',
		'backupscheduled' => 'S\'ha programat la vostra tasca de còpia de seguretat. Espereu que es processi.',
		'backupaborted' => 'La seva còpia de seguretat programada ha estat cancel·lada',
		'dns_record_added' => 'Registre DNS afegit correctament',
		'dns_record_deleted' => 'Registre DNS eliminat correctament',
		'testmailsent' => 'Correu de prova enviat correctament',
		'settingsimported' => 'Configuració importada correctament',
		'sent_error_report' => 'Informe d\'error enviat correctament. Gràcies per la vostra contribució.'
	],
	'tasks' => [
		'outstanding_tasks' => 'Tasques cron pendents',
		'REBUILD_VHOST' => 'Reconstrucció de la configuració del servidor web',
		'CREATE_HOME' => 'Afegeix nova %s client',
		'REBUILD_DNS' => 'Reconstrucció de la configuració bind',
		'CREATE_FTP' => 'Crear directori per a un nou usuari ftp',
		'DELETE_CUSTOMER_FILES' => 'Esborrar fitxers de client %s',
		'noneoutstanding' => 'Actualment no hi ha tasques pendents per a froxlor',
		'CREATE_QUOTA' => 'Establir quota al sistema de fitxers',
		'DELETE_EMAIL_DATA' => 'Esborrar dades de correu electrònic del client.',
		'DELETE_FTP_DATA' => 'Esborrar les dades del compte ftp del client.',
		'REBUILD_CRON' => 'Reconstruir el fitxer cron.d',
		'CREATE_CUSTOMER_BACKUP' => 'Treball de còpia de seguretat per al client %s',
		'DELETE_DOMAIN_PDNS' => 'Esborrar domini %s de la base de dades PowerDNS',
		'DELETE_DOMAIN_SSL' => 'Esborrar fitxers ssl de domini %s'
	],
	'terms' => 'Condicions d\'ús',
	'traffic' => [
		'month' => 'Mes',
		'day' => 'Dia',
		'months' => [
			'1' => 'Gener',
			'2' => 'Febrer',
			'3' => 'Març',
			'4' => 'Abril',
			'5' => 'Maig',
			'6' => 'Juny',
			'7' => 'Juliol',
			'8' => 'Agost',
			'9' => 'Setembre',
			'10' => 'Octubre',
			'11' => 'Novembre',
			'12' => 'Desembre',
			'jan' => 'Gener',
			'feb' => 'Febrer',
			'mar' => 'Març',
			'apr' => 'Abril',
			'may' => 'Maig',
			'jun' => 'Juny',
			'jul' => 'Juliol',
			'aug' => 'Agost',
			'sep' => 'Setembre',
			'oct' => 'Octubre',
			'nov' => 'Novembre',
			'dec' => 'Desembre',
			'total' => 'Total'
		],
		'mb' => 'Trànsit',
		'sumtotal' => 'Trànsit total',
		'sumhttp' => 'Trànsit HTTP',
		'sumftp' => 'Trànsit FTP',
		'summail' => 'Trànsit de correu',
		'customer' => 'Client',
		'domain' => 'Domini',
		'trafficoverview' => 'Resum del trànsit',
		'bycustomers' => 'Trànsit per clients',
		'details' => 'Detalls',
		'http' => 'HTTP',
		'ftp' => 'FTP',
		'mail' => 'Correu',
		'nocustomers' => 'Necessita com a mínim un client per veure els informes de trànsit.',
		'top5customers' => 'Top 5 clients',
		'nodata' => 'No s\'han trobat dades per a l\'interval donat.',
		'ranges' => [
			'last24h' => 'últimes 24 hores',
			'last7d' => 'últims 7 dies',
			'last30d' => 'últims 30 dies',
			'cm' => 'Mes actual',
			'last3m' => 'últims 3 mesos',
			'last6m' => 'últims 6 mesos',
			'last12m' => 'últims 12 meses',
			'cy' => 'Any en curs'
		],
		'byrange' => 'Especificat per rang'
	],
	'translator' => '',
	'update' => [
		'updateinprogress_onlyadmincanlogin' => 'S\'ha instal·lat una versió més recent del froxlor però encara no s\'ha configurat.<br/>Només l\'administrador pot iniciar sessió i finalitzar l\'actualització.',
		'update' => 'Actualització de froxlor',
		'proceed' => 'Procedir',
		'update_information' => [
			'part_a' => 'Els fitxers froxlor han estat actualitzats a la versió <strong>%s</strong>. La versió instal·lada és <strong>%s</strong>.',
			'part_b' => '<br/><br/>Els clients no es poden connectar fins que l\'actualització hagi finalitzat.<br/><strong>Procedir?</strong>'
		],
		'noupdatesavail' => 'Ja té instal·lada la darrera %sversion de froxlor.',
		'description' => 'Executant actualitzacions de la base de dades per a la instal·lació de froxlor',
		'uc_newinfo' => 'Hi ha una versió més recent disponible: "%s" (La vostra versió actual és: %s)',
		'notify_subject' => 'Nova actualització disponible'
	],
	'usersettings' => [
		'custom_notes' => [
			'title' => 'Notes personalitzades',
			'description' => 'Sigues lliure de posar les notes que vulguis/necessitis aquí. Es mostraran a la vista general de l\'administrador/client per a l\'usuari corresponent.',
			'show' => 'Mostrar les teves notes al tauler de control de l\'usuari'
		],
		'api_allowed' => [
			'title' => 'Permet accedir a la API',
			'description' => 'Quan està habilitat a la configuració, aquest usuari pot crear claus API i accedir a la API froxlor',
			'notice' => 'L\'accés a la API no està permès per al vostre compte.'
		]
	],
	'install' => [
		'slogan' => 'Panell de gestió del servidor froxlor',
		'preflight' => 'Comprovació del sistema',
		'critical_error' => 'Error crític',
		'suggestions' => 'No requerit però recomanat',
		'phpinfosuccess' => 'El seu sistema funciona amb PHP %s',
		'phpinfowarn' => 'El seu sistema està executant una versió inferior a PHP %s',
		'phpinfoupdate' => 'Actualitzi la seva versió PHP actual de %s a %s o superior',
		'start_installation' => 'Inicieu la instal·lació',
		'check_again' => 'Recarregar per comprovar de nou',
		'switchmode_advanced' => 'Mostrar opcions avançades',
		'switchmode_basic' => 'Ocultar opcions avançades',
		'dependency_check' => [
			'title' => 'Benvingut a froxlor',
			'description' => 'Comprovem les dependències del sistema per assegurar-nos que totes les extensions i mòduls php necessaris estan habilitats perquè froxlor funcioni correctament.'
		],
		'database' => [
			'top' => 'Base de dades',
			'title' => 'Crear base de dades i usuari',
			'description' => 'froxlor requereix una base de dades i addicionalment un usuari privilegiat per poder crear usuaris i bases de dades (opció GRANT). La base de dades i l\'usuari no privilegiat es crearan en aquest procés. L\'usuari privilegiat ha d\'existir.',
			'user' => 'Usuari no privilegiat de la base de dades',
			'dbname' => 'Nom de la base de dades',
			'force_create' => 'Fer còpia de seguretat i sobreescriure la base de dades si existeix?'
		],
		'admin' => [
			'top' => 'Usuari administrador',
			'title' => 'Crearem l\'usuari administrador principal.',
			'description' => 'Aquest usuari tindrà tots els privilegis per ajustar la configuració i afegir/actualitzar/eliminar recursos com a clients, dominis, etc.'
		],
		'system' => [
			'top' => 'Configuració del sistema',
			'title' => 'Detalls sobre el vostre servidor',
			'description' => 'Establiu el vostre entorn així com les dades i opcions rellevants del servidor aquí perquè froxlor conegui el vostre sistema. Aquests valors són crucials per a la configuració i el funcionament del sistema.',
			'ipv4' => 'Adreça IPv4 primària (si escau)',
			'ipv6' => 'Adreça IPv6 primària (si escau)',
			'servername' => 'Nom del servidor (FQDN, sense adreça IP)',
			'phpbackend' => 'PHP backend',
			'activate_newsfeed' => 'Habilitar la font oficial de notícies<br/><small>(font externa: https://inside.froxlor.org/news/)</small>'
		],
		'install' => [
			'top' => 'Finalitzar la configuració',
			'title' => 'Un últim pas...',
			'description' => 'L\'ordre següent descarregarà, instal·larà i configurarà els serveis necessaris al vostre sistema d\'acord amb les dades que heu facilitat en aquest procés d\'instal·lació.',
			'runcmd' => 'Executeu la següent ordre com a usuari root al vostre intèrpret d\'ordres en aquest servidor:',
			'manual_config' => 'Configuraré manualment els serveis, porta\'m a l\'inici de sessió',
			'waitforconfig' => 'Esperant que es configurin els serveis...'
		],
		'errors' => [
			'wrong_ownership' => 'Assegureu-vos que els fitxers froxlor són propietat de %s:%s',
			'missing_extensions' => 'Les següents extensions de php són necessàries i no estan instal·lades',
			'suggestedextensions' => 'No s\'han trobat les següents extensions de php però es recomanen',
			'databaseexists' => 'La base de dades ja existeix, si us plau establiu l\'opció override per reconstruir o trieu un altre nom',
			'unabletocreatedb' => 'No s\'ha pogut crear la base de dades de prova',
			'unabletodropdb' => 'No s\'ha pogut suprimir la base de dades de prova',
			'mysqlusernameexists' => 'L\'usuari especificat per a l\'usuari sense privilegis ja existeix. Si us plau, utilitzeu un altre nom d\'usuari o elimineu-lo primer.',
			'unabletocreateuser' => 'No s\'ha pogut crear l\'usuari de prova',
			'unabletodropuser' => 'L\'usuari de prova no s\'ha pogut eliminar.',
			'unabletoflushprivs' => 'L\'usuari privilegiat no pot eliminar privilegis.',
			'nov4andnov6ip' => 'Cal indicar una adreça IPv4 o IPv6.',
			'servernameneedstobevalid' => 'El nom de servidor indicat no sembla que sigui un FQDN o un nom de host.',
			'websrvuserdoesnotexist' => 'Sembla que l\'usuari del servidor web no existeix al sistema.',
			'websrvgrpdoesnotexist' => 'El webserver-group indicat no sembla existir al sistema.',
			'notyetconfigured' => 'Els serveis encara no s\'han configurat (correctament). Si us plau, executeu l\'ordre que es mostra a continuació o marqueu la casella per fer-ho més tard.',
			'mandatory_field_not_set' => 'El camp obligatori "%s" no està configurat.',
			'unexpected_database_error' => 'S\'ha produït una excepció inesperada a la base de dades. %s',
			'sql_import_failed' => 'Error en importar dades SQL.',
			'unprivileged_sql_connection_failed' => 'Error en inicialitzar una connexió SQL sense privilegis.',
			'privileged_sql_connection_failed' => 'Error en inicialitzar la connexió SQL privilegiada.',
			'mysqldump_backup_failed' => 'No es pot crear una còpia de seguretat de la base de dades, tenim un error de mysqldump.',
			'sql_backup_file_missing' => 'No es pot crear una còpia de seguretat de la base de dades, el fitxer de còpia de seguretat no existeix.',
			'backup_binary_missing' => 'No es pot crear una còpia de seguretat de la base de dades, assegureu-vos que heu instal·lat mysqldump.',
			'creating_configfile_failed' => 'No es poden crear fitxers de configuració, no es pot escriure el fitxer.',
			'database_already_exiting' => 'Hem trobat una base de dades i no se\'ns ha permès sobreescriure-la!'
		]
	],
	'welcome' => [
		'title' => 'Benvingut a froxlor!',
		'config_note' => 'Perquè froxlor pugui comunicar-se correctament amb el backend, has de configurar-lo.',
		'config_now' => 'Configurar ara'
	],
];
