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
		'cz' => 'Checo',
		'de' => 'Alemán',
		'en' => 'Inglés',
		'fr' => 'Francés',
		'it' => 'Italia',
		'nl' => 'Holandés',
		'pt' => 'Portugués',
		'se' => 'Sueco',
		'es' => 'Español',
		'zh_CN' => 'Chino (Simplificado)',
	],
	'2fa' => [
		'2fa' => 'Opciones 2FA',
		'2fa_enabled' => 'Activar la autenticación de dos factores (2FA)',
		'2fa_removed' => '2FA eliminado correctamente',
		'2fa_added' => '2FA activado correctamente<br /><a class="alert-link" href="%s?page=2fa">Ver detalles de 2FA</a>',
		'2fa_add' => 'Activar 2FA',
		'2fa_delete' => 'Desactivar 2FA',
		'2fa_verify' => 'Verificar código',
		'2fa_overview_desc' => 'Aquí puede activar una autenticación de dos factores para su cuenta.<br /><br />Puede utilizar una aplicación de autenticación (contraseña de un solo uso basada en el tiempo / TOTP) o dejar que froxlor le envíe un correo electrónico a la dirección de su cuenta después de cada inicio de sesión correcto con una contraseña de un solo uso.',
		'2fa_email_desc' => 'Su cuenta está configurada para utilizar contraseñas de un solo uso por correo electrónico. Para desactivarla, haga clic en "Desactivar 2FA".',
		'2fa_ga_desc' => 'Su cuenta está configurada para utilizar contraseñas de un solo uso basadas en el tiempo a través de una aplicación de autenticación. Escanee el código QR que aparece a continuación con la aplicación de autenticación que desee para generar los códigos. Para desactivar, haga clic en "Desactivar 2FA".'
	],
	'admin' => [
		'overview' => 'Visión general',
		'ressourcedetails' => 'Recursos usados',
		'systemdetails' => 'Detalles del sistema',
		'froxlordetails' => 'Detalles de froxlor',
		'installedversion' => 'Versión instalada',
		'latestversion' => 'Última versión',
		'lookfornewversion' => [
			'clickhere' => 'Búsqueda mediante webservice',
			'error' => 'Error de lectura'
		],
		'resources' => 'Recursos',
		'customer' => 'Cliente',
		'customers' => 'Clientes',
		'customers_list_desc' => 'Gestione sus clientes',
		'customer_add' => 'Crear cliente',
		'customer_edit' => 'Editar cliente',
		'username_default_msg' => 'Dejar vacío para el valor autogenerado',
		'domains' => 'Dominios',
		'domain_add' => 'Crear dominio',
		'domain_edit' => 'Editar dominio',
		'subdomainforemail' => 'Subdominios como dominios de correo electrónico',
		'admin' => 'Administrador',
		'admins' => 'Admins',
		'admin_add' => 'Crear administrador',
		'admin_edit' => 'Editar admin',
		'customers_see_all' => '¿Puede acceder a los recursos de otros administradores/revendedores?',
		'change_serversettings' => '¿Puede cambiar la configuración del servidor?',
		'server' => 'Sistema',
		'serversettings' => 'Ajustes',
		'serversettings_desc' => 'Administrar su sistema froxlor',
		'rebuildconf' => 'Reconstruir archivos de configuración',
		'stdsubdomain' => 'Subdominio estándar',
		'stdsubdomain_add' => 'Crear subdominio estándar',
		'phpenabled' => 'PHP habilitado',
		'deactivated' => 'Desactivado',
		'deactivated_user' => 'Desactivar usuario',
		'sendpassword' => 'Enviar contraseña',
		'ownvhostsettings' => 'Configuración vHost propia',
		'configfiles' => [
			'serverconfiguration' => 'Configuración',
			'overview' => 'Visión general',
			'wizard' => 'Asistente',
			'distribution' => 'Distribución',
			'service' => 'Servicio',
			'daemon' => 'Daemon',
			'http' => 'Servidor web (HTTP)',
			'dns' => 'Servidor de nombres (DNS)',
			'mail' => 'Servidor de correo (IMAP/POP3)',
			'smtp' => 'Servidor de correo (SMTP)',
			'ftp' => 'Servidor FTP',
			'etc' => 'Otros (Sistema)',
			'choosedistribution' => '-- Elija una distribución --',
			'chooseservice' => '-- Elija un servicio --',
			'choosedaemon' => '-- Elija un demonio --',
			'statistics' => 'Estadísticas',
			'compactoverview' => 'Vista general compacta',
			'legend' => '<h3>Está a punto de configurar un servicio/demonio</h3>',
			'commands' => '<span class="text-danger">Comandos:</span> Estos comandos deben ser ejecutados línea por línea como usuario root en un shell. Es seguro copiar todo el bloque y pegarlo en el shell.',
			'files' => '<span class="text-danger">Archivos de configuración:</span> Los comandos antes de los campos de texto deben abrir un editor con el archivo de destino. Sólo tienes que copiar y pegar el contenido en el editor y guardar el archivo.<br /><span class="text-danger">Nota:</span> La contraseña MySQL no ha sido reemplazada por razones de seguridad. Por favor, reemplaza "FROXLOR_MYSQL_PASSWORD" por tu cuenta o utiliza el formulario javascript de abajo para reemplazarla in situ. Si olvidaste tu contraseña MySQL la encontrarás en "lib/userdata.inc.php".',
			'importexport' => 'Importar/Exportar',
			'finishnote' => 'Archivo de parámetros generado correctamente. Ahora ejecute el siguiente comando como root:',
			'description' => 'Configurar los servicios del sistema',
			'minihowto' => 'En esta página puede ver las diferentes plantillas de configuración para cada servicio, (re)configurar servicios específicos si es necesario o exportar la selección actual a un archivo JSON para utilizarlo en los scripts CLI o en otro servidor.<br/><br/><b>Tenga en cuenta</b> que los servicios resaltados no reflejan su configuración actual, sino que muestran requisitos/recomendaciones de sus valores de configuración actuales.',
			'skipconfig' => 'No (re)configurar',
			'recommendednote' => 'Servicios recomendados/requeridos según la configuración actual del sistema',
			'selectrecommended' => 'Seleccionar recomendados',
			'downloadselected' => 'Exportar seleccionado'
		],
		'templates' => [
			'templates' => 'Plantillas de correo electrónico',
			'template_add' => 'Añadir plantilla',
			'template_fileadd' => 'Añadir plantilla de archivo',
			'template_edit' => 'Editar plantilla',
			'action' => 'Acción',
			'email' => 'Plantillas de correo electrónico y archivos',
			'subject' => 'Asunto',
			'mailbody' => 'Cuerpo del correo',
			'createcustomer' => 'Correo de bienvenida para nuevos clientes',
			'pop_success' => 'Correo de bienvenida para nuevas cuentas de correo electrónico',
			'template_replace_vars' => 'Variables a sustituir en la plantilla:',
			'SALUTATION' => 'Sustituido por un saludo correcto (nombre o empresa)',
			'FIRSTNAME' => 'Sustituido por el nombre del cliente.',
			'NAME' => 'Se sustituye por el nombre del cliente.',
			'COMPANY' => 'Se sustituye por el nombre de la empresa del cliente.',
			'USERNAME' => 'Se sustituye por el nombre de usuario de la cuenta del cliente.',
			'PASSWORD' => 'Se sustituye por la contraseña de la cuenta del cliente.',
			'EMAIL' => 'Se sustituye por la dirección de la cuenta POP3/IMAP.',
			'CUSTOMER_NO' => 'Sustituido por el número de cliente',
			'TRAFFIC' => 'Se sustituye por el tráfico asignado al cliente.',
			'TRAFFICUSED' => 'Sustituido por el tráfico, que fue agotado por el cliente.',
			'pop_success_alternative' => 'Correo de bienvenida para nuevas cuentas de correo electrónico enviado a la dirección alternativa',
			'EMAIL_PASSWORD' => 'Sustituido por la contraseña de la cuenta POP3/IMAP.',
			'index_html' => 'Archivo de índice para directorios de clientes recién creados',
			'SERVERNAME' => 'Sustituido por el nombre del servidor.',
			'CUSTOMER' => 'Sustituido por el nombre de usuario del cliente.',
			'ADMIN' => 'Se sustituye por el nombre de usuario del administrador.',
			'CUSTOMER_EMAIL' => 'Se sustituye por la dirección de correo electrónico del cliente.',
			'ADMIN_EMAIL' => 'Se sustituye por la dirección de correo electrónico del administrador.',
			'filetemplates' => 'Plantillas de archivos',
			'filecontent' => 'Contenido del fichero',
			'new_database_by_customer' => 'Notificación al cliente de la creación de una base de datos',
			'new_ftpaccount_by_customer' => 'Notificación al cliente de la creación de un usuario ftp',
			'newdatabase' => 'Correos de notificación para nuevas bases de datos',
			'newftpuser' => 'Correos de notificación para nuevos usuarios ftp',
			'CUST_NAME' => 'Nombre del cliente',
			'DB_NAME' => 'Nombre de la base de datos',
			'DB_PASS' => 'Contraseña de la base de datos',
			'DB_DESC' => 'Descripción de la base de datos',
			'DB_SRV' => 'Servidor de base de datos',
			'PMA_URI' => 'URL de phpMyAdmin (si se indica)',
			'USR_NAME' => 'Nombre de usuario FTP',
			'USR_PASS' => 'Contraseña FTP',
			'USR_PATH' => 'FTP homedir (relativo a customer-docroot)',
			'forgotpwd' => 'Correos de notificación de restablecimiento de contraseña',
			'password_reset' => 'Notificación al cliente de restablecimiento de contraseña',
			'trafficmaxpercent' => 'Correo de notificación para los clientes cuando se agota un determinado porcentaje máximo de tráfico',
			'MAX_PERCENT' => 'Sustituido por el límite de diskusage/tráfico para el envío de informes en porcentaje.',
			'USAGE_PERCENT' => 'Reemplazado con el diskusage/tráfico agotado por el cliente en porcentaje.',
			'diskmaxpercent' => 'Correo de notificación a los clientes cuando se agota el porcentaje máximo de espacio en disco.',
			'DISKAVAILABLE' => 'Sustituido por el uso de disco asignado al cliente.',
			'DISKUSED' => 'Reemplazado por el uso de disco, que fue agotado por el cliente.',
			'LINK' => 'Sustituido por el enlace de restablecimiento de contraseña del cliente.',
			'SERVER_HOSTNAME' => 'Reemplaza el system-hostname (URL a froxlor)',
			'SERVER_IP' => 'Reemplaza la dirección IP del servidor por defecto',
			'SERVER_PORT' => 'Reemplaza el puerto por defecto del servidor',
			'DOMAINNAME' => 'Reemplaza el subdominio estándar del cliente (puede estar vacío si no se genera ninguno)'
		],
		'webserver' => 'Servidor web',
		'createzonefile' => 'Crear zona dns para el dominio',
		'custombindzone' => 'Archivo de zona personalizado / no gestionado',
		'bindzonewarning' => 'vacío por defecto<br /><strong class="text-danger">ATENCIÓN:</strong> Si utiliza un archivo de zonas, tendrá que gestionar también manualmente todos los registros necesarios para todas las subzonas.',
		'ipsandports' => [
			'ipsandports' => 'IPs y Puertos',
			'add' => 'Añadir IP/Puerto',
			'edit' => 'Editar IP/Puerto',
			'ipandport' => 'IP/Puerto',
			'ip' => 'IP',
			'ipnote' => '<div id="ipnote" class="invalid-feedback">Nota: Aunque las direcciones IP privadas están permitidas, algunas características como DNS podrían no comportarse correctamente.<br />Sólo use direcciones IP privadas si está seguro.</div>',
			'port' => 'Puerto',
			'create_listen_statement' => 'Crear sentencia Listen',
			'create_namevirtualhost_statement' => 'Crear sentencia NameVirtualHost',
			'create_vhostcontainer' => 'Crear vHost-Container',
			'create_vhostcontainer_servername_statement' => 'Crear sentencia ServerName en vHost-Container',
			'enable_ssl' => '¿Se trata de un puerto SSL?',
			'ssl_cert_file' => 'Ruta al certificado SSL',
			'webserverdefaultconfig' => 'Configuración por defecto del servidor web',
			'webserverdomainconfig' => 'Configuración de dominio del servidor web',
			'webserverssldomainconfig' => 'Configuración SSL del servidor web',
			'ssl_key_file' => 'Ruta al archivo de claves SSL',
			'ssl_ca_file' => 'Ruta al certificado SSL CA',
			'default_vhostconf_domain' => 'Configuración vHost por defecto para cada contenedor de dominio',
			'ssl_cert_chainfile' => [
				'title' => 'Ruta al archivo SSL CertificateChainFile',
				'description' => 'Mayormente CA_Bundle, o similar, probablemente quieras configurar esto si has comprado un certificado SSL.'
			],
			'docroot' => [
				'title' => 'Docroot personalizado (vacío = apunta a froxlor)',
				'description' => 'Aquí puedes definir un document-root personalizado (el destino de una petición) para esta combinación ip/puerto.<br/><strong>ATENCIÓN:</strong> ¡Por favor, ten cuidado con lo que introduces aquí!'
			],
			'ssl_paste_description' => 'Pegue el contenido completo de su certificado en el cuadro de texto',
			'ssl_cert_file_content' => 'Contenido del certificado ssl',
			'ssl_key_file_content' => 'Contenido del archivo de clave ssl (privada)',
			'ssl_ca_file_content' => 'Contenido del archivo ssl CA (opcional)',
			'ssl_ca_file_content_desc' => '<br/><br/>Autenticación del cliente, configure esto sólo si sabe lo que es.',
			'ssl_cert_chainfile_content' => 'Contenido del archivo de cadena de certificados (opcional)',
			'ssl_cert_chainfile_content_desc' => '<br/><br/>Principalmente CA_Bundle, o similar, probablemente quiera establecer esto si compró un certificado SSL.',
			'ssl_default_vhostconf_domain' => 'Configuración SSL vHost por defecto para cada contenedor de dominio'
		],
		'memorylimitdisabled' => 'Desactivado',
		'valuemandatory' => 'Este valor es obligatorio',
		'valuemandatorycompany' => 'O bien "nombre" y "nombre" o "empresa" debe ser llenado',
		'serversoftware' => 'Serversoftware',
		'phpversion' => 'Versión PHP',
		'mysqlserverversion' => 'Versión del servidor MySQL',
		'webserverinterface' => 'Interfaz del servidor web',
		'accountsettings' => 'Configuración de la cuenta',
		'panelsettings' => 'Configuración del panel',
		'systemsettings' => 'Configuración del sistema',
		'webserversettings' => 'Configuración del servidor web',
		'mailserversettings' => 'Configuración del servidor de correo',
		'nameserversettings' => 'Configuración del servidor de nombres',
		'updatecounters' => 'Recalcular el uso de recursos',
		'subcanemaildomain' => [
			'never' => 'Nunca',
			'choosableno' => 'Seleccionable, por defecto no',
			'choosableyes' => 'Seleccionable, por defecto sí',
			'always' => 'Siempre'
		],
		'wipecleartextmailpwd' => 'Borrar contraseñas en texto plano',
		'webalizersettings' => 'Configuración de Webalizer',
		'webalizer' => [
			'normal' => 'Normal',
			'quiet' => 'Silencioso',
			'veryquiet' => 'Sin salida'
		],
		'domain_nocustomeraddingavailable' => 'Actualmente no es posible añadir un dominio. Primero debe añadir al menos un cliente.',
		'loggersettings' => 'Configuración del registro',
		'logger' => [
			'normal' => 'normal',
			'paranoid' => 'paranoico'
		],
		'emaildomain' => 'Emaildomain',
		'email_only' => '¿Sólo correo electrónico?',
		'wwwserveralias' => 'Añada un "www." ServerAlias',
		'subject' => 'Asunto',
		'recipient' => 'Destinatario',
		'message' => 'Escribir un mensaje',
		'text' => 'Mensaje',
		'sslsettings' => 'Configuración SSL',
		'specialsettings_replacements' => 'Puede utilizar las siguientes variables:<br/><code>{DOMAIN}</code>, <code>{DOCROOT}</code>, <code>{CUSTOMER}</code>, <code>{IP}</code>, <code>{PORT}</code>, <code>{SCHEME}</code>, <code>{FPMSOCKET}</code> (si procede)<br/>',
		'dkimsettings' => 'Configuración de DomainKey',
		'caneditphpsettings' => '¿Puede cambiar los ajustes de dominio relacionados con php?',
		'allips' => 'Todas las IP',
		'awstatssettings' => 'Configuración de AWstats',
		'domain_dns_settings' => 'Configuración dns del dominio',
		'activated' => 'Activado',
		'statisticsettings' => 'Configuración de estadísticas',
		'or' => 'o',
		'sysload' => 'Carga del sistema',
		'noloadavailable' => 'no disponible',
		'nouptimeavailable' => 'no disponible',
		'nosubject' => '(Sin asunto)',
		'security_settings' => 'Opciones de seguridad',
		'know_what_youre_doing' => 'Cambiar sólo, ¡si sabes lo que haces!',
		'show_version_login' => [
			'title' => 'Mostrar la versión de froxlor en el login',
			'description' => 'Mostrar la versión de froxlor en el pie de página en la página de inicio de sesión'
		],
		'show_version_footer' => [
			'title' => 'Mostrar la versión de froxlor en el pie de página',
			'description' => 'Mostrar la versión de froxlor en el pie de página del resto de páginas'
		],
		'froxlor_graphic' => [
			'title' => 'Gráfico de cabecera para froxlor',
			'description' => 'Qué gráfico debe mostrarse en la cabecera'
		],
		'phpsettings' => [
			'title' => 'Configuración PHP',
			'description' => 'Breve descripción',
			'actions' => 'Acciones',
			'activedomains' => 'En uso para dominio(s)',
			'notused' => 'Configuración no en uso',
			'editsettings' => 'Cambiar configuración PHP',
			'addsettings' => 'Crear nueva configuración PHP',
			'viewsettings' => 'Ver configuración PHP',
			'phpinisettings' => 'Configuración php.ini',
			'addnew' => 'Crear nueva configuración PHP',
			'binary' => 'PHP Binario',
			'fpmdesc' => 'Configuración PHP-FPM',
			'file_extensions' => 'Extensiones de archivos',
			'file_extensions_note' => '(sin punto, separadas por espacios)',
			'enable_slowlog' => 'Activar slowlog (por dominio)',
			'request_terminate_timeout' => 'Solicitar terminate-timeout',
			'request_slowlog_timeout' => 'Solicitar slowlog-timeout',
			'activephpconfigs' => 'En uso para php-config(s)',
			'pass_authorizationheader' => 'Añade "-pass-header Authorization" / "CGIPassAuth On" a vhosts'
		],
		'misc' => 'Varios',
		'fpmsettings' => [
			'addnew' => 'Crear nueva versión PHP',
			'edit' => 'Cambiar versión PHP'
		],
		'phpconfig' => [
			'template_replace_vars' => 'Variables que serán reemplazadas en las configs',
			'pear_dir' => 'Será reemplazada con la configuración global para el directorio pear.',
			'open_basedir_c' => 'Se insertará un ; (punto y coma) para comentar/desactivar open_basedir cuando se establezca',
			'open_basedir' => 'Se sustituirá por la configuración open_basedir del dominio.',
			'tmp_dir' => 'Será reemplazado por el directorio temporal del dominio.',
			'open_basedir_global' => 'Se sustituirá por el valor global de la ruta que se adjuntará a open_basedir (ver configuración del servidor web).',
			'customer_email' => 'Se sustituirá por la dirección de correo electrónico del cliente propietario del dominio.',
			'admin_email' => 'Se sustituirá por la dirección de correo electrónico del administrador propietario del dominio.',
			'domain' => 'Se sustituirá por el dominio.',
			'customer' => 'Se sustituirá por el nombre de usuario del cliente propietario del dominio.',
			'admin' => 'Se sustituirá por el nombre de usuario del administrador propietario del dominio.',
			'docroot' => 'Se sustituirá por la raíz del documento del dominio.',
			'homedir' => 'Se sustituirá por el directorio raíz del cliente.'
		],
		'expert_settings' => 'Configuración experta',
		'mod_fcgid_starter' => [
			'title' => 'Procesos PHP para este dominio (vacío por defecto)'
		],
		'phpserversettings' => 'Configuración PHP',
		'mod_fcgid_maxrequests' => [
			'title' => 'Peticiones php máximas para este dominio (vacío por defecto)'
		],
		'spfsettings' => 'Configuración SPF del dominio',
		'specialsettingsforsubdomains' => 'Aplicar configuración especial a todos los subdominios (*.ejemplo.com)',
		'accountdata' => 'Datos de la cuenta',
		'contactdata' => 'Datos de contacto',
		'servicedata' => 'Datos de servicio',
		'newerversionavailable' => 'Hay una nueva versión de froxlor disponible.',
		'newerversiondetails' => '¿Actualice ahora a la versión <b>%s</b>?<br/>(Su versión actual es: %s)',
		'extractdownloadedzip' => '¿Extraer el archivo descargado "%s"?',
		'cron' => [
			'cronsettings' => 'Configuración de Cronjob',
			'add' => 'Añadir cronjob'
		],
		'cronjob_edit' => 'Editar cronjob',
		'warning' => 'ADVERTENCIA - ¡Tenga en cuenta!',
		'lastlogin_succ' => 'Último acceso',
		'ftpserver' => 'Servidor FTP',
		'ftpserversettings' => 'Configuración del servidor FTP',
		'webserver_user' => 'Nombre de usuario del servidor web',
		'webserver_group' => 'Nombre de grupo del servidor web',
		'perlenabled' => 'Perl activado',
		'fcgid_settings' => 'FCGID',
		'mod_fcgid_user' => 'Usuario local a utilizar para FCGID (froxlor vHost)',
		'mod_fcgid_group' => 'Grupo local a utilizar para FCGID (froxlor vHost)',
		'perl_settings' => 'Perl/CGI',
		'notgiven' => '[No indicado]',
		'store_defaultindex' => 'Almacenar el archivo de índice por defecto en el docroot del cliente',
		'phpfpm_settings' => 'PHP-FPM',
		'traffic' => 'Tráfico',
		'traffic_sub' => 'Detalles sobre el uso del tráfico',
		'domaintraffic' => 'Dominios',
		'customertraffic' => 'Clientes',
		'assignedmax' => 'Asignado / Max',
		'usedmax' => 'Usado / Max',
		'used' => 'Usado',
		'speciallogwarning' => '<div id="speciallogfilenote" class="invalid-feedback">ADVERTENCIA: Al cambiar esta configuración perderá todas sus antiguas estadísticas para este dominio.</div>',
		'speciallogfile' => [
			'title' => 'Archivo de registro separado',
			'description' => 'Active esta opción para obtener un archivo de registro de acceso independiente para este dominio.'
		],
		'domain_editable' => [
			'title' => 'Permitir editar el dominio',
			'desc' => 'Si se establece en sí, el cliente puede cambiar varios ajustes del dominio.<br/>Si se establece en no, el cliente no puede cambiar nada.'
		],
		'writeaccesslog' => [
			'title' => 'Escribir un registro de acceso',
			'description' => 'Active esta opción para obtener un archivo de registro de acceso para este dominio.'
		],
		'writeerrorlog' => [
			'title' => 'Escribir un registro de errores',
			'description' => 'Active esta opción para obtener un archivo de registro de errores para este dominio.'
		],
		'phpfpm.ininote' => 'No todos los valores que quiera definir pueden ser usados en la configuración del pool php-fpm',
		'phpinfo' => 'PHPinfo()',
		'selectserveralias' => 'Valor ServerAlias para el dominio',
		'selectserveralias_desc' => 'Elija si froxlor debe crear una entrada comodín (*.dominio.tld), un alias WWW (www.domain.tld) o ningún alias.',
		'show_news_feed' => [
			'title' => 'Mostrar noticias en el panel de administración',
			'description' => 'Activa esta opción para mostrar las noticias oficiales de froxlor (https://inside.froxlor.org/news/) en tu panel de control y no perderte nunca información importante o anuncios de lanzamientos.'
		],
		'cronsettings' => 'Configuración de Cronjob',
		'integritycheck' => 'Validación de la base de datos',
		'integrityname' => 'Nombre',
		'integrityresult' => 'Resultado',
		'integrityfix' => 'Solución automática de problemas',
		'customer_show_news_feed' => 'Mostrar noticias en el panel del cliente',
		'customer_news_feed_url' => [
			'title' => 'Utilizar un canal RSS personalizado',
			'description' => 'Especifique un canal RSS personalizado que se mostrará a sus clientes en su panel de control.<br/><small>Deje este campo vacío para utilizar el canal de noticias oficial de froxlor (https://inside.froxlor.org/news/).</small>'
		],
		'movetoadmin' => 'Mover cliente',
		'movecustomertoadmin' => 'Mueve el cliente al administrador/revendedor seleccionado<br/><small>Deja esto vacío para no hacer cambios.<br/>Si el administrador deseado no aparece en la lista, su límite de clientes ha sido alcanzado.</small>',
		'note' => 'Nota',
		'mod_fcgid_umask' => [
			'title' => 'Máscara (por defecto: 022)'
		],
		'apcuinfo' => 'Información APCu',
		'opcacheinfo' => 'Información OPcache',
		'letsencrypt' => [
			'title' => 'Usar Let\'s Encrypt',
			'description' => 'Obtenga un certificado gratuito de <a href="https://letsencrypt.org">Let\'s Encrypt</a>. El certificado se creará y renovará automáticamente.<br /><strong class="text-danger">ATENCIÓN:</strong> Si los comodines están activados, esta opción se desactivará automáticamente.'
		],
		'autoupdate' => 'Actualizar automáticamente',
		'server_php' => 'PHP',
		'dnsenabled' => 'Habilitar editor DNS',
		'froxlorvhost' => 'Configuración de froxlor VirtualHost',
		'hostname' => 'Nombre de host',
		'memory' => 'Uso de memoria',
		'webserversettings_ssl' => 'Configuración SSL del servidor web',
		'domain_hsts_maxage' => [
			'title' => 'Seguridad estricta de transporte HTTP (HSTS)',
			'description' => 'Especifique el valor max-age para la cabecera Strict-Transport-Security<br/>El valor <i>0</i> desactivará HSTS para el dominio. La mayoría de los usuarios establecen un valor de <i>31536000</i> (un año).'
		],
		'domain_hsts_incsub' => [
			'title' => 'Incluir HSTS para cualquier subdominio',
			'description' => 'La directiva opcional "includeSubDomains", si está presente, indica a la UA que la Política HSTS se aplica a este Host HSTS así como a cualquier subdominio del nombre de dominio del host.'
		],
		'domain_hsts_preload' => [
			'title' => 'Incluir dominio en la <a href="https://hstspreload.org/" target="_blank">lista de precarga</a> HSTS',
			'description' => 'Si desea que este dominio se incluya en la lista de precarga HSTS mantenida por Chrome (y utilizada por Firefox y Safari), active esta opción.<br />El envío de la directiva de precarga desde su sitio puede tener CONSECUENCIAS PERMANENTES e impedir que los usuarios accedan a su sitio y a cualquiera de sus subdominios.<br />Por favor, lea los detalles en <a href="https://hstspreload.org/#removal" target="_blank">https://hstspreload.org/#removal</a> antes de enviar la cabecera con "preload".'
		],
		'domain_ocsp_stapling' => [
			'title' => 'Engrapado OCSP',
			'description' => 'Consulte <a target="_blank" href="https://en.wikipedia.org/wiki/OCSP_stapling">Wikipedia</a> para una explicación detallada del grapado OCSP',
			'nginx_version_warning' => '<br /><strong class="text-danger">ADVERTENCIA:</strong> Se requiere la versión 1.3.7 o superior de Nginx para el grapado OCSP. Si su versión es anterior, ¡el servidor web NO se iniciará correctamente mientras el grapado OCSP esté activado!'
		],
		'domain_http2' => [
			'title' => 'Soporte HTTP2',
			'description' => 'Consulte <a target="_blank" href="https://en.wikipedia.org/wiki/HTTP/2">Wikipedia</a> para una explicación detallada de HTTP2'
		],
		'testmail' => 'Prueba SMTP',
		'phpsettingsforsubdomains' => 'Aplicar php-config a todos los subdominios:',
		'plans' => [
			'name' => 'Nombre del plan',
			'description' => 'Descripción',
			'last_update' => 'Última actualización',
			'plans' => 'Planes de alojamiento',
			'plan_details' => 'Detalles del plan',
			'add' => 'Añadir nuevo plan',
			'edit' => 'Editar plan',
			'use_plan' => 'Aplicar plan'
		],
		'notryfiles' => [
			'title' => 'No autogenerated try_files',
			'description' => 'Diga sí aquí si desea especificar una directiva try_files personalizada en specialsettings (necesaria para algunos plugins de wordpress, por ejemplo).'
		],
		'logviewenabled' => 'Habilitar acceso a access/error-logs',
		'novhostcontainer' => '<br /><br /><small class="text-danger">Ninguna de las IPs y puertos tiene activada la opción "Crear vHost-Container", muchos ajustes aquí no estarán disponibles</small>',
		'ownsslvhostsettings' => 'Configuración propia de SSL vHost',
		'domain_override_tls' => 'Anular la configuración TLS del sistema',
		'domain_override_tls_addinfo' => '<br /><span class="text-danger">Sólo se utiliza si la opción "Override system TLS settings" está configurada como "Yes".</span>',
		'domain_sslenabled' => 'Habilitar el uso de SSL',
		'domain_honorcipherorder' => 'Respetar el orden de cifrado (servidor), por defecto <strong>no</strong>',
		'domain_sessiontickets' => 'Habilitar TLS sessiontickets (RFC 5077), por defecto <strong>sí</strong>',
		'domain_sessionticketsenabled' => [
			'title' => 'Habilitar el uso de TLS sessiontickets globalmente',
			'description' => 'Por defecto <strong>sí</strong><br/>Requiere apache-2.4.11+ o nginx-1.5.9+'
		],
		'domaindefaultalias' => 'Valor por defecto de ServerAlias para nuevos dominios',
		'smtpsettings' => 'Configuración SMTP',
		'smtptestaddr' => 'Enviar correo de prueba a',
		'smtptestnote' => 'Tenga en cuenta que los valores siguientes reflejan su configuración actual y sólo pueden ajustarse allí (véase el enlace en la esquina superior derecha)',
		'smtptestsend' => 'Enviar correo de prueba',
		'mysqlserver' => [
			'mysqlserver' => 'Servidor MySQL',
			'dbserver' => 'Servidor',
			'caption' => 'Descripción',
			'host' => 'Nombre de host / IP',
			'port' => 'Puerto',
			'user' => 'Usuario privilegiado',
			'add' => 'Añadir nuevo servidor MySQL',
			'edit' => 'Editar servidor MySQL',
			'password' => 'Contraseña de usuario privilegiado',
			'password_emptynochange' => 'Nueva contraseña, dejar vacío para ningún cambio',
			'allowall' => [
				'title' => 'Permitir el uso de este servidor a todos los clientes existentes actualmente',
				'description' => 'Establezca esta opción en "true" si desea permitir el uso de este servidor de base de datos a todos los clientes existentes para que puedan añadir bases de datos en él. Esta configuración no es permanente, pero se puede ejecutar varias veces.'
			],
			'testconn' => 'Probar la conexión al guardar',
			'ssl' => 'Utilizar SSL para la conexión al servidor de base de datos',
			'ssl_cert_file' => 'La ruta del archivo a la autoridad del certificado SSL',
			'verify_ca' => 'Habilitar la verificación del certificado SSL del servidor'
		],
		'settings_importfile' => 'Elegir archivo de importación',
		'documentation' => 'Documentación',
		'adminguide' => 'Guía del administrador',
		'userguide' => 'Guía del usuario',
		'apiguide' => 'Guía de la API'
	],
	'apcuinfo' => [
		'clearcache' => 'Borrar caché de APCu',
		'generaltitle' => 'Información general sobre la caché',
		'version' => 'Versión de APCu',
		'phpversion' => 'Versión PHP',
		'host' => 'Host APCu',
		'sharedmem' => 'Memoria compartida',
		'sharedmemval' => '%d Segmento(s) con %s (%s memoria)',
		'start' => 'Hora de inicio',
		'uptime' => 'Tiempo de actividad',
		'upload' => 'Soporte de carga de archivos',
		'cachetitle' => 'Información de la caché',
		'cvar' => 'Variables en caché',
		'hit' => 'Aciertos',
		'miss' => 'Fallos',
		'reqrate' => 'Tasa de peticiones (aciertos, fallos)',
		'creqsec' => 'Peticiones de caché/segundo',
		'hitrate' => 'Tasa de aciertos',
		'missrate' => 'Porcentaje de fallos',
		'insrate' => 'Tasa de inserciones',
		'cachefull' => 'Recuento de caché llena',
		'runtime' => 'Configuración de tiempo de ejecución',
		'memnote' => 'Uso de memoria',
		'total' => 'Total',
		'free' => 'Libre',
		'used' => 'Usado',
		'hitmiss' => 'Aciertos y errores',
		'detailmem' => 'Uso detallado de memoria y fragmentación',
		'fragment' => 'Fragmentación',
		'nofragment' => 'Sin fragmentación',
		'fragments' => 'Fragmentos'
	],
	'apikeys' => [
		'no_api_keys' => 'No se han encontrado claves API',
		'key_add' => 'Añadir nueva clave',
		'apikey_removed' => 'La clave api con el id #%s ha sido eliminada con éxito',
		'apikey_added' => 'Se ha generado correctamente una nueva clave api',
		'clicktoview' => 'Haga clic para ver',
		'allowed_from' => 'Permitido desde',
		'allowed_from_help' => 'Lista separada por comas de direcciones IP / redes.<br />Por defecto está vacío (permitir desde todos).',
		'valid_until' => 'Válido hasta',
		'valid_until_help' => 'Fecha hasta la que es válido, formato AAAA-MM-DDThh:mm'
	],
	'changepassword' => [
		'old_password' => 'Contraseña antigua',
		'new_password' => 'Nueva contraseña',
		'new_password_confirm' => 'Confirme la contraseña',
		'new_password_ifnotempty' => 'Nueva contraseña (vacía = sin cambios)',
		'also_change_ftp' => ' cambie también la contraseña de la cuenta FTP principal',
		'also_change_stats' => ' cambie también la contraseña de la página de estadísticas'
	],
	'cron' => [
		'cronname' => 'cronjob-name',
		'lastrun' => 'última ejecución',
		'interval' => 'intervalo',
		'isactive' => 'activado',
		'description' => 'descripción',
		'changewarning' => 'Cambiar estos valores puede tener una causa negativa en el comportamiento de froxlor y sus tareas automatizadas.<br/>Por favor, sólo cambie los valores aquí, si está seguro de lo que está haciendo.'
	],
	'crondesc' => [
		'cron_unknown_desc' => 'no description given',
		'cron_tasks' => 'Generación de archivos de configuración',
		'cron_legacy' => 'cronjob heredado (antiguo)',
		'cron_traffic' => 'Cálculo de tráfico',
		'cron_usage_report' => 'Informes web y de tráfico',
		'cron_mailboxsize' => 'Cálculo del tamaño del buzón',
		'cron_letsencrypt' => 'Actualización de certificados Let\'s Encrypt',
		'cron_backup' => 'Procesar tareas de copia de seguridad'
	],
	'cronjob' => [
		'cronjobsettings' => 'Configuración de Cronjob',
		'cronjobintervalv' => 'Valor del intervalo de tiempo de ejecución',
		'cronjobinterval' => 'Intervalo de ejecución'
	],
	'cronjobs' => [
		'notyetrun' => 'Aún no ejecutado'
	],
	'cronmgmt' => [
		'minutes' => 'minutos',
		'hours' => 'horas',
		'days' => 'días',
		'weeks' => 'semanas',
		'months' => 'meses'
	],
	'customer' => [
		'documentroot' => 'Directorio de inicio',
		'name' => 'Nombre',
		'firstname' => 'Nombre de pila',
		'lastname' => 'Apellidos',
		'company' => 'Empresa',
		'nameorcompany_desc' => 'Se requiere nombre/apellido o empresa',
		'street' => 'Calle',
		'zipcode' => 'Código postal',
		'city' => 'Ciudad',
		'phone' => 'Teléfono',
		'fax' => 'Fax',
		'email' => 'Correo electrónico',
		'customernumber' => 'ID de cliente',
		'diskspace' => 'Espacio web',
		'traffic' => 'Tráfico',
		'mysqls' => 'Bases de datos MySQL',
		'emails' => 'Direcciones de correo electrónico',
		'accounts' => 'Cuentas de correo electrónico',
		'forwarders' => 'Remitentes de correo electrónico',
		'ftps' => 'Cuentas FTP',
		'subdomains' => 'Subdominios',
		'domains' => 'Dominios',
		'mib' => 'MiB',
		'gib' => 'GiB',
		'title' => 'Título',
		'country' => 'País',
		'email_quota' => 'Cuota de correo electrónico',
		'email_imap' => 'Correo IMAP',
		'email_pop3' => 'Correo electrónico POP3',
		'sendinfomail' => 'Enviarme datos por correo electrónico',
		'generated_pwd' => 'Sugerencia de contraseña',
		'usedmax' => 'Usado / Max',
		'services' => 'Servicios',
		'letsencrypt' => [
			'title' => 'Usar Let\'s Encrypt',
			'description' => 'Obtenga un certificado gratuito de <a href="https://letsencrypt.org">Let\'s Encrypt</a>. El certificado se creará y renovará automáticamente.'
		],
		'selectserveralias_addinfo' => 'Esta opción se puede configurar al editar el dominio. Su valor inicial se hereda del dominio padre.',
		'total_diskspace' => 'Espacio total en disco',
		'mysqlserver' => 'Servidor mysql utilizable'
	],
	'diskquota' => 'Cuota',
	'dns' => [
		'destinationip' => 'IP(s) del dominio',
		'standardip' => 'IP estándar del servidor',
		'a_record' => 'Registro A (IPv6 opcional)',
		'cname_record' => 'Registro CNAME',
		'mxrecords' => 'Definir registros MX',
		'standardmx' => 'Registro MX estándar del servidor',
		'mxconfig' => 'Registros MX personalizados',
		'priority10' => 'Prioridad 10',
		'priority20' => 'Prioridad 20',
		'txtrecords' => 'Definir registros TXT',
		'txtexample' => 'Ejemplo (SPF-entry):<br/>v=spf1 ip4:xxx.xxx.xx.0/23 -all',
		'howitworks' => 'Aquí puedes gestionar las entradas DNS para tu dominio. Ten en cuenta que froxlor generará automáticamente los registros NS/MX/A/AAAA por ti. Las entradas personalizadas son preferibles, sólo las entradas que falten serán generadas automáticamente.'
	],
	'dnseditor' => [
		'edit' => 'editar DNS',
		'records' => 'Registros',
		'notes' => [
			'A' => 'Dirección IPv4 de 32 bits, usada para mapear nombres de host a una dirección IP del host.',
			'AAAA' => 'Dirección IPv6 de 128 bits, utilizada para asignar nombres de host a una dirección IP del host.',
			'CAA' => 'El registro de recursos CAA permite al titular de un nombre de dominio DNS especificar una o varias Autoridades de Certificación (CA) autorizadas a emitir certificados para ese dominio.<br/>Estructura: <code>flag tag[issue|issuewild|iodef|contactmail|contactphone] value</code><br/>Ejemplo: <code>0 issue "ca.example.net"<br/></code> 0 <code>iodef "mailto:security@example.com"</code>',
			'CNAME' => 'Alias del nombre de dominio, la búsqueda DNS continuará reintentando la búsqueda con el nuevo nombre. Sólo es posible para subdominios.',
			'DNAME' => 'Crea un alias para todo un subárbol del árbol de nombres de dominio',
			'LOC' => 'Información sobre la ubicación geográfica de un nombre de dominio.<br/>Estructura: <code>( d1 [m1 [s1]] { d2 [m2 [s2]] { alt["m"] [siz["m"] [hp["m"] [vp["m"]]]] )</code><br/>Descripción: <code>d1</code>: [0 . <code>. 90] (grados de latitud)
			d2: [0 .. 180] (grados de longitud)
			m1, m2: [0 .. 59] (minutos latitud/longitud)
			s1, s2: [0 .. 59,999] (segundos latitud/longitud)
			alt: [-100000.00 .. 42849672.95] POR .01 (altitud en metros)
			siz, hp, vp: [0 .. 90000000.00] (tamaño/precisión en metros)</code><br/>Ejemplo: <code>52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m</code>',
			'MX' => 'Registro de intercambio de correo, asigna un nombre de dominio a un servidor de correo para ese dominio.<br/>Ejemplo: <code>10 mail.example.com</code><br/>Nota: Para la prioridad, utilice el campo anterior.',
			'NS' => 'Delega una zona DNS para que utilice los servidores de nombres autoritativos indicados.',
			'RP' => 'Registro de persona responsable<br/>Estructura: <code>mailbox[sustituir @ por un punto] txt-record-name</code><br/>Ejemplo: <code>team.froxlor.org. froxlor.org.</code>',
			'SRV' => 'Registro de ubicación de servicio, utilizado para protocolos más recientes en lugar de crear registros específicos de protocolo como MX.<br/>Estructura: <code>priority weight port target</code><br/>Ejemplo: <code>0 5 5060 sipserver.example.com.</code><br/>Nota: Para la prioridad, utilice el campo anterior.',
			'SSHFP' => 'El registro de recursos SSHFP se utiliza para publicar huellas digitales de claves de shell seguro (SSH) en el DNS.<br/>Estructura: <code>tipo de algoritmo huella digital</code><br/>Algoritmos: 0: reservado <code>, 1: RSA, 2: DSA, 3: ECDSA, 4: Ed25519, 6: Ed448</code><br/>Tipos: 0 <code>: reservado, 1: SHA-1, 2: SHA-256</code><br/>Ejemplo: <code>2 1 123456789abcdef67890123456789abcdef67890</code>',
			'TXT' => 'Texto descriptivo de libre definición.'
		]
	],
	'domain' => [
		'openbasedirpath' => 'Ruta OpenBasedir',
		'docroot' => 'Ruta del campo anterior',
		'homedir' => 'Directorio de inicio',
		'docparent' => 'Directorio padre de la ruta del campo anterior',
    'ssl_certificate_placeholder' => '---- BEGIN CERTIFICATE---' . PHP_EOL . '[...]' . PHP_EOL . '----END CERTIFICATE----',
    'ssl_key_placeholder' => '---- BEGIN RSA PRIVATE KEY-----' . PHP_EOL . '[...]' . PHP_EOL . '-----END RSA PRIVATE KEY-----',
	],
	'domains' => [
		'description' => 'Aquí puede crear (sub)dominios y cambiar sus rutas.<br/>El sistema necesitará algún tiempo para aplicar la nueva configuración después de cada cambio.',
		'domainsettings' => 'Configuración del dominio',
		'domainname' => 'Nombre de dominio',
		'subdomain_add' => 'Crear subdominio',
		'subdomain_edit' => 'Editar (sub)dominio',
		'wildcarddomain' => '¿Crear como dominio comodín?',
		'aliasdomain' => 'Alias para dominio',
		'noaliasdomain' => 'Sin alias de dominio',
		'hasaliasdomains' => 'Tiene dominio(s) alias',
		'statstics' => 'Estadísticas de uso',
		'isassigneddomain' => 'Dominio asignado',
		'add_date' => 'Añadido a froxlor',
		'registration_date' => 'Añadido al registro',
		'topleveldomain' => 'Top-Level-Dominio',
		'associated_with_domain' => 'Asociado',
		'aliasdomains' => 'Alias dominios',
		'redirectifpathisurl' => 'Código de redirección (por defecto: vacío)',
		'redirectifpathisurlinfo' => 'Sólo tiene que seleccionar una de estas opciones si ha introducido una URL como ruta<br/><strong class="text-danger">NOTA:</strong> Los cambios sólo se aplican si la ruta indicada es una URL.',
		'ipandport_multi' => [
			'title' => 'Direcciones IP',
			'description' => 'Especifique una o más direcciones IP para el dominio.<br/><br/><div class="text-danger">NOTA: Las direcciones IP no pueden cambiarse cuando el dominio está configurado como <strong>alias-dominio</strong> de otro dominio.</div>'
		],
		'ipandport_ssl_multi' => [
			'title' => 'Dirección(es) IP SSL'
		],
		'ssl_redirect' => [
			'title' => 'Redirección SSL',
			'description' => 'Esta opción crea redireccionamientos para vhosts no SSL de forma que todas las peticiones son redirigidas al vhost SSL.<br/><br/>p.e. una petición a <strong>http://domain.tld/</strong> le redirigirá a <strong>https://domain.tld/</strong>'
		],
		'serveraliasoption_wildcard' => 'Comodín (*.dominio.tld)',
		'serveraliasoption_www' => 'WWW (www.domain.tld)',
		'serveraliasoption_none' => 'Sin alias',
		'domain_import' => 'Importar dominios',
		'import_separator' => 'Separador',
		'import_offset' => 'Desplazamiento',
		'import_file' => 'Archivo CSV',
		'import_description' => 'Para obtener información detallada sobre la estructura del archivo de importación y sobre cómo realizar la importación correctamente, visite <a href="https://docs.froxlor.org/latest/admin-guide/domain-import/" target="_blank" class="alert-link">https://docs.froxlor.org/latest/admin-guide/domain-import/</a>.',
		'ssl_redirect_temporarilydisabled' => '<br/>La redirección SSL se desactiva temporalmente mientras se genera un nuevo certificado Let\'s Encrypt. Se volverá a activar una vez generado el certificado.',
		'termination_date' => 'Fecha de terminación',
		'termination_date_overview' => 'terminado a partir de ',
		'ssl_certificates' => 'Certificados SSL',
		'ssl_certificate_removed' => 'El certificado con el id #%s ha sido eliminado con éxito',
		'ssl_certificate_error' => 'Error al leer el certificado para el dominio: %s',
		'no_ssl_certificates' => 'No hay dominios con certificado SSL',
		'isaliasdomainof' => 'Es aliasdomain para %s',
		'isbinddomain' => 'Crear zona DNS',
		'dkimenabled' => 'DKIM activado',
		'openbasedirenabled' => 'Restricción de Openbasedir',
		'hsts' => 'HSTS habilitado',
		'aliasdomainid' => 'ID de aliasdominio'
	],
	'emails' => [
		'description' => 'Aquí puedes crear y modificar tus direcciones de correo electrónico.<br/>Una cuenta es como el buzón que tienes delante de casa. Si alguien le envía un correo electrónico, éste caerá en la cuenta.<br/><br/>Para descargar sus correos electrónicos utilice la siguiente configuración en su programa de correo: (¡Los datos en <i>cursiva</i> deben cambiarse por los equivalentes que haya escrito!)<br/>Hostname: <b><i>nombre del dominio</i></b><br/>Username: <b><i>nombre de la cuenta / dirección de correo electrónico</i></b><br/>password: <b><i>la contraseña que haya elegido</i></b>',
		'emailaddress' => 'Dirección de correo electrónico',
		'emails_add' => 'Crear dirección de correo electrónico',
		'emails_edit' => 'Editar dirección de correo electrónico',
		'catchall' => 'Catchall',
		'iscatchall' => '¿Definir como dirección "catchall"?',
		'account' => 'Cuenta',
		'account_add' => 'Crear cuenta',
		'account_delete' => 'Eliminar cuenta',
		'from' => 'Fuente',
		'to' => 'Destino',
		'forwarders' => 'Transitarios',
		'forwarder_add' => 'Crear expedidor',
		'alternative_emailaddress' => 'Dirección de correo electrónico alternativa',
		'quota' => 'Cuota',
		'noquota' => 'Sin cuota',
		'updatequota' => 'Actualizar cuota',
		'quota_edit' => 'Modificar cuota de correo electrónico',
		'noemaildomainaddedyet' => 'Aún no tiene un dominio (de correo electrónico) en su cuenta.',
		'back_to_overview' => 'Volver a la vista general de dominios',
		'accounts' => 'Cuentas',
		'emails' => 'Direcciones'
	],
	'error' => [
		'error' => 'Error',
		'directorymustexist' => 'El directorio %s debe existir. Por favor, créalo con tu cliente FTP.',
		'filemustexist' => 'El archivo %s debe existir.',
		'allresourcesused' => 'Ya ha utilizado todos sus recursos.',
		'domains_cantdeletemaindomain' => 'No puede eliminar un dominio asignado.',
		'domains_canteditdomain' => 'No puede editar este dominio. Ha sido desactivado por el administrador.',
		'domains_cantdeletedomainwithemail' => 'No puede eliminar un dominio que se utiliza como dominio de correo electrónico. Elimine primero todas las direcciones de correo electrónico.',
		'firstdeleteallsubdomains' => 'Antes de crear un dominio comodín, debe eliminar todos los subdominios.',
		'youhavealreadyacatchallforthisdomain' => 'Ya ha definido un dominio comodín para este dominio.',
		'ftp_cantdeletemainaccount' => 'No puede eliminar su cuenta FTP principal',
		'login' => 'El nombre de usuario o la contraseña que has introducido son incorrectos. Inténtalo de nuevo.',
		'login_blocked' => 'Esta cuenta ha sido suspendida debido a demasiados errores de inicio de sesión. <br/>Por favor, inténtelo %s nuevo en segundos.',
		'notallreqfieldsorerrors' => 'No ha rellenado todos los campos o ha rellenado algunos incorrectamente.',
		'oldpasswordnotcorrect' => 'La contraseña antigua no es correcta.',
		'youcantallocatemorethanyouhave' => 'No puede asignarse más recursos de los que posee.',
		'mustbeurl' => 'No has escrito una url válida o completa (por ejemplo http://somedomain.com/error404.htm)',
		'invalidpath' => 'No ha elegido una URL válida (¿quizás problemas con la lista de direcciones?)',
		'stringisempty' => 'Falta información en el campo',
		'stringiswrong' => 'Campo incorrecto',
		'newpasswordconfirmerror' => 'La nueva contraseña y la confirmación no coinciden',
		'mydomain' => 'Dominio',
		'mydocumentroot' => 'Documentroot',
		'loginnameexists' => 'Loginname %s ya existe',
		'emailiswrong' => 'Email-address %s contiene caracteres no válidos o está incompleto',
		'alternativeemailiswrong' => 'Las %s dirección de correo electrónico alternativas dadas para enviar las credenciales parecen no ser válidas',
		'loginnameiswrong' => 'Loginname "%s" contiene caracteres ilegales.',
		'loginnameiswrong2' => 'Loginname contiene demasiados caracteres. Sólo se permiten caracteres de %s.',
		'userpathcombinationdupe' => 'La combinación de nombre de usuario y ruta ya existe',
		'patherror' => 'Error general La ruta no puede estar vacía',
		'errordocpathdupe' => 'La opción para la %s la ruta ya existe',
		'adduserfirst' => 'Por favor, cree primero un cliente',
		'domainalreadyexists' => 'El %s dominio ya está asignado a un cliente',
		'nolanguageselect' => 'No se ha seleccionado ningún idioma.',
		'nosubjectcreate' => 'Debe definir un asunto para esta plantilla de correo.',
		'nomailbodycreate' => 'Debe definir un texto de correo para esta plantilla de correo.',
		'templatenotfound' => 'No se ha encontrado la plantilla.',
		'alltemplatesdefined' => 'No puede definir más plantillas, todos los idiomas ya están soportados.',
		'wwwnotallowed' => 'www no está permitido para subdominios.',
		'subdomainiswrong' => 'La %s del subdominio contiene caracteres no válidos.',
		'domaincantbeempty' => 'El nombre de dominio no puede estar vacío.',
		'domainexistalready' => 'El dominio %s ya existe.',
		'domainisaliasorothercustomer' => 'El dominio alias seleccionado es en sí mismo un dominio alias, tiene una combinación ip/puerto diferente o pertenece a otro cliente.',
		'emailexistalready' => 'La dirección de correo electrónico %s ya existe.',
		'maindomainnonexist' => 'El dominio principal %s no existe.',
		'destinationnonexist' => 'Por favor, cree su redireccionador en el campo "Destino".',
		'destinationalreadyexistasmail' => 'El remitente a %s ya existe como dirección de correo electrónico activa.',
		'destinationalreadyexist' => 'Ya ha definido un reenviador para "%s".',
		'destinationiswrong' => 'La %s la redirección contiene caracteres no válidos o está incompleta.',
		'templatelanguagecombodefined' => 'La combinación idioma/plantilla seleccionada ya ha sido definida.',
		'templatelanguageinvalid' => 'El idioma seleccionado no existe.',
		'ipstillhasdomains' => 'La combinación IP/Puerto que desea eliminar todavía tiene dominios asignados, por favor reasígnelos a otras combinaciones IP/Puerto antes de eliminar esta combinación IP/Puerto.',
		'cantdeletedefaultip' => 'No puede borrar la combinación IP/Puerto por defecto, por favor haga otra combinación IP/Puerto por defecto para antes de borrar esta combinación IP/Puerto.',
		'cantdeletesystemip' => 'No puede borrar la última IP del sistema, cree una nueva combinación IP/Puerto para la IP del sistema o cambie la IP del sistema.',
		'myipaddress' => 'IP',
		'myport' => 'Puerto',
		'myipdefault' => 'Debe seleccionar una combinación IP/Puerto que se convierta en predeterminada.',
		'myipnotdouble' => 'Esta combinación IP/Puerto ya existe.',
		'admin_domain_emailsystemhostname' => 'El nombre de host del servidor no se puede utilizar como dominio del cliente.',
		'cantchangesystemip' => 'No puede cambiar la última IP del sistema, cree otra nueva combinación IP/Puerto para la IP del sistema o cambie la IP del sistema.',
		'sessiontimeoutiswrong' => 'Sólo se permite un "tiempo de espera de sesión" numérico.',
		'maxloginattemptsiswrong' => 'Sólo se permiten "intentos de inicio de sesión máximos" numéricos.',
		'deactivatetimiswrong' => 'Sólo se permite "tiempo de desactivación" numérico.',
		'accountprefixiswrong' => 'El "customerprefix" es incorrecto.',
		'mysqlprefixiswrong' => 'El "prefijo SQL" es incorrecto.',
		'ftpprefixiswrong' => 'El "prefijo FTP" es incorrecto.',
		'ipiswrong' => 'La "dirección IP" es incorrecta. Sólo se permite una dirección IP válida.',
		'vmailuidiswrong' => 'El "mails-uid" es incorrecto. Sólo se permite un UID numérico.',
		'vmailgidiswrong' => 'El "mails-gid" es incorrecto. Sólo se permite un GID numérico.',
		'adminmailiswrong' => 'La dirección del remitente es incorrecta. Sólo se permite una dirección de correo electrónico válida.',
		'pagingiswrong' => 'El valor "entries per page" es incorrecto. Sólo se permiten caracteres numéricos.',
		'phpmyadminiswrong' => 'El enlace phpMyAdmin no es un enlace válido.',
		'webmailiswrong' => 'El enlace webmail no es un enlace válido.',
		'webftpiswrong' => 'El enlace WebFTP no es un enlace válido.',
		'stringformaterror' => 'El valor del campo "%s" no tiene el formato esperado.',
		'loginnameisusingprefix' => 'No puede crear cuentas que empiecen por "%s", ya que este prefijo está configurado para ser utilizado en la asignación automática de nombres de cuenta. Por favor, introduzca otro nombre de cuenta.',
		'loginnameissystemaccount' => 'La cuenta "%s" ya existe en el sistema y no se puede utilizar. Por favor, introduzca otro nombre de cuenta.',
		'youcantdeleteyourself' => 'No puede borrarse por razones de seguridad.',
		'youcanteditallfieldsofyourself' => 'Nota: No puede editar todos los campos de su propia cuenta por razones de seguridad.',
		'documentrootexists' => 'El directorio "%s" ya existe para este cliente. Por favor, elimínelo antes de añadir el cliente de nuevo.',
		'norepymailiswrong' => 'La dirección "Noreply-address" es incorrecta. Sólo se permite una dirección de correo electrónico válida.',
		'logerror' => 'Log-Error: %s',
		'nomessagetosend' => 'No ha introducido ningún mensaje.',
		'norecipientsgiven' => 'No ha especificado ningún destinatario',
		'errorsendingmail' => 'El mensaje a "%s" ha fallado',
		'errorsendingmailpub' => 'El mensaje a la dirección de correo electrónico indicada ha fallado',
		'cannotreaddir' => 'No se ha podido leer el directorio "%s".',
		'invalidip' => 'Dirección IP no válida: %s',
		'invalidmysqlhost' => 'Dirección de host MySQL no válida: %s',
		'cannotuseawstatsandwebalizeratonetime' => 'No puede activar Webalizer y AWstats al mismo tiempo, por favor elija uno de ellos.',
		'cannotwritetologfile' => 'No se puede abrir el archivo de registro %s para escribir',
		'vmailquotawrong' => 'El quotasize debe ser un número positivo.',
		'allocatetoomuchquota' => 'Ha intentado asignar la cuota %s MB, pero no tiene suficiente.',
		'missingfields' => 'No se han rellenado todos los campos obligatorios.',
		'requiredfield' => 'Este campo es obligatorio.',
		'accountnotexisting' => 'La cuenta de correo electrónico indicada no existe.',
		'nopermissionsorinvalidid' => 'No tiene permisos suficientes para cambiar esta configuración o se ha introducido un identificador no válido.',
		'phpsettingidwrong' => 'No existe una configuración PHP con este id.',
		'descriptioninvalid' => 'La descripción es demasiado corta, demasiado larga o contiene caracteres ilegales.',
		'info' => 'Información',
		'filecontentnotset' => 'El archivo no puede estar vacío.',
		'index_file_extension' => 'La extensión del fichero índice debe tener entre 1 y 6 caracteres. La extensión sólo puede contener caracteres como a-z, A-Z y 0-9',
		'customerdoesntexist' => 'El cliente seleccionado no existe.',
		'admindoesntexist' => 'El administrador elegido no existe.',
		'ipportdoesntexist' => 'La combinación ip/puerto que ha elegido no existe.',
		'usernamealreadyexists' => 'El nombre de usuario %s ya existe.',
		'plausibilitychecknotunderstood' => 'No se ha entendido la respuesta de la comprobación de plausibilidad.',
		'errorwhensaving' => 'Se ha producido un error al guardar la %s campos',
		'hiddenfieldvaluechanged' => 'El valor del campo oculto "%s" ha cambiado al editar la configuración.<br/><br/>Esto no suele ser un gran problema, pero la configuración no se ha podido guardar por este motivo.',
		'notrequiredpasswordlength' => 'La contraseña introducida es demasiado corta. Por favor, introduzca al menos caracteres de %s.',
		'overviewsettingoptionisnotavalidfield' => 'Ups, un campo que debería mostrarse como una opción en la vista de configuración no es un tipo exceptuado. Puedes culpar a los desarrolladores por esto. Esto no debería ocurrir.',
		'pathmaynotcontaincolon' => 'La ruta introducida no debe contener dos puntos (":"). Por favor, introduzca un valor de ruta correcto.',
		'exception' => '%s',
		'notrequiredpasswordcomplexity' => 'La complejidad de la contraseña especificada no se ha cumplido.<br/>Póngase en contacto con su administrador si tiene alguna duda sobre la complejidad especificada.',
		'invaliderrordocumentvalue' => 'El valor dado como ErrorDocument no parece ser un archivo, URL o cadena válidos.',
		'intvaluetoolow' => 'El número dado es demasiado bajo (campo %s))',
		'intvaluetoohigh' => 'El número dado es demasiado alto (campo %s)',
		'phpfpmstillenabled' => 'PHP-FPM está actualmente activo. Desactívelo antes de activar FCGID.',
		'fcgidstillenabled' => 'FCGID está actualmente activo. Desactívelo antes de activar PHP-FPM.',
		'domains_cantdeletedomainwithaliases' => 'No se puede eliminar un dominio que se utiliza para alias. Primero debe eliminar los alias.',
		'user_banned' => 'Su cuenta ha sido bloqueada. Por favor, contacte con su administrador para más información.',
		'session_timeout' => 'Valor demasiado bajo',
		'session_timeout_desc' => 'El tiempo de espera de la sesión no debe ser inferior a 1 minuto.',
		'invalidhostname' => 'El nombre de host debe ser un dominio válido. No puede estar vacío ni estar formado sólo por espacios en blanco.',
		'operationnotpermitted' => 'Operación no permitida',
		'featureisdisabled' => 'La función de %s está desactivada. Póngase en contacto con su proveedor de servicios.',
		'usercurrentlydeactivated' => 'El usuario %s está actualmente desactivado',
		'setlessthanalreadyused' => 'No puede establecer menos recursos de \'%s\' de los que este usuario ya ha utilizado<br/>',
		'stringmustntbeempty' => 'El valor del campo %s no debe estar vacío',
		'sslcertificateismissingprivatekey' => 'Necesita especificar una clave privada para su certificado',
		'sslcertificatewrongdomain' => 'El certificado indicado no pertenece a este dominio',
		'sslcertificateinvalidcert' => 'El contenido del certificado indicado no parece ser un certificado válido.',
		'sslcertificateinvalidcertkeypair' => 'La clave privada indicada no pertenece al certificado en cuestión.',
		'sslcertificateinvalidca' => 'Los datos del certificado de la CA no parecen ser un certificado válido.',
		'sslcertificateinvalidchain' => 'Los datos de la cadena del certificado no parecen ser un certificado válido.',
		'givendirnotallowed' => 'El directorio indicado en el campo %s no está permitido.',
		'sslredirectonlypossiblewithsslipport' => 'El uso de Let\'s Encrypt sólo es posible cuando el dominio tiene asignada al menos una combinación IP/puerto habilitada para ssl.',
		'fcgidstillenableddeadlock' => 'FCGID está actualmente activo.<br/>Por favor, desactívelo antes de cambiar a otro servidor web que no sea Apache2',
		'send_report_title' => 'Enviar informe de error',
		'send_report_desc' => 'Gracias por informar de este error y ayudarnos a mejorar froxlor.<br/>Este es el correo electrónico que se enviará al equipo de desarrolladores de froxlor:',
		'send_report' => 'Enviar informe',
		'send_report_error' => 'Error al enviar el informe: <br/>%s',
		'notallowedtouseaccounts' => 'Tu cuenta no permite usar IMAP/POP3. No puedes añadir cuentas de correo.',
		'cannotdeletehostnamephpconfig' => 'Esta configuración PHP es usada por el froxlor-vhost y no puede ser borrada.',
		'cannotdeletedefaultphpconfig' => 'Esta configuración PHP está establecida por defecto y no puede ser borrada.',
		'passwordshouldnotbeusername' => 'La contraseña no debe ser la misma que el nombre de usuario.',
		'no_phpinfo' => 'Lo sentimos, no puedo leer phpinfo()',
		'moveofcustomerfailed' => 'El cambio del cliente al administrador/revendedor seleccionado ha fallado. Tenga en cuenta que todos los demás cambios en el cliente se aplicaron con éxito en esta etapa.<br/><br/>Mensaje de error: %s',
		'domain_import_error' => 'Se ha producido el siguiente error al importar dominios: %s',
		'fcgidandphpfpmnogoodtogether' => 'FCGID y PHP-FPM no pueden ser activados al mismo tiempo',
		'no_apcuinfo' => 'No hay información de caché disponible. APCu no parece estar ejecutándose.',
		'no_opcacheinfo' => 'No hay información de caché disponible. OPCache no parece estar ejecutándose.',
		'nowildcardwithletsencrypt' => 'Let\'s Encrypt no puede manejar dominios comodín usando ACME en froxlor (requiere dns-challenge), lo siento. Por favor, establezca el ServerAlias a WWW o desactívelo completamente.',
		'customized_version' => 'Parece que tu instalación de froxlor ha sido modificada, no hay soporte, lo sentimos.',
		'autoupdate_0' => 'Error desconocido',
		'autoupdate_1' => 'El ajuste de PHP allow_url_fopen está desactivado. Autoupdate necesita que este ajuste esté habilitado en php.ini',
		'autoupdate_2' => 'Extensión PHP zip no encontrada, por favor asegúrese de que está instalada y activada',
		'autoupdate_4' => 'El archivo froxlor no pudo ser almacenado en el disco :(',
		'autoupdate_5' => 'version.froxlor.org devolvió valores inaceptables :(',
		'autoupdate_6' => 'Whoops, no había una versión (válida) dada para descargar :(',
		'autoupdate_7' => 'No se pudo encontrar el archivo descargado :(',
		'autoupdate_8' => 'No se ha podido extraer el archivo :(',
		'autoupdate_9' => 'El archivo descargado no ha pasado la comprobación de integridad. Por favor, intente actualizar de nuevo.',
		'autoupdate_10' => 'La versión mínima soportada de PHP es 7.4.0',
		'autoupdate_11' => 'Webupdate está desactivado',
		'mailaccistobedeleted' => 'Otra cuenta con el mismo nombre (%s) está siendo eliminada y por lo tanto no puede ser añadida en este momento.',
		'dns_domain_nodns' => 'DNS no está habilitado para este dominio',
		'dns_content_empty' => 'No hay contenido',
		'dns_content_invalid' => 'El contenido DNS no es válido',
		'dns_arec_noipv4' => 'No se ha proporcionado una dirección IP válida para el registro A.',
		'dns_aaaarec_noipv6' => 'No se ha indicado una dirección IP válida para el registro AAAA',
		'dns_mx_prioempty' => 'Prioridad MX no válida',
		'dns_mx_needdom' => 'El valor de contenido MX debe ser un nombre de dominio válido.',
		'dns_mx_noalias' => 'El valor de contenido MX no puede ser una entrada CNAME.',
		'dns_cname_invaliddom' => 'Nombre de dominio no válido para el registro CNAME',
		'dns_cname_nomorerr' => 'Ya existe un resource-record con el mismo nombre de registro. No se puede utilizar como CNAME.',
		'dns_other_nomorerr' => 'Ya existe un registro CNAME con el mismo nombre de registro. No se puede utilizar para otro tipo.',
		'dns_ns_invaliddom' => 'Nombre de dominio no válido para el registro NS',
		'dns_srv_prioempty' => 'Prioridad SRV no válida',
		'dns_srv_invalidcontent' => 'Contenido SRV no válido, debe contener los campos weight, port y target, p.ej: 5 5060 sipserver.ejemplo.com.',
		'dns_srv_needdom' => 'El valor SRV target debe ser un nombre de dominio válido',
		'dns_srv_noalias' => 'El valor SRV-target no puede ser una entrada CNAME.',
		'dns_duplicate_entry' => 'El registro ya existe',
		'dns_notfoundorallowed' => 'Dominio no encontrado o sin permiso',
		'domain_nopunycode' => 'No debe especificar punycode (IDNA). El dominio se convertirá automáticamente',
		'dns_record_toolong' => 'Los registros/etiquetas sólo pueden tener un máximo de 63 caracteres',
		'noipportgiven' => 'No se ha especificado IP/puerto',
		'jsonextensionnotfound' => 'Esta función requiere la extensión php json.',
		'cannotdeletesuperadmin' => 'El primer administrador no puede ser eliminado.',
		'no_wwwcnamae_ifwwwalias' => 'No se puede establecer un registro CNAME para "www" porque el dominio está configurado para generar un alias www. Cambie la configuración a "Sin alias" o "Alias comodín".',
		'local_group_exists' => 'El grupo indicado ya existe en el sistema.',
		'local_group_invalid' => 'El nombre del grupo no es válido',
		'invaliddnsforletsencrypt' => 'El DNS del dominio no incluye ninguna de las direcciones IP seleccionadas. La generación del certificado Let\'s Encrypt no es posible.',
		'notallowedphpconfigused' => 'Intentando usar php-config que no está asignado al cliente',
		'pathmustberelative' => 'El usuario no tiene permiso para especificar directorios fuera del directorio personal del cliente. Por favor, especifique una ruta relativa (sin /).',
		'mysqlserverstillhasdbs' => 'No se puede eliminar el servidor de base de datos de la lista de clientes permitidos, ya que todavía hay bases de datos en él.',
		'domaincannotbeedited' => 'No se le permite editar la %s dominio.',
		'invalidcronjobintervalvalue' => 'El intervalo de Cronjob debe ser uno de los siguientes: %s'
	],
	'extras' => [
		'description' => 'Aquí puede añadir algunos extras, por ejemplo protección de directorios.<br/>El sistema necesitará algún tiempo para aplicar la nueva configuración después de cada cambio.',
		'directoryprotection_add' => 'Añadir protección de directorio',
		'view_directory' => 'Mostrar el contenido del directorio',
		'pathoptions_add' => 'Añadir opciones de ruta',
		'directory_browsing' => 'Exploración del contenido del directorio',
		'pathoptions_edit' => 'Editar opciones de ruta',
		'error404path' => '404',
		'error403path' => '403',
		'error500path' => '500',
		'error401path' => '401',
		'errordocument404path' => 'DocumentoError 404',
		'errordocument403path' => 'DocumentoError 403',
		'errordocument500path' => 'DocumentoError 500',
		'errordocument401path' => 'DocumentoError 401',
		'execute_perl' => 'Ejecutar perl/CGI',
		'htpasswdauthname' => 'Razón de autenticación (AuthName)',
		'directoryprotection_edit' => 'Editar protección de directorio',
		'path_protection_label' => '<strong class="text-danger">Importante</strong>',
		'path_protection_info' => 'Le recomendamos encarecidamente que proteja la ruta indicada, consulte "Extras" -> "Protección de directorios".'
	],
	'ftp' => [
		'description' => 'Aquí puede crear y modificar sus cuentas FTP.<br/>Los cambios se realizan al instante y las cuentas pueden utilizarse inmediatamente.',
		'account_add' => 'Crear cuenta',
		'account_edit' => 'Editar cuenta ftp',
		'editpassdescription' => 'Establezca una nueva contraseña o déjela en blanco para no cambiarla.'
	],
	'gender' => [
		'title' => 'Título',
		'male' => 'Sr.',
		'female' => 'Sra.',
		'undef' => ''
	],
	'imprint' => 'Aviso legal',
	'index' => [
		'customerdetails' => 'Datos del cliente',
		'accountdetails' => 'Datos de la cuenta'
	],
	'integrity_check' => [
		'databaseCharset' => 'Juego de caracteres de la base de datos (debe ser UTF-8)',
		'domainIpTable' => 'Referencias IP <-> dominio',
		'subdomainSslRedirect' => 'Bandera falsa SSL-redirect para dominios no SSL',
		'froxlorLocalGroupMemberForFcgidPhpFpm' => 'froxlor-usuario en los grupos de clientes (para FCGID/php-fpm)',
		'webserverGroupMemberForFcgidPhpFpm' => 'Webserver-user en los grupos de clientes (para FCGID/php-fpm)',
		'subdomainLetsencrypt' => 'Los dominios principales sin puerto SSL asignado no tienen subdominios con redirección SSL activa'
	],
	'logger' => [
		'date' => 'Fecha',
		'type' => 'Tipo',
		'action' => 'Acción',
		'user' => 'Usuario',
		'truncate' => 'Registro vacío',
		'reseller' => 'Revendedor',
		'admin' => 'Administrador',
		'cron' => 'Cronjob',
		'login' => 'Inicio de sesión',
		'intern' => 'Interno',
		'unknown' => 'Desconocido'
	],
	'login' => [
		'username' => 'Nombre de usuario',
		'password' => 'Contraseña',
		'language' => 'Idioma',
		'login' => 'Inicio de sesión',
		'logout' => 'Cierre de sesión',
		'profile_lng' => 'Idioma del perfil',
		'welcomemsg' => 'Inicie sesión para acceder a su cuenta.',
		'forgotpwd' => '¿Ha olvidado su contraseña?',
		'presend' => 'Restablecer contraseña',
		'email' => 'Correo electrónico',
		'remind' => 'Restablecer mi contraseña',
		'usernotfound' => 'Usuario no encontrado',
		'backtologin' => 'Volver al inicio de sesión',
		'combination_not_found' => 'No se ha encontrado la combinación de usuario y dirección de correo electrónico.',
		'2fa' => 'Autenticación de dos factores (2FA)',
		'2facode' => 'Introduzca el código 2FA'
	],
	'mails' => [
		'pop_success' => [
			'mailbody' => 'Hola,\\nsu cuenta de correo {EMAIL} configurado correctamente.\\nEste es un correo creado\\nautomáticamente, ¡por favor no conteste!\\nSu atentamente, su administrador',
			'subject' => 'Cuenta de correo configurada correctamente'
		],
		'createcustomer' => [
			'mailbody' => 'Hola {SALUTATION}, aquí están los datos de su cuenta: Nombre de usuario: {USERNAME}: {PASSWORD}, su administrador.',
			'subject' => 'Información de la cuenta'
		],
		'pop_success_alternative' => [
			'mailbody' => 'Hola {SALUTATION}, su cuenta de correo {EMAIL} se ha configurado correctamente. Su contraseña es {PASSWORD}. Este es un correo creado automáticamente, por favor no conteste. Atentamente, su administrador.',
			'subject' => 'Cuenta de correo configurada correctamente'
		],
		'password_reset' => [
			'subject' => 'Restablecer contraseña',
			'mailbody' => 'Hola {SALUTATION}, aquí está su enlace para establecer una nueva contraseña. Este enlace es válido durante las próximas 24 horas. {LINK}, su administrador.'
		],
		'new_database_by_customer' => [
			'subject' => '[Nueva base de datos creada',
			'mailbody' => 'Hola {CUST_NAME},

acabas de añadir una nueva base de datos. Aquí está la información introducida:

Nombre de base de datos: {DB_NAME}
Contraseña: {DB_PASS}
Descripción: {DB_DESC}
Nombre de host de base de datos: {DB_SRV}
phpMyAdmin: {PMA_URI}
Atentamente, su administrador'
		],
		'new_ftpaccount_by_customer' => [
			'subject' => 'Nuevo usuario ftp creado',
			'mailbody' => 'Hola {CUST_NAME}

acabas de añadir un nuevo usuario ftp. Aquí está la información introducida:

Nombre de usuario: {USR_NAME}
Contraseña: {USR_PASS}
Ruta: {USR_PATH}

Atentamente, su administrador'
		],
		'trafficmaxpercent' => [
			'mailbody' => 'Estimado {SALUTATION}, ha utilizado {TRAFFICUSED} del {MAX_PERCENT} de su {TRAFFIC} disponible de tráfico.',
			'subject' => 'Alcanzando su límite de tráfico'
		],
		'diskmaxpercent' => [
			'mailbody' => 'Estimado {SALUTATION}, ha utilizado el {DISKUSED} de su {DISKAVAILABLE} disponible de espacio en disco. Esto es más del {MAX_PERCENT}.',
			'subject' => 'Alcanzando el límite de espacio en disco'
		],
		'2fa' => [
			'mailbody' => 'Hola, su código de acceso 2FA es..: {CODE}. Este es un correo creado automáticamente, por favor no responda. Atentamente, su administrador.',
			'subject' => 'froxlor - Código 2FA'
		]
	],
	'menue' => [
		'main' => [
			'main' => 'Principal',
			'changepassword' => 'Cambiar contraseña',
			'changelanguage' => 'Cambiar idioma',
			'username' => 'Iniciar sesión como ',
			'changetheme' => 'Cambiar tema',
			'apihelp' => 'Ayuda API',
			'apikeys' => 'Claves de la API'
		],
		'email' => [
			'email' => 'Correo electrónico',
			'emails' => 'Direcciones',
			'webmail' => 'Correo web',
			'emailsoverview' => 'Vista general de dominios de correo electrónico'
		],
		'mysql' => [
			'mysql' => 'MySQL',
			'databases' => 'Bases de datos',
			'phpmyadmin' => 'phpMyAdmin'
		],
		'domains' => [
			'domains' => 'Dominios',
			'settings' => 'Vista general de dominios'
		],
		'ftp' => [
			'ftp' => 'FTP',
			'accounts' => 'Cuentas',
			'webftp' => 'WebFTP'
		],
		'extras' => [
			'extras' => 'Extras',
			'directoryprotection' => 'Protección de directorios',
			'pathoptions' => 'Opciones de ruta',
			'export' => 'Exportación de datos'
		],
		'traffic' => [
			'traffic' => 'Tráfico',
			'current' => 'Mes en curso',
			'overview' => 'Tráfico total'
		],
		'phpsettings' => [
			'maintitle' => 'Configuraciones PHP',
			'fpmdaemons' => 'Versiones de PHP-FPM'
		],
		'logger' => [
			'logger' => 'Registro del sistema'
		]
	],
	'message' => [
		'norecipients' => 'No se ha enviado ningún correo electrónico porque no hay destinatarios en la base de datos',
		'success' => 'Mensaje enviado correctamente a los destinatarios de %s',
	],
	'mysql' => [
		'databasename' => 'Usuario/Nombre de la base de datos',
		'databasedescription' => 'Descripción de la base de datos',
		'database_create' => 'Crear base de datos',
		'description' => 'Aquí puede crear y modificar sus bases de datos MySQL.<br/>Los cambios se realizan al instante y la base de datos se puede utilizar inmediatamente.<br/>En el menú de la izquierda encontrará la herramienta phpMyAdmin con la que puede administrar fácilmente su base de datos.<br/><br/>Para utilizar sus bases de datos en sus propios scripts php utilice los siguientes ajustes: (¡Los datos en <i>cursiva</i> tienen que cambiarse por los equivalentes que haya escrito!)<br/>Nombre de host: <b><sql_host/></b><br/>Nombre de usuario: <b><i>databasename</i></b><br/>Contraseña: <b><i>la contraseña que hayas elegido</i></b><br/>Base de datos: <b><i>databasename</i></b>',
		'mysql_server' => 'Servidor MySQL',
		'database_edit' => 'Editar base de datos',
		'size' => 'Tamaño',
		'privileged_user' => 'Usuario privilegiado de la base de datos',
		'privileged_passwd' => 'Contraseña para usuario privilegiado',
		'unprivileged_passwd' => 'Contraseña para usuario sin privilegios',
		'mysql_ssl_ca_file' => 'Certificado del servidor SSL',
		'mysql_ssl_verify_server_certificate' => 'Verificar certificado de servidor SSL'
	],
	'opcacheinfo' => [
		'generaltitle' => 'Información general',
		'resetcache' => 'Restablecer OPcache',
		'version' => 'Versión de OPCache',
		'phpversion' => 'Versión PHP',
		'runtimeconf' => 'Configuración de tiempo de ejecución',
		'start' => 'Hora de inicio',
		'lastreset' => 'Último reinicio',
		'oomrestarts' => 'Recuento de reinicios OOM',
		'hashrestarts' => 'Recuento de reinicios Hash',
		'manualrestarts' => 'Recuento de reinicios manuales',
		'hitsc' => 'Número de aciertos',
		'missc' => 'Faltas',
		'blmissc' => 'Lista negra',
		'status' => 'Estado',
		'never' => 'nunca',
		'enabled' => 'OPcache activado',
		'cachefull' => 'Caché llena',
		'restartpending' => 'Reinicio pendiente',
		'restartinprogress' => 'Reinicio en curso',
		'cachedscripts' => 'Recuento de scripts en caché',
		'memusage' => 'Uso de memoria',
		'totalmem' => 'Memoria total',
		'usedmem' => 'Memoria utilizada',
		'freemem' => 'Memoria libre',
		'wastedmem' => 'Memoria desperdiciada',
		'maxkey' => 'Teclas máximas',
		'usedkey' => 'Teclas usadas',
		'wastedkey' => 'Teclas desperdiciadas',
		'strinterning' => 'Intercalación de cadenas',
		'strcount' => 'Recuento de cadenas',
		'keystat' => 'Estadística de claves en caché',
		'used' => 'Usado',
		'free' => 'Libre',
		'blacklist' => 'Lista negra',
		'novalue' => '<i>sin valor</i>',
		'true' => '<i>verdadero</i>',
		'false' => '<i>falso</i>',
		'funcsavail' => 'Funciones disponibles'
	],
	'panel' => [
		'edit' => 'Editar',
		'delete' => 'Eliminar',
		'create' => 'Crear',
		'save' => 'Guardar',
		'yes' => 'Sí',
		'no' => 'No',
		'emptyfornochanges' => 'vacío para ningún cambio',
		'emptyfordefault' => 'vacío para valores por defecto',
		'path' => 'Ruta',
		'toggle' => 'Conmutar',
		'next' => 'Siguiente',
		'dirsmissing' => '¡No se puede encontrar o leer el directorio!',
		'unlimited' => '∞',
		'urloverridespath' => 'URL (anula la ruta)',
		'pathorurl' => 'Ruta o URL',
		'ascending' => 'ascendente',
		'descending' => 'descendente',
		'search' => 'Buscar en',
		'used' => 'utilizada',
		'translator' => 'Traductor',
		'reset' => 'Descartar cambios',
		'pathDescription' => 'Si el directorio no existe, se creará automáticamente.',
		'pathDescriptionEx' => '<br/><br/><span class="text-danger">Nota:</span> La ruta <code>/</code> no está permitida debido a la configuración administrativa, se establecerá automáticamente en <code>/elegido.subdominio.tld/</code> si no se establece en otro directorio.',
		'pathDescriptionSubdomain' => 'Si el directorio no existe, se creará automáticamente.<br/><br/>Si desea una redirección a otro dominio, esta entrada debe empezar por http:// o https://.<br/><br/>Si la URL termina en / se considera una carpeta, si no, se trata como archivo.',
		'back' => 'Volver',
		'reseller' => 'revendedor',
		'admin' => 'admin',
		'customer' => 'cliente/s',
		'send' => 'enviar',
		'nosslipsavailable' => 'Actualmente no hay combinaciones ip/puerto ssl para este servidor',
		'backtooverview' => 'Volver a la vista general',
		'dateformat' => 'AAAA-MM-DD',
		'dateformat_function' => 'Y-m-d',
		'timeformat_function' => 'H:i:s',
		'default' => 'Por defecto',
		'never' => 'Nunca',
		'active' => 'Activo',
		'please_choose' => 'Seleccione una opción',
		'allow_modifications' => 'Permitir modificaciones',
		'megabyte' => 'MegaByte',
		'not_supported' => 'No soportado en: ',
		'view' => 'ver',
		'toomanydirs' => 'Demasiados subdirectorios. Volver a la selección manual de ruta.',
		'abort' => 'Abortar',
		'not_activated' => 'no activado',
		'off' => 'desactivado',
		'options' => 'Opciones',
		'neverloggedin' => 'Aún no se ha iniciado sesión',
		'descriptionerrordocument' => 'Puede ser una URL, la ruta a un archivo o simplemente una cadena rodeada de " "<br/>Déjelo vacío para utilizar el valor predeterminado del servidor.',
		'unlock' => 'Desbloquear',
		'theme' => 'Tema',
		'variable' => 'Variable',
		'description' => 'Descripción',
		'cancel' => 'Cancelar',
		'ssleditor' => 'Configuración SSL para este dominio',
		'ssleditor_infoshared' => 'Actualmente usando el certificado del dominio padre',
		'ssleditor_infoglobal' => 'Actualmente usando certificado global',
		'dashboard' => 'Panel de control',
		'assigned' => 'Asignado',
		'available' => 'Disponible',
		'news' => 'Noticias',
		'newsfeed_disabled' => 'La fuente de noticias está desactivada. Haga clic en el icono de edición para ir a la configuración.',
		'ftpdesc' => 'Descripción de FTP',
		'letsencrypt' => 'Usando Let\'s encrypt',
		'set' => 'Aplicar',
		'shell' => 'Shell',
		'backuppath' => [
			'title' => 'Ruta de destino de la copia de seguridad',
			'description' => 'Esta es la ruta donde se almacenarán las copias de seguridad. Si se selecciona la copia de seguridad de los datos web, todos los archivos de la carpeta de inicio se almacenan excluyendo la carpeta de copia de seguridad especificada aquí.'
		],
		'none_value' => 'Ninguno',
		'viewlogs' => 'Ver archivos de registro',
		'not_configured' => 'El sistema aún no está configurado. Pulse aquí para ir a la configuración.',
		'ihave_configured' => 'He configurado los servicios',
		'system_is_configured' => '<i class="fa-solid fa-circle-exclamation me-1"/>El sistema ya está configurado',
		'settings_before_configuration' => 'Por favor, asegúrese de ajustar la configuración antes de configurar los servicios aquí',
		'image_field_delete' => 'Borrar la imagen actual existente',
		'usage_statistics' => 'Uso de recursos',
		'security_question' => 'Cuestión de seguridad',
		'listing_empty' => 'No se han encontrado entradas',
		'unspecified' => 'sin especificar',
		'settingsmode' => 'Modo',
		'settingsmodebasic' => 'Básico',
		'settingsmodeadvanced' => 'Avanzado',
		'settingsmodetoggle' => 'Haga clic para cambiar el modo',
		'modalclose' => 'Cerrar',
		'managetablecolumnsmodal' => [
			'title' => 'Administrar columnas de la tabla',
			'description' => 'Aquí puede personalizar las columnas visibles'
		],
		'mandatoryfield' => 'Campo obligatorio',
		'select_all' => 'Seleccionar todo',
		'unselect_all' => 'Deseleccionar todo',
		'searchtablecolumnsmodal' => [
			'title' => 'Buscar en campos',
			'description' => 'Seleccione el campo en el que desea buscar'
		],
		'upload_import' => 'Cargar e importar'
	],
	'phpfpm' => [
		'vhost_httpuser' => 'Usuario local a usar para PHP-FPM (froxlor vHost)',
		'vhost_httpgroup' => 'Grupo local a usar para PHP-FPM (froxlor vHost)',
		'ownvhost' => [
			'title' => 'Habilitar PHP-FPM para el vHost de froxlor',
			'description' => 'Si está habilitado, froxlor también se ejecutará bajo un usuario local'
		],
		'use_mod_proxy' => [
			'title' => 'Usar mod_proxy / mod_proxy_fcgi',
			'description' => '<strong class="text-danger">Debe activarse cuando se use Debian 9.x (Stretch) o posterior</strong>. Activar para usar php-fpm via mod_proxy_fcgi. Requiere al menos apache-2.4.9'
		],
		'ini_flags' => 'Introduzca posibles <strong>php_flags</strong>para php.ini. Una entrada por línea',
		'ini_values' => 'Introduzca posibles <strong>php_values</strong>para php.ini. Una entrada por línea',
		'ini_admin_flags' => 'Introduzca posibles <strong>php_admin_flags</strong>para php.ini. Una entrada por línea',
		'ini_admin_values' => 'Introduzca posibles <strong>php_admin_values</strong>para php.ini. Una entrada por línea'
	],
	'privacy' => 'Política de privacidad',
	'pwdreminder' => [
		'success' => 'Restablecimiento de contraseña solicitado con éxito. Por favor, siga las instrucciones del correo electrónico que ha recibido.',
		'notallowed' => 'Usuario desconocido o el restablecimiento de contraseña está desactivado',
		'changed' => 'Su contraseña se ha actualizado correctamente. Ya puede iniciar sesión con su nueva contraseña.',
		'wrongcode' => 'Lo sentimos, su código de activación no existe o ya ha caducado.',
		'choosenew' => 'Establecer nueva contraseña'
	],
	'question' => [
		'question' => 'Cuestión de seguridad',
		'admin_customer_reallydelete' => '¿Realmente desea eliminar el cliente %s? No se puede deshacer.',
		'admin_domain_reallydelete' => '¿Realmente quieres borrar el dominio %s?',
		'admin_domain_reallydisablesecuritysetting' => '¿Realmente quieres desactivar esta configuración de seguridad OpenBasedir?',
		'admin_admin_reallydelete' => '¿Realmente quieres borrar el admin %s? Todos los clientes y dominios serán reasignados a tu cuenta.',
		'admin_template_reallydelete' => '¿Realmente quieres borrar la plantilla \'%s\'?',
		'domains_reallydelete' => '¿Realmente quieres borrar el dominio %s?',
		'email_reallydelete' => '¿Realmente quieres borrar la dirección de email %s?',
		'email_reallydelete_account' => '¿Realmente quieres borrar la cuenta de correo de %s?',
		'email_reallydelete_forwarder' => '¿Realmente quieres borrar el forwarder %s?',
		'extras_reallydelete' => '¿Realmente quieres borrar la protección de directorio de %s?',
		'extras_reallydelete_pathoptions' => '¿Realmente quieres borrar las opciones de ruta de %s?',
		'ftp_reallydelete' => '¿Realmente quieres borrar la cuenta FTP %s?',
		'mysql_reallydelete' => '¿Realmente quieres borrar la base de datos %s? Esto no se puede deshacer.',
		'admin_configs_reallyrebuild' => '¿Realmente quieres reconstruir todos los archivos de configuración?',
		'admin_customer_alsoremovefiles' => '¿Quitar también los archivos de usuario?',
		'admin_customer_alsoremovemail' => '¿Eliminar completamente los datos de correo electrónico del sistema de archivos?',
		'admin_customer_alsoremoveftphomedir' => '¿Quitar también el directorio del usuario FTP?',
		'admin_ip_reallydelete' => '¿Realmente quieres borrar la dirección IP %s?',
		'admin_domain_reallydocrootoutofcustomerroot' => '¿Estás seguro de que quieres que la raíz del documento para este dominio no esté dentro de la raíz del cliente?',
		'admin_counters_reallyupdate' => '¿Realmente quiere recalcular el uso de recursos?',
		'admin_cleartextmailpws_reallywipe' => '¿Realmente quiere borrar todas las contraseñas no encriptadas de las cuentas de correo de la tabla mail_users? Esto no se puede revertir. La opción de almacenar las contraseñas de correo electrónico sin cifrar también se desactivará.',
		'logger_reallytruncate' => '¿Realmente quieres truncar la tabla "%s"?',
		'admin_quotas_reallywipe' => '¿Realmente desea borrar todas las cuotas de la tabla mail_users? Esto no se puede revertir.',
		'admin_quotas_reallyenforce' => '¿Realmente desea aplicar la cuota por defecto a todos los usuarios? Esto no se puede revertir.',
		'phpsetting_reallydelete' => '¿Realmente desea eliminar esta configuración? Todos los dominios que usen esta configuración serán cambiados a la configuración por defecto.',
		'fpmsetting_reallydelete' => '¿Realmente desea eliminar esta configuración de php-fpm? Todas las configuraciones de php que utilicen estos ajustes se cambiarán a la configuración por defecto.',
		'customer_reallyunlock' => '¿Realmente quieres desbloquear al cliente %s?',
		'admin_integritycheck_reallyfix' => '¿Realmente quieres intentar arreglar todos los problemas de integridad de la base de datos automáticamente?',
		'plan_reallydelete' => '¿De verdad quieres eliminar el plan de alojamiento %s?',
		'apikey_reallydelete' => '¿Realmente quieres borrar esta api-key?',
		'apikey_reallyadd' => '¿Realmente quieres crear una nueva api-key?',
		'dnsentry_reallydelete' => '¿Realmente desea eliminar esta entrada de zona?',
		'certificate_reallydelete' => '¿Realmente quieres borrar este certificado?',
		'cache_reallydelete' => '¿Realmente quieres borrar la caché?'
	],
	'redirect_desc' => [
		'rc_default' => 'por defecto',
		'rc_movedperm' => 'movido permanentemente',
		'rc_found' => 'encontrado',
		'rc_seeother' => 'ver otro',
		'rc_tempred' => 'redirección temporal'
	],
	'serversettings' => [
		'session_timeout' => [
			'title' => 'Tiempo de espera de la sesión',
			'description' => '¿Cuánto tiempo tiene que estar inactivo un usuario para que se invalide la sesión (segundos)?'
		],
		'accountprefix' => [
			'title' => 'Prefijo de cliente',
			'description' => '¿Qué prefijo deben tener las cuentas de cliente?'
		],
		'mysqlprefix' => [
			'title' => 'Prefijo SQL',
			'description' => '¿Qué prefijo deben tener las cuentas MySQL?<br/>Utilice "RANDOM" como valor para obtener un prefijo aleatorio de 3 dígitos<br/>Utilice "DBNAME" como valor, se utiliza un campo de nombre de base de datos junto con el nombre del cliente como prefijo.'
		],
		'ftpprefix' => [
			'title' => 'Prefijo FTP',
			'description' => '¿Qué prefijo deben tener las cuentas ftp?<br/><b>Si cambias esto, también tendrás que cambiar la consulta SQL Quota en el archivo de configuración del servidor FTP en caso de que lo utilices</b>. '
		],
		'documentroot_prefix' => [
			'title' => 'Directorio de inicio',
			'description' => '¿Dónde deben almacenarse todos los directorios de inicio?'
		],
		'logfiles_directory' => [
			'title' => 'Directorio Logfiles',
			'description' => '¿Dónde deben almacenarse todos los archivos de registro?'
		],
		'logfiles_script' => [
			'title' => 'Script personalizado al que enviar los archivos de registro',
			'description' => 'Puede especificar un script aquí y utilizar los marcadores de posición <strong>{LOGFILE}, {DOMAIN} y {CUSTOMER}</strong> si es necesario. En caso de que desee utilizarlo, deberá activar también la opción <strong>Pipe webserver logfiles</strong>. No es necesario el prefijo pipe.'
		],
		'logfiles_format' => [
			'title' => 'Formato de registro de acceso',
			'description' => 'Introduzca aquí un formato de registro personalizado de acuerdo con las especificaciones de su servidor web, deje vacío por defecto. Dependiendo de su formato, la cadena debe estar entre comillas.<br/>Si se utiliza con nginx, se verá como <i>log_format</i> <i>frx_custom</i> <i> {CONFIGURED_VALUE}</i>.<br/>Si se utiliza con Apache, se verá como <i>LogFormat {CONFIGURED_VALUE} frx_custom</i>.<br/><strong>Atención</strong>: No se comprobará si el código contiene errores. Si contiene errores, ¡el servidor web podría no volver a arrancar!'
		],
		'logfiles_type' => [
			'title' => 'Tipo de registro de acceso',
			'description' => 'Elija aquí entre <strong>combinado</strong> o <strong>vhost_combinado</strong>.'
		],
		'logfiles_piped' => [
			'title' => 'Canalizar los archivos de registro del servidor web al script especificado (ver arriba)',
			'description' => 'Si utiliza un script personalizado para los archivos de registro, deberá activarlo para que se ejecute.'
		],
		'ipaddress' => [
			'title' => 'Dirección IP',
			'description' => '¿Cuál es la dirección IP principal de este servidor?'
		],
		'hostname' => [
			'title' => 'Nombre de host',
			'description' => '¿Cuál es el nombre de host de este servidor?'
		],
		'apachereload_command' => [
			'title' => 'Comando de recarga del servidor web',
			'description' => '¿Cuál es el comando del servidor web para recargar los archivos de configuración?'
		],
		'bindenable' => [
			'title' => 'Habilitar servidor de nombres',
			'description' => 'Aquí se puede habilitar y deshabilitar globalmente el servidor de nombres.'
		],
		'bindconf_directory' => [
			'title' => 'Directorio de configuración del servidor DNS',
			'description' => '¿Dónde deben guardarse los archivos de configuración del servidor DNS?'
		],
		'bindreload_command' => [
			'title' => 'Comando de recarga del servidor DNS',
			'description' => '¿Cuál es el comando para recargar el demonio del servidor DNS?'
		],
		'vmail_uid' => [
			'title' => 'Mails-UID',
			'description' => '¿Qué UserID deben tener los correos?'
		],
		'vmail_gid' => [
			'title' => 'Mails-GID',
			'description' => '¿Qué GroupID debe tener Mails?'
		],
		'vmail_homedir' => [
			'title' => 'Mails-homedir',
			'description' => '¿Dónde deberían almacenarse todos los correos?'
		],
		'adminmail' => [
			'title' => 'Remitente',
			'description' => '¿Cuál es la dirección del remitente para los emails enviados desde el Panel?'
		],
		'phpmyadmin_url' => [
			'title' => 'URL de phpMyAdmin',
			'description' => '¿Cuál es la URL de phpMyAdmin? (debe empezar por http(s)://)'
		],
		'webmail_url' => [
			'title' => 'URL de Webmail',
			'description' => '¿Cuál es la URL de webmail? (debe empezar por http(s)://)'
		],
		'webftp_url' => [
			'title' => 'URL de WebFTP',
			'description' => '¿Cuál es la URL de WebFTP? (debe empezar por http(s)://)'
		],
		'language' => [
			'description' => '¿Cuál es el lenguaje estándar de su servidor?'
		],
		'maxloginattempts' => [
			'title' => 'Número máximo de intentos de inicio de sesión',
			'description' => 'Número máximo de intentos de inicio de sesión tras los cuales se desactiva la cuenta.'
		],
		'deactivatetime' => [
			'title' => 'Tiempo de desactivación',
			'description' => 'Tiempo (seg.) que se desactiva una cuenta después de demasiados intentos de inicio de sesión.'
		],
		'pathedit' => [
			'title' => 'Tipo de entrada de ruta',
			'description' => '¿Debe seleccionarse una ruta mediante un menú desplegable o mediante un campo de entrada?'
		],
		'nameservers' => [
			'title' => 'Servidores de nombres',
			'description' => 'Una lista separada por comas que contiene los nombres de host de todos los servidores de nombres. El primero será el principal.'
		],
		'mxservers' => [
			'title' => 'Servidores MX',
			'description' => 'Una lista separada por comas que contiene un par de un número y un nombre de host separados por espacios en blanco (por ejemplo, \'10 mx.ejemplo.com\') que contiene los servidores mx.'
		],
		'paging' => [
			'title' => 'Entradas por página',
			'description' => '¿Cuántas entradas se mostrarán en una página? (0 = desactivar la paginación)'
		],
		'defaultip' => [
			'title' => 'IP/Puerto por defecto',
			'description' => 'Seleccione todas las direcciones IP que desee utilizar como predeterminadas para los nuevos dominios.'
		],
		'defaultsslip' => [
			'title' => 'IP/Puerto SSL por defecto',
			'description' => 'Seleccione todas las direcciones IP con ssl habilitado que desee utilizar por defecto para los nuevos dominios'
		],
		'phpappendopenbasedir' => [
			'title' => 'Rutas a añadir a OpenBasedir',
			'description' => 'Estas rutas (separadas por dos puntos) se añadirán a la declaración OpenBasedir en cada contenedor vHost.'
		],
		'natsorting' => [
			'title' => 'Usar ordenación humana natural en la vista de lista',
			'description' => 'Ordena las listas como web1 -> web2 -> web11 en lugar de web1 -> web11 -> web2.'
		],
		'deactivateddocroot' => [
			'title' => 'Docroot para usuarios desactivados',
			'description' => 'Cuando un usuario es desactivado esta ruta es usada como su docroot. Dejar vacío para no crear ningún vHost.'
		],
		'mailpwcleartext' => [
			'title' => 'Guardar también las contraseñas de las cuentas de correo sin cifrar en la base de datos',
			'description' => 'Si esta opción está activada, todas las contraseñas serán guardadas sin encriptar (texto claro, legible para cualquiera con acceso a la base de datos) en la tabla mail_users. Active esta opción sólo si desea utilizar SASL.'
		],
		'ftpdomain' => [
			'title' => 'Cuentas FTP @dominio',
			'description' => 'Los clientes pueden crear cuentas FTP user@customerdomain?'
		],
		'mod_fcgid' => [
			'title' => 'Activar FCGID',
			'description' => 'Use esto para ejecutar PHP con la cuenta de usuario correspondiente.<br/><br/><b>Esto necesita una configuración especial del servidor web para Apache, vea <a target="_blank" href="https://docs.froxlor.org/latest/admin-guide/configuration/fcgid/">FCGID - manual</a></b>',
			'configdir' => [
				'title' => 'Directorio de configuración',
				'description' => '¿Dónde deben guardarse todos los archivos de configuración fcgid? Si no utiliza un binario suexec autocompilado, que es la situación normal, esta ruta debe estar bajo /var/www/<br/><br/><div class="text-danger">NOTA: El contenido de esta carpeta se borra regularmente, así que evite almacenar datos allí manualmente.</div>'
			],
			'tmpdir' => [
				'title' => 'Directorio temporal',
				'description' => 'Dónde deben almacenarse los directorios temporales'
			],
			'starter' => [
				'title' => 'Procesos por dominio',
				'description' => '¿Cuántos procesos deberían iniciarse/permitirse por dominio? Se recomienda el valor 0 porque PHP gestionará entonces la cantidad de procesos por sí mismo de forma muy eficiente.'
			],
			'wrapper' => [
				'title' => 'Wrapper en Vhosts',
				'description' => 'Cómo debe incluirse el wrapper en los Vhosts'
			],
			'peardir' => [
				'title' => 'Directorios globales de PEAR',
				'description' => '¿Qué directorios globales de PEAR deben ser reemplazados en cada configuración php.ini? Los diferentes directorios deben estar separados por dos puntos.'
			],
			'maxrequests' => [
				'title' => 'Número máximo de peticiones por dominio',
				'description' => '¿Cuántas peticiones deben permitirse por dominio?'
			],
			'defaultini' => 'Configuración PHP por defecto para nuevos dominios',
			'defaultini_ownvhost' => 'Configuración PHP por defecto para froxlor-vHost',
			'idle_timeout' => [
				'title' => 'Tiempo de espera',
				'description' => 'Configuración de tiempo de espera para Mod FastCGI.'
			]
		],
		'sendalternativemail' => [
			'title' => 'Utilizar una dirección de correo electrónico alternativa',
			'description' => 'Enviar la contraseña a una dirección diferente durante la creación de la cuenta de correo electrónico.'
		],
		'apacheconf_vhost' => [
			'title' => 'Archivo/nombre de directorio de configuración del servidor web vHost',
			'description' => '¿Dónde debe guardarse la configuración del vHost? Puede especificar aquí un archivo (todos los vHosts en un archivo) o un directorio (cada vHost en su propio archivo).'
		],
		'apacheconf_diroptions' => [
			'title' => 'Archivo/nombre de directorio de configuración de diropciones del servidor web',
			'description' => '¿Dónde debe almacenarse la configuración de diroptions? Puede especificar un archivo (todas las diropciones en un archivo) o directorio (cada diropción en su propio archivo) aquí.'
		],
		'apacheconf_htpasswddir' => [
			'title' => 'Webserver htpasswd dirname',
			'description' => '¿Dónde deben guardarse los archivos htpasswd para la protección de directorios?'
		],
		'mysql_access_host' => [
			'title' => 'MySQL-Access-Hosts',
			'description' => 'Una lista separada por comas de los hosts desde los que se debe permitir a los usuarios conectarse al servidor MySQL. Para permitir una subred es válida la sintaxis netmask o cidr.'
		],
		'webalizer_quiet' => [
			'title' => 'Salida de Webalizer',
			'description' => 'Verbosidad del programa webalizer'
		],
		'logger' => [
			'enable' => 'Registro activado/desactivado',
			'severity' => 'Nivel de registro',
			'types' => [
				'title' => 'Tipo(s) de registro',
				'description' => 'Especifique los tipos de registro. Para seleccionar varios tipos, mantenga pulsada la tecla CTRL mientras selecciona.<br/>Los tipos de registro disponibles son: syslog, file, mysql'
			],
			'logfile' => [
				'title' => 'Nombre del archivo de registro',
				'description' => 'Sólo se utiliza si log-type incluye "file". Este archivo se creará en froxlor/logs/. Esta carpeta está protegida contra el acceso público.'
			],
			'logcron' => 'Log cronjobs',
			'logcronoption' => [
				'never' => 'Nunca',
				'once' => 'Una vez',
				'always' => 'Siempre'
			]
		],
		'ssl' => [
			'use_ssl' => [
				'title' => 'Activar uso de SSL',
				'description' => 'Marque esta opción si desea utilizar SSL para su servidor web'
			],
			'ssl_cert_file' => [
				'title' => 'Ruta al certificado SSL',
				'description' => 'Especifique la ruta incluyendo el nombre del archivo .crt o .pem (certificado principal)'
			],
			'openssl_cnf' => 'Valores predeterminados para crear el archivo Cert',
			'ssl_key_file' => [
				'title' => 'Ruta al archivo de claves SSL',
				'description' => 'Especifique la ruta incluyendo el nombre de archivo para el archivo de clave privada (.key principalmente)'
			],
			'ssl_ca_file' => [
				'title' => 'Ruta al certificado SSL CA (opcional)',
				'description' => 'Autenticación del cliente, configure esto sólo si sabe lo que es.'
			],
			'ssl_cipher_list' => [
				'title' => 'Configure los cifrados SSL permitidos',
				'description' => 'Esta es una lista de cifradores que quiere (o no quiere) usar cuando hable SSL. Para una lista de cifradores y cómo incluirlos/excluirlos, vea las secciones "CIPHER LIST FORMAT" y "CIPHER STRINGS" en <a href="https://www.openssl.org/docs/manmaster/man1/openssl-ciphers.html">la página man de cifradores</a>.<br/><br/><b>El valor por defecto es:</b><pre>ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305</pre>'
			],
			'apache24_ocsp_cache_path' => [
				'title' => 'Apache 2.4: ruta a la caché de grapado OCSP',
				'description' => 'Configura la caché utilizada para almacenar las respuestas OCSP que se incluyen en los handshakes TLS.'
			],
			'ssl_protocols' => [
				'title' => 'Configurar la versión del protocolo TLS',
				'description' => 'Esta es una lista de protocolos ssl que quiere (o no quiere) usar cuando use SSL. <b>Nota:</b> Es posible que algunos navegadores antiguos no admitan las versiones de protocolo más recientes.<br/><br/><b>El valor predeterminado es:</b><pre>TLSv1.2</pre>'
			],
			'tlsv13_cipher_list' => [
				'title' => 'Configurar cifrados explícitos TLSv1.3 si se utilizan',
				'description' => 'Esta es una lista de cifradores que desea (o no desea) utilizar cuando hable TLSv1.3. Para una lista de cifradores y como incluirlos/excluirlos, vea <a href="https://wiki.openssl.org/index.php/TLS1.3">los documentos para TLSv1.3</a>.<br/><br/><b>El valor por defecto es vacío</b>'
			]
		],
		'default_vhostconf' => [
			'title' => 'Configuración vHost por defecto',
			'description' => 'El contenido de este campo se incluirá en este contenedor ip/port vHost directamente. Puede utilizar las siguientes variables:<br/><code>{DOMAIN}</code>, <code>{DOCROOT}</code>, <code>{CUSTOMER}</code>, <code>{IP}</code>, <code>{PORT}</code>, <code>{SCHEME}</code>, <code>{FPMSOCKET}</code> (si procede)<br/> Atención: No se comprobará si el código contiene errores. Si contiene errores, ¡el servidor web podría no volver a arrancar!'
		],
		'apache_globaldiropt' => [
			'title' => 'Opciones de directorio para customer-prefix',
			'description' => 'El contenido de este campo se incluirá en la configuración de apache 05_froxlor_dirfix_nofcgid.conf. Si está vacío, se usará el valor por defecto:<br/><br/>apache >=2.4<br/><code>Require all granted<br/>AllowOverride All</code><br/><br/>apache <=2.2<br/><code>Order allow,deny<br/>allow from all</code>'
		],
		'default_vhostconf_domain' => [
			'description' => 'El contenido de este campo se incluirá directamente en el contenedor vHost del dominio. Puede utilizar las siguientes variables:<br/><code>{DOMAIN}</code>, <code>{DOCROOT}</code>, <code>{CUSTOMER}</code>, <code>{IP}</code>, <code>{PORT}</code>, <code>{SCHEME}</code>, <code>{FPMSOCKET}</code> (si procede)<br/> Atención: No se comprobará si el código contiene errores. Si contiene errores, ¡el servidor web podría no volver a arrancar!'
		],
		'decimal_places' => 'Número de decimales en la salida de tráfico/espacio web',
		'selfdns' => [
			'title' => 'Configuración dns del dominio del cliente'
		],
		'selfdnscustomer' => [
			'title' => 'Permitir a los clientes editar la configuración dns del dominio'
		],
		'unix_names' => [
			'title' => 'Utilizar nombres de usuario compatibles con UNIX',
			'description' => 'Permite utilizar <strong>-</strong> y <strong>_</strong> en los nombres de usuario si <strong>No</strong>'
		],
		'allow_password_reset' => [
			'title' => 'Permitir que los clientes restablezcan la contraseña',
			'description' => 'Los clientes pueden restablecer su contraseña y se les enviará un enlace de activación a su dirección de correo electrónico.'
		],
		'allow_password_reset_admin' => [
			'title' => 'Permitir que los administradores restablezcan la contraseña',
			'description' => 'Los administradores/revendedores pueden restablecer su contraseña y se les enviará un enlace de activación a su dirección de correo electrónico.'
		],
		'mail_quota' => [
			'title' => 'Cuota de buzón',
			'description' => 'La cuota por defecto para los nuevos buzones creados (MegaByte).'
		],
		'mail_quota_enabled' => [
			'title' => 'Usar mailbox-quota para clientes',
			'description' => 'Activar para utilizar cuotas en los buzones de correo. Por defecto es <b>No</b> ya que esto requiere una configuración especial.',
			'removelink' => 'Haga clic aquí para borrar todas las cuotas de las cuentas de correo.',
			'enforcelink' => 'Haga clic aquí para aplicar la cuota por defecto a todas las cuentas de correo de los usuarios.'
		],
		'index_file_extension' => [
			'description' => '¿Qué extensión de archivo debe utilizarse para el archivo de índice en los directorios de clientes recién creados? Esta extensión de archivo se utilizará si usted o uno de sus administradores ha creado su propia plantilla de archivo de índice.',
			'title' => 'Extensión de archivo para el archivo de índice en directorios de clientes recién creados'
		],
		'session_allow_multiple_login' => [
			'title' => 'Permitir inicio de sesión múltiple',
			'description' => 'Si se activa, un usuario puede iniciar sesión varias veces.'
		],
		'panel_allow_domain_change_admin' => [
			'title' => 'Permitir mover dominios entre administradores',
			'description' => 'Si está activado puede cambiar el admin de un dominio en domainsettings.<br/><b>Atención:</b> Si un cliente no está asignado al mismo administrador que el dominio, ¡el administrador puede ver todos los demás dominios de ese cliente!'
		],
		'panel_allow_domain_change_customer' => [
			'title' => 'Permitir mover dominios entre clientes',
			'description' => 'Si está activado puedes cambiar el cliente de un dominio en domainsettings.<br/><b>Atención:</b> froxlor cambia el documentroot al homedir por defecto del nuevo cliente (+ carpeta de dominio si está activado)'
		],
		'specialsettingsforsubdomains' => [
			'description' => 'En caso afirmativo, estos ajustes personalizados de vHost se añadirán a todos los subdominios; en caso negativo, se eliminarán los ajustes especiales de subdominio.'
		],
		'panel_password_min_length' => [
			'title' => 'Longitud mínima de contraseña',
			'description' => 'Aquí puede establecer una longitud mínima para las contraseñas. 0\' significa que no se requiere longitud mínima.'
		],
		'system_store_index_file_subs' => [
			'title' => 'Almacenar el fichero índice por defecto también en las nuevas subcarpetas',
			'description' => 'Si se activa, el archivo de índice por defecto se almacena en cada ruta de subdominio recién creada (no si la carpeta ya existe).'
		],
		'adminmail_return' => [
			'title' => 'Dirección de respuesta',
			'description' => 'Defina una dirección de email como dirección de respuesta para los emails enviados por el panel.'
		],
		'adminmail_defname' => 'Nombre del remitente del e-mail del panel',
		'stdsubdomainhost' => [
			'title' => 'Subdominio estándar del cliente',
			'description' => 'Qué nombre de host debe usarse para crear subdominios estándar para el cliente. Si está vacío, se utiliza el nombre de host del sistema.'
		],
		'awstats_path' => 'Ruta a AWStats \'awstats_buildstaticpages.pl\'',
		'awstats_conf' => 'Ruta de configuración de AWStats',
		'defaultttl' => 'TTL de dominio para bind en segundos (por defecto \'604800\' = 1 semana)',
		'defaultwebsrverrhandler_enabled' => 'Habilitar documentos de error por defecto para todos los clientes',
		'defaultwebsrverrhandler_err401' => [
			'title' => 'Archivo/URL para error 401',
			'description' => ''
		],
		'defaultwebsrverrhandler_err403' => [
			'title' => 'Archivo/URL para error 403',
			'description' => ''
		],
		'defaultwebsrverrhandler_err404' => 'Archivo/URL para error 404',
		'defaultwebsrverrhandler_err500' => [
			'title' => 'Archivo/URL para error 500',
			'description' => ''
		],
		'ftpserver' => [
			'desc' => 'Si se selecciona pureftpd, los archivos .ftpquota para cuotas de usuario se crean y actualizan diariamente'
		],
		'customredirect_enabled' => [
			'title' => 'Permitir redireccionamientos de clientes',
			'description' => 'Permitir a los clientes elegir el código http-status para las redirecciones que se utilizarán'
		],
		'customredirect_default' => [
			'title' => 'Redirección por defecto',
			'description' => 'Establece el código de redirección por defecto que se utilizará si el cliente no lo establece por sí mismo'
		],
		'mail_also_with_mxservers' => 'Crear mail-, imap-, pop3- y smtp-"A record" también con MX-Servers set',
		'froxlordirectlyviahostname' => 'Acceder a froxlor directamente a través del nombre de host',
		'panel_password_regex' => [
			'title' => 'Expresión regular para contraseñas',
			'description' => 'Aquí puede establecer una expresión regular para la complejidad de las contraseñas.<br/>Empty = no specific requirement'
		],
		'mod_fcgid_ownvhost' => [
			'title' => 'Habilitar FCGID para el vHost de froxlor',
			'description' => 'Si está habilitado, froxlor también se ejecutará bajo un usuario local'
		],
		'perl' => [
			'suexecworkaround' => [
				'title' => 'Habilitar solución SuExec',
				'description' => 'Habilitar sólo si los directorios del cliente no están dentro de la ruta apache suexec.<br/>Si está habilitado, froxlor generará un enlace simbólico desde el directorio del cliente habilitado para perl + /cgi-bin/ a la ruta dada.<br/>Tenga en cuenta que perl sólo funcionará en el subdirectorio de carpetas /cgi-bin/ y no en la carpeta en sí (¡como lo hace sin esta solución!)'
			],
			'suexeccgipath' => [
				'title' => 'Ruta para los enlaces simbólicos de directorio habilitados para perl del cliente',
				'description' => 'Sólo necesita configurar esto si la solución de SuExec está activada.<br/>ATENCIÓN: Asegúrese de que esta ruta está dentro de la ruta de suexec o de lo contrario esta solución es inútil.'
			]
		],
		'awstats_awstatspath' => 'Ruta a AWStats \'awstats.pl\'.',
		'awstats_icons' => [
			'title' => 'Ruta a la carpeta de iconos de AWstats',
			'description' => 'e.g. /usr/share/awstats/htdocs/icon/'
		],
		'login_domain_login' => 'Permitir login con dominios',
		'perl_server' => [
			'title' => 'Ubicación del socket del servidor Perl',
			'description' => 'Puede encontrar una guía sencilla en: <a target="blank" href="https://www.nginx.com/resources/wiki/start/topics/examples/fcgiwrap/">nginx.com</a>'
		],
		'nginx_php_backend' => [
			'title' => 'Nginx PHP backend',
			'description' => 'aquí es donde el proceso PHP está escuchando peticiones de nginx, puede ser un socket unix de combinación ip:port<br/>*NO se usa con php-fpm'
		],
		'phpreload_command' => [
			'title' => 'Comando PHP reload',
			'description' => 'se usa para recargar el backend PHP si se usa alguno<br/>Por defecto: en blanco<br/>*NO se usa con php-fpm'
		],
		'phpfpm' => [
			'title' => 'Habilitar php-fpm',
			'description' => '<b>Esto necesita una configuración especial del servidor web ver <a target="_blank" href="https://docs.froxlor.org/latest/admin-guide/configuration/php-fpm/">manual PHP-FPM</a></b>'
		],
		'phpfpm_settings' => [
			'configdir' => 'Directorio de configuración de php-fpm',
			'aliasconfigdir' => 'Directorio Alias de configuración de php-fpm',
			'reload' => 'Comando de reinicio de php-fpm',
			'pm' => 'Control del gestor de procesos (pm)',
			'max_children' => [
				'title' => 'Número de procesos hijo',
				'description' => 'El número de procesos hijo a ser creados cuando pm está en \'static\' y el número máximo de procesos hijo a ser creados cuando pm está en \'dynamic/ondemand\'<br/>Equivalente a PHP_FCGI_CHILDREN'
			],
			'start_servers' => [
				'title' => 'El número de procesos hijo creados al inicio',
				'description' => 'Nota: Sólo se usa cuando pm está configurado como \'dynamic'
			],
			'min_spare_servers' => [
				'title' => 'El número mínimo deseado de procesos de servidor inactivos',
				'description' => 'Nota: Sólo se usa cuando pm es \'dynamic\'<br/>Nota: Obligatorio cuando pm es \'dynamic'
			],
			'max_spare_servers' => [
				'title' => 'El número máximo deseado de procesos de servidor inactivos',
				'description' => 'Nota: sólo se utiliza cuando pm tiene el valor "dynamic".<br/>Nota: obligatorio cuando pm tiene el valor "dynamic".'
			],
			'max_requests' => [
				'title' => 'Peticiones por hijo antes de respawning',
				'description' => 'Para un procesamiento infinito de peticiones especifique \'0\'. Equivalente a PHP_FCGI_MAX_REQUESTS.'
			],
			'idle_timeout' => [
				'title' => 'Tiempo de espera',
				'description' => 'Configuración de tiempo de espera para PHP FPM FastCGI.'
			],
			'ipcdir' => [
				'title' => 'Directorio IPC FastCGI',
				'description' => 'El directorio donde los sockets php-fpm serán almacenados por el servidor web.<br/>Este directorio debe ser legible para el servidor web.'
			],
			'limit_extensions' => [
				'title' => 'Extensiones permitidas',
				'description' => 'Limita las extensiones del script principal que FPM permitirá analizar. Esto puede evitar errores de configuración en el servidor web. Sólo debe limitar FPM a extensiones .php para evitar que usuarios maliciosos utilicen otras extensiones para ejecutar código php. Valor por defecto: .php'
			],
			'envpath' => 'Rutas a añadir al entorno PATH. Dejar vacío para ninguna variable de entorno PATH',
			'override_fpmconfig' => 'Anular la configuración de FPM-daemon (pm, max_children, etc.)',
			'override_fpmconfig_addinfo' => '<br/><span class="text-danger">Sólo se usa si "Override FPM-daemon settings" está en "Yes"</span>',
			'restart_note' => 'Atención: La configuración no será revisada por errores. Si contiene errores, PHP-FPM podría no arrancar de nuevo.',
			'custom_config' => [
				'title' => 'Configuración personalizada',
				'description' => 'Agregue configuración personalizada a cada instancia de versión de PHP-FPM, por ejemplo <i>pm.status_path = /status</i> para monitoreo. Las variables de abajo pueden ser usadas aquí. <strong>Atención: La configuración no será revisada por errores. Si contiene errores, ¡PHP-FPM podría no arrancar de nuevo!</strong>'
			],
			'allow_all_customers' => [
				'title' => 'Asigne esta configuración a todos los clientes existentes',
				'description' => 'Establézcalo en "true" si desea asignar esta configuración a todos los clientes existentes para que puedan utilizarla. Esta configuración no es permanente, pero puede ejecutarse varias veces.'
			]
		],
		'report' => [
			'report' => 'Habilitar el envío de informes sobre el uso de la web y el tráfico',
			'webmax' => [
				'title' => 'Nivel de advertencia en porcentaje para el espacio web',
				'description' => 'Los valores válidos son 0 hasta 150. Establecer este valor a 0 desactiva este informe.'
			],
			'trafficmax' => [
				'title' => 'Nivel de advertencia en porcentaje para el tráfico',
				'description' => 'Los valores válidos son de 0 a 150. El valor 0 desactiva este informe.'
			]
		],
		'dropdown' => 'Desplegable',
		'manual' => 'Manual',
		'default_theme' => 'Tema por defecto',
		'validate_domain' => 'Validar nombres de dominio',
		'diskquota_enabled' => '¿Cuota activada?',
		'diskquota_repquota_path' => [
			'description' => 'Ruta a repquota'
		],
		'diskquota_quotatool_path' => [
			'description' => 'Ruta a quotatool'
		],
		'diskquota_customer_partition' => [
			'description' => 'Partición en la que se almacenan los archivos del cliente'
		],
		'vmail_maildirname' => [
			'title' => 'Nombre del maildir',
			'description' => 'Directorio maildir en la cuenta del usuario. Normalmente \'Maildir\', en algunas implementaciones \'.maildir\', y directamente en el directorio del usuario si se deja en blanco.'
		],
		'catchall_enabled' => [
			'title' => 'Utilizar Catchall',
			'description' => '¿Quiere proporcionar a sus clientes la función catchall?'
		],
		'apache_24' => [
			'title' => 'Utilice las modificaciones para Apache 2.4',
			'description' => '<strong class="text-danger">ATENCIÓN:</strong> utilícelo sólo si tiene instalada la versión 2.4 o superior de apache<br/>de lo contrario su servidor web no podrá arrancar'
		],
		'nginx_fastcgiparams' => [
			'title' => 'Ruta al archivo fastcgi_params',
			'description' => 'Especifique la ruta al archivo fastcgi_params de nginx incluyendo el nombre de archivo'
		],
		'documentroot_use_default_value' => [
			'title' => 'Usar el nombre de dominio como valor por defecto para la ruta DocumentRoot',
			'description' => 'Si está habilitado y la ruta DocumentRoot está vacía, el valor por defecto será el (sub)nombre de dominio.<br/><br/>Ejemplos: <br/>/var/clientes/nombre_cliente/ejemplo.com/<br/>/var/clientes/nombre_cliente/subdominio.ejemplo.com/'
		],
		'panel_phpconfigs_hidesubdomains' => [
			'title' => 'Ocultar subdominios en la vista general de configuración PHP',
			'description' => 'Si se activa, los subdominios de los clientes no se mostrarán en la vista general de configuraciones PHP, sólo se mostrará el número de subdominios.<br/><br/>Nota: Esto sólo es visible si ha activado FCGID o PHP-FPM.'
		],
		'panel_phpconfigs_hidestdsubdomain' => [
			'title' => 'Ocultar subdominios estándar en la vista general de configuraciones PHP',
			'description' => 'Si se activa, los subdominios estándar de los clientes no se mostrarán en la vista general de configuraciones php<br/><br/>Nota: Esto sólo es visible si ha activado FCGID o PHP-FPM.'
		],
		'passwordcryptfunc' => [
			'title' => 'Elija el método de cifrado de contraseñas a utilizar'
		],
		'systemdefault' => 'Sistema por defecto',
		'panel_allow_theme_change_admin' => 'Permitir a los administradores cambiar el tema',
		'panel_allow_theme_change_customer' => 'Permitir a los clientes cambiar el tema',
		'axfrservers' => [
			'title' => 'Servidores AXFR',
			'description' => 'Una lista separada por comas de direcciones IP permitidas para transferir (AXFR) zonas dns.'
		],
		'powerdns_mode' => [
			'title' => 'Modo de funcionamiento PowerDNS',
			'description' => 'Seleccione el modo PoweDNS: Nativo para no replicación (Predeterminado) / Maestro si se necesita replicación DNS.'
		],
		'customerssl_directory' => [
			'title' => 'Webserver customer-ssl certificates-directory',
			'description' => '¿Dónde deben crearse los certificados ssl especificados por el cliente?<br/><br/><div class="text-danger">NOTA: El contenido de esta carpeta se borra con regularidad, así que evite almacenar datos allí manualmente.</div>'
		],
		'allow_error_report_admin' => [
			'title' => 'Permitir a los administradores/revendedores informar de errores en la base de datos a froxlor',
			'description' => 'Nota: ¡Nunca nos envíes datos personales (de clientes)!'
		],
		'allow_error_report_customer' => [
			'title' => 'Permitir a los clientes informar de errores en la base de datos a froxlor',
			'description' => 'Nota: ¡No nos envíe nunca datos personales (de clientes)!'
		],
		'mailtraffic_enabled' => [
			'title' => 'Analizar el tráfico de correo',
			'description' => 'Permitir el análisis de los registros del servidor de correo para calcular el tráfico'
		],
		'mdaserver' => [
			'title' => 'Tipo de MDA',
			'description' => 'Tipo de servidor de entrega de correo'
		],
		'mdalog' => [
			'title' => 'Registro MDA',
			'description' => 'Archivo de registro del Mail Delivery Server'
		],
		'mtaserver' => [
			'title' => 'Tipo de MTA',
			'description' => 'Tipo de agente de transferencia de correo'
		],
		'mtalog' => [
			'title' => 'Registro MTA',
			'description' => 'Archivo de registro del Agente de Transferencia de Correo'
		],
		'system_cronconfig' => [
			'title' => 'Archivo de configuración de cron',
			'description' => 'Ruta al archivo de configuración del servicio cron. Este archivo será actualizado regular y automáticamente por froxlor.<br/>Nota: ¡Por favor <b>asegúrese</b> de usar el mismo nombre de archivo que para el froxlor cronjob principal (por defecto: /etc/cron.d/froxlor)!<br/><br/>¡Si está usando <b>FreeBSD</b>, por favor especifique <i>/etc/crontab</i> aquí!'
		],
		'system_crondreload' => [
			'title' => 'Comando Cron-daemon reload',
			'description' => 'Especifique el comando a ejecutar para recargar el cron-daemon de su sistema'
		],
		'system_croncmdline' => [
			'title' => 'Comando de ejecución de cron (php-binario)',
			'description' => 'Comando para ejecutar nuestros cronjobs. Cámbielo sólo si sabe lo que está haciendo (por defecto: "/usr/bin/nice -n 5 /usr/bin/php -q").'
		],
		'system_cron_allowautoupdate' => [
			'title' => 'Permitir la actualización automática de la base de datos',
			'description' => '<div class="text-danger"><b>ATENCIÓN:</b></div> Esta configuración permite al cronjob saltarse la comprobación de versión de los archivos froxlors y la base de datos y ejecuta la actualización de la base de datos en caso de que ocurra un desajuste de versión.<br/><br/><div class="text-danger">Auto-update siempre establecerá valores por defecto para nuevas configuraciones o cambios. Esto puede no ser siempre adecuado para su sistema. Por favor, piénselo dos veces antes de activar esta opción</div>'
		],
		'dns_createhostnameentry' => 'Crear bind-zone/config para el nombre de host del sistema',
		'panel_password_alpha_lower' => [
			'title' => 'Carácter en minúsculas',
			'description' => 'La contraseña debe contener al menos una letra minúscula (a-z).'
		],
		'panel_password_alpha_upper' => [
			'title' => 'Mayúsculas',
			'description' => 'La contraseña debe contener al menos una letra mayúscula (A-Z).'
		],
		'panel_password_numeric' => [
			'title' => 'Números',
			'description' => 'La contraseña debe contener al menos un número (0-9).'
		],
		'panel_password_special_char_required' => [
			'title' => 'Carácter especial',
			'description' => 'La contraseña debe contener al menos uno de los caracteres definidos a continuación.'
		],
		'panel_password_special_char' => [
			'title' => 'Lista de caracteres especiales',
			'description' => 'Se requiere uno de estos caracteres si se establece la opción anterior.'
		],
		'apache_itksupport' => [
			'title' => 'Modificaciones de uso para Apache ITK-MPM',
			'description' => '<strong class="text-danger">ATENCIÓN:</strong> utilícela sólo si tiene apache itk-mpm habilitado<br/>, de lo contrario su servidor web no podrá iniciarse.'
		],
		'letsencryptca' => [
			'title' => 'Entorno ACME',
			'description' => 'Entorno que se utilizará para los certificados Let\'s Encrypt / ZeroSSL.'
		],
		'letsencryptchallengepath' => [
			'title' => 'Ruta para los desafíos Let\'s Encrypt',
			'description' => 'Directorio desde el que se ofrecerán los retos Let\'s Encrypt a través de un alias global.'
		],
		'letsencryptkeysize' => [
			'title' => 'Tamaño de la clave para nuevos certificados Let\'s Encrypt',
			'description' => 'Tamaño de la clave en Bits para nuevos certificados Let\'s Encrypt.'
		],
		'letsencryptreuseold' => [
			'title' => 'Reutilizar clave Let\'s Encrypt',
			'description' => 'Si se activa, se utilizará la misma clave para cada renovación, de lo contrario se generará una nueva clave cada vez.'
		],
		'leenabled' => [
			'title' => 'Activar Let\'s Encrypt',
			'description' => 'Si se activa, los clientes pueden dejar que froxlor automáticamente genere y renueve certificados ssl Let\'s Encrypt para dominios con una IP/puerto ssl.<br/><br/>Por favor recuerda que necesitas ir a través de la configuración del servidor web cuando se activa porque esta característica necesita una configuración especial.'
		],
		'caa_entry' => [
			'title' => 'Generar registros DNS CAA',
			'description' => 'Genera automáticamente registros CAA para dominios habilitados para SSL que utilizan Let\'s Encrypt.'
		],
		'caa_entry_custom' => [
			'title' => 'Registros DNS CAA adicionales',
			'description' => 'DNS Certification Authority Authorization (CAA) es un mecanismo de política de seguridad en Internet que permite a los titulares de nombres de dominio indicar a las autoridades de certificación<br/>si están autorizadas a emitir certificados digitales para un nombre de dominio concreto. Lo hace mediante un nuevo registro de recursos del Sistema de Nombres de Dominio (DNS) "CAA".<br/><br/>El contenido de este campo se incluirá en la zona DNS directamente (cada línea da lugar a un registro CAA).<br/>Si Let\'s Encrypt está habilitado para este dominio, esta entrada siempre se añadirá automáticamente y no es necesario añadirla manualmente:<br/> 0<code>issue "letsencrypt.org"</code> (Si el dominio es un dominio comodín, se utilizará issuewild en su lugar).<br/>Para habilitar el informe de incidentes, puede añadir un registro <code>iodef</code>. Un ejemplo para enviar dicho informe a <code>me@example.com</code> sería:<br/> 0<code>iodef "mailto:me@example.com"</code><br/><br/><strong>Atención:</strong> No se comprobará si el código contiene errores. Si contiene errores, ¡es posible que sus registros CAA no funcionen!'
		],
		'dnseditorenable' => [
			'title' => 'Habilitar editor DNS',
			'description' => 'Permite a los administradores y a los clientes gestionar las entradas DNS del dominio'
		],
		'dns_server' => [
			'title' => 'Demonio del servidor DNS',
			'description' => 'Recuerde que los daemons tienen que ser configurados usando las plantillas de configuración de froxlors'
		],
		'panel_customer_hide_options' => [
			'title' => 'Ocultar elementos de menú y gráficos de tráfico en el panel de cliente',
			'description' => 'Seleccione los elementos que desea ocultar en el panel de cliente. Para seleccionar varias opciones, mantenga pulsada la tecla CTRL mientras selecciona.'
		],
		'allow_allow_customer_shell' => [
			'title' => 'Permitir a los clientes habilitar el acceso shell para usuarios ftp',
			'description' => '<strong class="text-danger">Atención: El acceso Shell permite al usuario ejecutar varios binarios en su sistema. Utilícelo con extrema precaución. ¡¡¡Por favor, active esto sólo si REALMENTE sabe lo que está haciendo!!!</strong>'
		],
		'available_shells' => [
			'title' => 'Lista de shells disponibles',
			'description' => 'Lista separada por comas de los intérpretes de comandos que están disponibles para que el cliente elija para sus usuarios ftp.<br/><br/>Tenga en cuenta que el intérprete de comandos predeterminado <strong>/bin/false</strong> siempre será una opción (si está habilitado), incluso si esta configuración está vacía. Es el valor por defecto para los usuarios ftp en cualquier caso.'
		],
		'le_froxlor_enabled' => [
			'title' => 'Activar Let\'s Encrypt para el froxlor vhost',
			'description' => 'Si se activa, el froxlor vhost se asegurará automáticamente usando un certificado Let\'s Encrypt.'
		],
		'le_froxlor_redirect' => [
			'title' => 'Activar SSL-redirect para froxlor vhost',
			'description' => 'Si se activa, todas las peticiones http a su froxlor serán redirigidas al sitio SSL correspondiente.'
		],
		'option_unavailable_websrv' => '<br/><em class="text-danger">Disponible sólo para: %s</em>',
		'option_unavailable' => '<br/><em class="text-danger">Opción no disponible debido a otros ajustes.</em>',
		'letsencryptacmeconf' => [
			'title' => 'Ruta al fragmento acme.conf',
			'description' => 'Nombre de archivo del fragmento de configuración que permite al servidor web servir el desafío acme.'
		],
		'mail_use_smtp' => 'Configurar mailer para usar SMTP',
		'mail_smtp_host' => 'Especifique el servidor SMTP',
		'mail_smtp_usetls' => 'Activar el cifrado TLS',
		'mail_smtp_auth' => 'Activar la autenticación SMTP',
		'mail_smtp_port' => 'Puerto TCP al que conectarse',
		'mail_smtp_user' => 'Nombre de usuario SMTP',
		'mail_smtp_passwd' => 'Contraseña SMTP',
		'http2_support' => [
			'title' => 'Soporte HTTP2',
			'description' => 'habilite el soporte HTTP2 para ssl.<br/><em class="text-danger">HABILITAR SÓLO SI SU WEBSERVER SOPORTA ESTA CARACTERÍSTICA (nginx versión 1.9.5+, apache2 versión 2.4.17+)</em>'
		],
		'nssextrausers' => [
			'title' => 'Usar libnss-extrausers en lugar de libnss-mysql',
			'description' => 'No leer usuarios de la base de datos sino de ficheros. Por favor, actívelo sólo si ya ha realizado los pasos de configuración necesarios (system -><strong class="text-danger">libnss-extrausers).</strong><br/><strong class="text-danger">Sólo para Debian/Ubuntu (¡o si ha compilado libnss-extrausers usted mismo!)</strong>'
		],
		'le_domain_dnscheck' => [
			'title' => 'Validar DNS de dominios al usar Let\'s Encrypt',
			'description' => 'Si está activado, froxlor validará si el dominio que solicita un certificado Let\'s Encrypt resuelve al menos a una de las direcciones ip del sistema.'
		],
		'le_domain_dnscheck_resolver' => [
			'title' => 'Usar un servidor de nombres externo para validación DNS',
			'description' => 'Si se establece, froxlor usará este DNS para validar los DNS de los dominios cuando use Let\'s Encrypt. Si está vacío, se usará el resolver DNS por defecto del sistema.'
		],
		'phpsettingsforsubdomains' => [
			'description' => 'En caso afirmativo se actualizará el php-config elegido a todos los subdominios'
		],
		'leapiversion' => [
			'title' => 'Elegir la implementación ACME de Let\'s Encrypt',
			'description' => 'Actualmente sólo se soporta la implementación ACME v2 para Let\'s Encrypt.'
		],
		'enable_api' => [
			'title' => 'Habilitar uso de API externa',
			'description' => 'Para utilizar la API froxlor es necesario activar esta opción. Para obtener información más detallada, consulte <a href="https://docs.froxlor.org/latest/api-guide/" target="_new">https://docs.froxlor.org/</a>'
		],
		'api_customer_default' => '"Permitir acceso a la API" valor por defecto para nuevos clientes',
		'dhparams_file' => [
			'title' => 'Archivo DHParams (intercambio de claves Diffie-Hellman)',
			'description' => 'Si se especifica aquí un archivo dhparams.pem, se incluirá en la configuración del servidor web. Déjelo vacío para desactivarlo.<br/>Ejemplo: <code>/etc/ssl/webserver/dhparams</code>.pem<br/><br/>Si el archivo no existe, se creará automáticamente con el siguiente comando: <code>openssl dhparam -out /etc/ssl/webserver/dhparams.pem 4096</code>. Se recomienda crear el archivo antes de especificarlo aquí, ya que la creación tarda bastante y bloquea el cronjob.'
		],
		'errorlog_level' => [
			'title' => 'Nivel de registro de errores',
			'description' => 'Especifique el nivel de registro de errores. Por defecto es "warn" para usuarios apache y "error" para usuarios nginx.'
		],
		'letsencryptecc' => [
			'title' => 'Emitir certificado ECC / ECDSA',
			'description' => 'Si se establece un tamaño de clave válido, el certificado emitido utilizará ECC / ECDSA.'
		],
		'froxloraliases' => [
			'title' => 'Alias de dominio para froxlor vhost',
			'description' => 'Lista separada por comas de dominios para añadir como alias de servidor al froxlor vhost'
		],
		'default_sslvhostconf' => [
			'title' => 'SSL por defecto vHost-settings',
			'description' => 'El contenido de este campo se incluirá en este contenedor ip/port vHost directamente. Puede utilizar las siguientes variables:<br/><code>{DOMAIN}</code>, <code>{DOCROOT}</code>, <code>{CUSTOMER}</code>, <code>{IP}</code>, <code>{PORT}</code>, <code>{SCHEME}</code>, <code>{FPMSOCKET}</code> (si procede)<br/> Atención: No se comprobará si el código contiene errores. Si contiene errores, ¡el servidor web podría no volver a arrancar!'
		],
		'includedefault_sslvhostconf' => 'Incluir configuración de vHost no SSL en SSL-vHost',
		'apply_specialsettings_default' => [
			'title' => 'Valor por defecto para "Apply specialsettings to all subdomains (*.example.com)\' setting when editing a domain'
		],
		'apply_phpconfigs_default' => [
			'title' => 'Valor por defecto para "Aplicar php-config a todos los subdominios:\' al editar un dominio'
		],
		'awstats' => [
			'logformat' => [
				'title' => 'Configuración de LogFormat',
				'description' => 'Si utilizas un formato de registro personalizado para tu servidor web, necesitas cambiar también el awstats LogFormat.<br/>Por defecto es 1. Para más información consulta la documentación <a target="_blank" href="https://awstats.sourceforge.io/docs/awstats_config.html#LogFormat">aquí</a>.'
			]
		],
		'hide_incompatible_settings' => 'Ocultar configuraciones incompatibles',
		'soaemail' => 'Dirección de correo a usar en registros SOA (por defecto la dirección del remitente de la configuración del panel si está vacía)',
		'imprint_url' => [
			'title' => 'URL a notas legales / impresión',
			'description' => 'Especifique una URL a su sitio de notas legales / impresión. El enlace será visible en la pantalla de inicio de sesión y en el pie de página una vez iniciada la sesión.'
		],
		'terms_url' => [
			'title' => 'URL a las condiciones de uso',
			'description' => 'Especifique una URL a su sitio de condiciones de uso. El enlace será visible en la pantalla de inicio de sesión y en el pie de página al iniciar sesión.'
		],
		'privacy_url' => [
			'title' => 'URL a la política de privacidad',
			'description' => 'Especifique una URL a su sitio de política de privacidad / sitio de impresión. El enlace será visible en la pantalla de inicio de sesión y en el pie de página al iniciar sesión.'
		],
		'logo_image_header' => [
			'title' => 'Imagen de logotipo (cabecera)',
			'description' => 'Cargue su propia imagen de logotipo para que se muestre en el encabezado después del inicio de sesión (altura recomendada 30px)'
		],
		'logo_image_login' => [
			'title' => 'Imagen del logotipo (inicio de sesión)',
			'description' => 'Cargue su propia imagen de logotipo para que se muestre durante el inicio de sesión'
		],
		'logo_overridetheme' => [
			'title' => 'Sobrescribe el logo definido en el tema por "Logo Image" (Cabecera y Login, ver más abajo)',
			'description' => 'Esta opción debe establecerse como "true" si desea utilizar el logotipo que ha cargado; como alternativa, puede seguir utilizando las posibilidades basadas en el tema "logo_custom.png" y "logo_custom_login.png".'
		],
		'logo_overridecustom' => [
			'title' => 'Sobrescribir el logotipo personalizado (logo_custom.png y logo_custom_login.png) definido en el tema por "Imagen del logotipo" (Cabecera e Inicio de sesión, ver más abajo).',
			'description' => 'Establezca este valor en "true" si desea ignorar los logotipos personalizados específicos del tema para el encabezado y el inicio de sesión y utilizar "Logo Image".'
		],
		'createstdsubdom_default' => [
			'title' => 'Valor preseleccionado para "Crear subdominio estándar" al crear un cliente',
			'description' => ''
		],
		'froxlorusergroup' => [
			'title' => 'Grupo de sistema personalizado para todos los usuarios del cliente',
			'description' => 'Se requiere el uso de libnss-extrausers (system-settings) para que esto tenga efecto. Un valor vacío omite la creación o elimina el grupo existente.'
		],
		'acmeshpath' => [
			'title' => 'Ruta a acme.sh',
			'description' => 'Establézcalo donde se instala acme.sh, incluyendo el script acme.sh<br/>Por defecto es <b>/root/.acme.sh/acme.sh</b>'
		],
		'update_channel' => [
			'title' => 'froxlor actualizar-canal',
			'description' => 'Seleccione el canal de actualización de froxlor. Por defecto es "estable"'
		],
		'uc_stable' => 'estable',
		'uc_testing' => 'testing',
		'traffictool' => [
			'toolselect' => 'Analizador de tráfico',
			'webalizer' => 'Webalizer',
			'awstats' => 'AWStats',
			'goaccess' => 'goaccess'
		],
		'requires_reconfiguration' => 'El cambio de esta configuración podría requerir una reconfiguración de los siguientes servicios:<br/><strong>%s</strong>'
	],
	'spf' => [
		'use_spf' => '¿Activar SPF para dominios?',
		'spf_entry' => 'Entrada SPF para todos los dominios'
	],
	'ssl_certificates' => [
		'certificate_for' => 'Certificado para',
		'valid_from' => 'Válido de',
		'valid_until' => 'Válido hasta',
		'issuer' => 'Emisor'
	],
	'success' => [
		'success' => 'Información',
		'clickheretocontinue' => 'Haga clic aquí para continuar',
		'settingssaved' => 'La configuración se ha guardado correctamente.',
		'rebuildingconfigs' => 'Tareas insertadas con éxito para reconstruir archivos de configuración',
		'domain_import_successfully' => 'Se han importado correctamente los dominios %s.',
		'dns_record_added' => 'Registro añadido correctamente',
		'dns_record_deleted' => 'Registro eliminado correctamente',
		'testmailsent' => 'Correo de prueba enviado correctamente',
		'settingsimported' => 'Ajustes importados correctamente',
		'sent_error_report' => 'Informe de error enviado correctamente. Gracias por su contribución.'
	],
	'tasks' => [
		'outstanding_tasks' => 'Tareas cron pendientes',
		'REBUILD_VHOST' => 'Reconstrucción de la configuración del servidor web',
		'CREATE_HOME' => 'Añadir nueva %s cliente',
		'REBUILD_DNS' => 'Reconstrucción de la configuración bind',
		'CREATE_FTP' => 'Crear directorio para nuevo usuario ftp',
		'DELETE_CUSTOMER_FILES' => 'Borrar archivos de cliente %s',
		'noneoutstanding' => 'Actualmente no hay tareas pendientes para froxlor',
		'CREATE_QUOTA' => 'Establecer cuota en el sistema de archivos',
		'DELETE_EMAIL_DATA' => 'Borrar datos de e-mail del cliente.',
		'DELETE_FTP_DATA' => 'Borrar los datos de la cuenta ftp del cliente.',
		'REBUILD_CRON' => 'Reconstruir el archivo cron.d',
		'DELETE_DOMAIN_PDNS' => 'Borrar dominio %s de la base de datos PowerDNS',
		'DELETE_DOMAIN_SSL' => 'Borrar archivos ssl de dominio %s'
	],
	'terms' => 'Condiciones de uso',
	'traffic' => [
		'month' => 'Mes',
		'day' => 'Día',
		'months' => [
			'1' => 'Enero',
			'2' => 'Febrero',
			'3' => 'Marzo',
			'4' => 'Abril',
			'5' => 'Mayo',
			'6' => 'Junio',
			'7' => 'Julio',
			'8' => 'Agosto',
			'9' => 'Septiembre',
			'10' => 'Octubre',
			'11' => 'Noviembre',
			'12' => 'Diciembre',
			'jan' => 'Enero',
			'feb' => 'Febrero',
			'mar' => 'Mar',
			'apr' => 'Abr',
			'may' => 'Mayo',
			'jun' => 'Jun',
			'jul' => 'Jul',
			'aug' => 'Ago',
			'sep' => 'Sep',
			'oct' => 'Oct',
			'nov' => 'Nov',
			'dec' => 'Diciembre',
			'total' => 'Total'
		],
		'mb' => 'Tráfico',
		'sumtotal' => 'Tráfico total',
		'sumhttp' => 'Tráfico HTTP',
		'sumftp' => 'Tráfico FTP',
		'summail' => 'Tráfico de correo',
		'customer' => 'Cliente',
		'domain' => 'Dominio',
		'trafficoverview' => 'Resumen del tráfico',
		'bycustomers' => 'Tráfico por clientes',
		'details' => 'Detalles',
		'http' => 'HTTP',
		'ftp' => 'FTP',
		'mail' => 'Correo',
		'nocustomers' => 'Necesita al menos un cliente para ver los informes de tráfico.',
		'top5customers' => 'Top 5 clientes',
		'nodata' => 'No se han encontrado datos para el intervalo dado.',
		'ranges' => [
			'last24h' => 'últimas 24 horas',
			'last7d' => 'últimos 7 días',
			'last30d' => 'últimos 30 días',
			'cm' => 'Mes actual',
			'last3m' => 'últimos 3 meses',
			'last6m' => 'últimos 6 meses',
			'last12m' => 'últimos 12 meses',
			'cy' => 'Año en curso'
		],
		'byrange' => 'Especificado por rango'
	],
	'translator' => '',
	'update' => [
		'updateinprogress_onlyadmincanlogin' => 'Se ha instalado una versión más reciente de froxlor pero aún no se ha configurado.<br/>Sólo el administrador puede iniciar sesión y finalizar la actualización.',
		'update' => 'Actualización de froxlor',
		'proceed' => 'Proceder',
		'update_information' => [
			'part_a' => 'Los archivos froxlor han sido actualizados a la versión <strong>%s</strong>. La versión instalada es <strong>%s</strong>.',
			'part_b' => '<br/><br/>Los clientes no podrán conectarse hasta que la actualización haya finalizado.<br/><strong>¿Proceder?</strong>'
		],
		'noupdatesavail' => 'Ya tiene instalada la última %sversion de froxlor.',
		'description' => 'Ejecutando actualizaciones de la base de datos para su instalación de froxlor',
		'uc_newinfo' => 'Hay un %sversion más reciente disponible: "%s" (Su versión actual es: %s)',
		'notify_subject' => 'Nueva actualización disponible'
	],
	'usersettings' => [
		'custom_notes' => [
			'title' => 'Notas personalizadas',
			'description' => 'Siéntete libre de poner las notas que quieras/necesites aquí. Se mostrarán en la vista general del administrador/cliente para el usuario correspondiente.',
			'show' => 'Mostrar tus notas en el panel de control del usuario'
		],
		'api_allowed' => [
			'title' => 'Permitir el acceso a la API',
			'description' => 'Cuando está habilitado en la configuración, este usuario puede crear claves API y acceder a la API froxlor',
			'notice' => 'El acceso a la API no está permitido para su cuenta.'
		]
	],
	'install' => [
		'slogan' => 'Panel de gestión del servidor froxlor',
		'preflight' => 'Comprobación del sistema',
		'critical_error' => 'Error crítico',
		'suggestions' => 'No requerido pero recomendado',
		'phpinfosuccess' => 'Su sistema funciona con PHP %s',
		'phpinfowarn' => 'Su sistema está ejecutando una versión inferior a PHP %s',
		'phpinfoupdate' => 'Actualice su versión PHP actual de %s a %s o superior',
		'start_installation' => 'Inicie la instalación',
		'check_again' => 'Recargar para comprobar de nuevo',
		'switchmode_advanced' => 'Mostrar opciones avanzadas',
		'switchmode_basic' => 'Ocultar opciones avanzadas',
		'dependency_check' => [
			'title' => 'Bienvenido a froxlor',
			'description' => 'Comprobamos las dependencias del sistema para asegurarnos de que todas las extensiones y módulos php necesarios están habilitados para que froxlor funcione correctamente.'
		],
		'database' => [
			'top' => 'Base de datos',
			'title' => 'Crear base de datos y usuario',
			'description' => 'froxlor requiere una base de datos y adicionalmente un usuario privilegiado para poder crear usuarios y bases de datos (opción GRANT). La base de datos y el usuario no privilegiado serán creados en este proceso. El usuario privilegiado debe existir.',
			'user' => 'Usuario no privilegiado de la base de datos',
			'dbname' => 'Nombre de la base de datos',
			'force_create' => '¿Hacer copia de seguridad y sobrescribir la base de datos si existe?'
		],
		'admin' => [
			'top' => 'Usuario administrador',
			'title' => 'Vamos a crear el usuario administrador principal.',
			'description' => 'Este usuario tendrá todos los privilegios para ajustar la configuración y añadir/actualizar/eliminar recursos como clientes, dominios, etc.'
		],
		'system' => [
			'top' => 'Configuración del sistema',
			'title' => 'Detalles sobre su servidor',
			'description' => 'Establezca su entorno así como los datos y opciones relevantes del servidor aquí para que froxlor conozca su sistema. Estos valores son cruciales para la configuración y el funcionamiento del sistema.',
			'ipv4' => 'Dirección IPv4 primaria (si procede)',
			'ipv6' => 'Dirección IPv6 primaria (si procede)',
			'servername' => 'Nombre del servidor (FQDN, sin dirección IP)',
			'phpbackend' => 'PHP backend',
			'activate_newsfeed' => 'Habilitar la fuente oficial de noticias<br/><small>(fuente externa: https://inside.froxlor.org/news/)</small>'
		],
		'install' => [
			'top' => 'Finalizar la configuración',
			'title' => 'Un último paso...',
			'description' => 'El siguiente comando descargará, instalará y configurará los servicios necesarios en tu sistema de acuerdo con los datos que has facilitado en este proceso de instalación.',
			'runcmd' => 'Ejecute el siguiente comando como usuario root en su shell en este servidor:',
			'manual_config' => 'Configuraré manualmente los servicios, llévame al inicio de sesión',
			'waitforconfig' => 'Esperando a que se configuren los servicios...'
		],
		'errors' => [
			'wrong_ownership' => 'Asegúrese de que los archivos froxlor son propiedad de %s:%s',
			'missing_extensions' => 'Las siguientes extensiones de php son necesarias y no están instaladas',
			'suggestedextensions' => 'No se han encontrado las siguientes extensiones de php pero se recomiendan',
			'databaseexists' => 'La base de datos ya existe, por favor establezca la opción override para reconstruir o elija otro nombre',
			'unabletocreatedb' => 'No se ha podido crear la base de datos de prueba',
			'unabletodropdb' => 'No se ha podido eliminar la base de datos de prueba',
			'mysqlusernameexists' => 'El usuario especificado para el usuario sin privilegios ya existe. Por favor, utilice otro nombre de usuario o elimínelo primero.',
			'unabletocreateuser' => 'No se ha podido crear el usuario de prueba',
			'unabletodropuser' => 'No se ha podido eliminar el usuario de prueba.',
			'unabletoflushprivs' => 'El usuario privilegiado no puede eliminar privilegios.',
			'nov4andnov6ip' => 'Debe indicarse una dirección IPv4 o IPv6.',
			'servernameneedstobevalid' => 'El nombre de servidor indicado no parece ser un FQDN o un nombre de host.',
			'websrvuserdoesnotexist' => 'El usuario del servidor web no parece existir en el sistema.',
			'websrvgrpdoesnotexist' => 'El webserver-group indicado no parece existir en el sistema.',
			'notyetconfigured' => 'Parece que los servicios aún no se han configurado (correctamente). Por favor, ejecute el comando que se muestra a continuación o marque la casilla para hacerlo más tarde.',
			'mandatory_field_not_set' => 'El campo obligatorio "%s" no está configurado.',
			'unexpected_database_error' => 'Se ha producido una excepción inesperada en la base de datos. %s',
			'sql_import_failed' => 'Error al importar datos SQL.',
			'unprivileged_sql_connection_failed' => 'Error al inicializar una conexión SQL sin privilegios.',
			'privileged_sql_connection_failed' => 'Error al inicializar la conexión SQL privilegiada.',
			'mysqldump_backup_failed' => 'No se puede crear una copia de seguridad de la base de datos, tenemos un error de mysqldump.',
			'sql_backup_file_missing' => 'No se puede crear una copia de seguridad de la base de datos, el archivo de copia de seguridad no existe.',
			'backup_binary_missing' => 'No se puede crear una copia de seguridad de la base de datos, asegúrese de que ha instalado mysqldump.',
			'creating_configfile_failed' => 'No se pueden crear archivos de configuración, no se puede escribir el archivo.',
			'database_already_exiting' => '¡Encontramos una base de datos y no se nos permitió sobreescribirla!'
		]
	],
	'welcome' => [
		'title' => '¡Bienvenido a froxlor!',
		'config_note' => 'Para que froxlor pueda comunicarse correctamente con el backend, tienes que configurarlo.',
		'config_now' => 'Configurar ahora'
	]
];
