<?php

global $CFG;

$string['auth_onelogin_samltitle'] = 'OneLogin SAML'; //SSO Authentication

$string['auth_onelogin_samldescription']   = 'Security Assertion Markup Language (SAML) is a standard for logging users into applications based on their session in another context. This has significant advantages over logging in using a username/password: no need to type in credentials, no need to remember and renew password, no weak passwords etc. Most companies already know the identity of users because they are logged into their Active Directory domain or intranet. It is natural to use this information to log users into other applications as well such as web-based application, and one of the more elegant ways of doing this by using SAML. SAML is very powerful and flexible, but the specification can be quite a handful. Now OneLogin is releasing this SAML toolkit for your Moodle application to enable you to integrate SAML in seconds instead of months. We\'ve filtered the signal from the noise and come up with a simple setup that will work for most applications out there.
<h4>Module Setup Notes</h4>
For the greatest convenience and security, be sure to perform the following steps...<br>
<ul><li>Go to your <a target="_blank" title="New Window" href=\'{$a}/admin/settings.php?section=manageauths\'>Manage Authentication</a> page and...<ul><li>Enable the OneLogin SAML authentication module by clicking on the eyeball so that the eye is open.</li><li>Click the UP arrow to prioritize the SAML authentication above all of the others.</li><li>Disable "Self-registration" (optional but recommended)</li><li>In the "Alternative login URL" textbox   <strong>&larr; /auth/onelogin_saml</strong></li></ul></li><li>Configure the options below from your company\'s OneLogin Moodle connector.</li></ul>
<h4>SECRET  FOR  ADMINS</h4>
Skip the SAML process and see the regular login box by adding "?normal" to your normal login URL: <a href=\'{$a}/login/index.php?normal\' title="Normal login mode">/login/index.php?normal</a><br>To enable this feature, you must find the 1 line of code in "/login/index.php" that looks like...<br><br><em>if (!empty($CFG->alternateloginurl)) {</em><br><br>...and change it to...<br><br><em>if (!empty($CFG->alternateloginurl) && !isset($_GET[\'normal\'])) {</em><br>';

$string['auth_onelogin_saml_idp_settings'] = "Identity Provider Settings";
$string['auth_onelogin_saml_idp_head'] = '<a href=\'{$a}/auth/onelogin_saml/metadata.php\'>Go to the metadata of this SP</a><br><br>Set here some info related to the IdP that will be connected with our Moodle. You can find this values at the Onelogin\'s platform in the Moodle App at the Single Sign-On tab';
$string['auth_onelogin_saml_idp_sso_issuer_url'] = 'IdP Entity Id';
$string['auth_onelogin_saml_idp_sso_issuer_url_description'] = 'Identifier of the IdP entity. ("Issuer URL")';
$string['auth_onelogin_saml_idp_sso_target_url'] = 'Single Sign On Service Url';
$string['auth_onelogin_saml_idp_sso_target_url_description'] = 'SSO endpoint info of the IdP. URL target of the IdP where the SP will send the Authentication Request. ("SAML 2.0 Endpoint (HTTP)")';
$string['auth_onelogin_saml_idp_slo_target_url'] = 'Single Log Out Service Url';
$string['auth_onelogin_saml_idp_slo_target_url_description'] = 'SLO endpoint info of the IdP. URL target of the IdP where the SP will send the SLO Request. ("SLO Endpoint (HTTP)")';
$string['auth_onelogin_saml_x509certificate'] = 'X.509 Certificate';
$string['auth_onelogin_saml_x509certificate_description'] = 'Public x509 certificate of the IdP. ("X.509 certificate")';

$string['auth_onelogin_saml_options'] = "Options";
$string['auth_onelogin_saml_options_head'] = "In this section the behavior of the plugin is set.";
$string['auth_onelogin_saml_dual_login'] = "Display in IDP list";
$string['auth_onelogin_saml_dual_login_description'] = "Add a button to the login page instead of intercepting all login requests.";
$string['auth_onelogin_saml_idp_button'] = "IDP list button text";
$string['auth_onelogin_saml_idp_button_description'] = "The text to display on the IDP button.";
$string['auth_onelogin_saml_idp_button_default'] = "Login via OneLogin";
$string['auth_onelogin_saml_override_auth'] = 'Override all auth methods';
$string['auth_onelogin_saml_override_auth_description'] = 'Allow this plugin to provide authentication for accounts using other authentication methods';
$string['auth_onelogin_saml_auto_create_users'] = 'Create user if not exists';
$string['auth_onelogin_saml_auto_create_users_description'] = 'Auto-provisioning. If user not exists, Moodle will create a new user with the data provided by the IdP. Review the Mapping section.<br />By default, the accounts are created without a password, and the user must login via SAML identity verification.';
$string['auth_onelogin_saml_auto_update_users'] = 'Update user data';
$string['auth_onelogin_saml_auto_update_users_description'] = 'Auto-update. Moodle will update the account of the user with the data provided by the IdP. Review the Mapping section.';
$string['auth_onelogin_saml_slo'] = 'Single Log Out';
$string['auth_onelogin_saml_slo_description'] = 'Enable/disable Single Log Out. SLO is a complex functionality, the most common SLO implementation is based on front-channel (redirections), sometimes if the SLO workflow fails a user can be blocked in an unhandled view. If the admin does not controls the set of apps involved in the SLO process maybe is better to disable this functionality due could carry more problems than benefits.';
$string['auth_onelogin_saml_account_matcher'] = 'Match Moodle account by';
$string['auth_onelogin_saml_account_matcher_description'] = "Select what field will be used in order to find the user account. We recomment to use the 'username' becouse is an attribute that the user can't change. If you select the 'email' and the user change his value in Moodle, he will lost the access.";

$string['auth_onelogin_saml_attrmapping_head'] = "Sometimes the names of the attributes sent by the IdP not match the names used by Moodle for the user accounts. In this section we can set the mapping between IdP fields and Moodle fields.";
$string['auth_onelogin_saml_username_map'] = "Username";
$string['auth_onelogin_saml_email_map'] = "Email Address";
$string['auth_onelogin_saml_firstname_map'] = "First Name";
$string['auth_onelogin_saml_surname_map'] = "Surname";
$string['auth_onelogin_saml_idnumber_map'] = "IDnumber";
$string['auth_onelogin_saml_role_map'] = "Role";

$string['auth_onelogin_saml_rolemapping'] = "Role Mapping";
$string['auth_onelogin_saml_rolemapping_head'] = "The IdP can use it's own roles. Set in this section the mapping between IdP and Moodle roles. Accepts multiple valued comma separated. Example: admin,owner,superuser.";
$string['auth_onelogin_saml_role_siteadmin_map'] = "Site administrators";
$string['auth_onelogin_saml_role_coursecreator_map'] = "Course creator";
$string['auth_onelogin_saml_role_manager_map'] = "Manager";

$string['auth_onelogin_saml_advanced'] = "Advanced Settings";
$string['auth_onelogin_saml_advanced_head'] = "Handle some other parameters related to customizations and security issues.<br>If sign/encryption is enabled, then x509 cert and private key for the SP must be provided. There are 2 ways:<br>1. Store them as files named sp.key and sp.crt on the 'certs' folder of the plugin. (be sure that the folder is protected and not exposed to internet)<br>2. Store them at the database, filling the corresponding textareas. (take care of security issues)";

$string['auth_onelogin_saml_debug_mode'] = "Debug Mode";
$string['auth_onelogin_saml_debug_mode_description'] = "Enable it when your are debugging the SAML workflow. Errors and Warnigs will be showed.";
$string['auth_onelogin_saml_strict_mode'] = "Strict Mode";
$string['auth_onelogin_saml_strict_mode_description'] = "If Strict mode is Enabled, then Moodle will reject unsigned or unencrypted messages if it expects them signed or encrypted. Also will reject the messages if not strictly follow the SAML standard: Destination, NameId, Conditions ... are validated too.";
$string['auth_onelogin_saml_sp_entity_id'] = "Service Provider Entity Id";
$string['auth_onelogin_saml_sp_entity_id_description'] = "Set the Entity ID for the Service Provider. If not provided, 'moodle-php-saml' will be used.<br>Set this value as a Valid Audience at the Onelogin Platform.";
$string['auth_onelogin_saml_nameid_format'] = "NameID Format";
$string['auth_onelogin_saml_nameid_format_description'] = "Specifies constraints on the name identifier to be used to represent the requested subject.";
$string['auth_onelogin_saml_nameid_encrypted'] = "Encrypt nameID";
$string['auth_onelogin_saml_nameid_encrypted_description'] = "The nameID sent by this SP will be encrypted.";
$string['auth_onelogin_saml_authn_request_signed'] = "Sign AuthnRequest";
$string['auth_onelogin_saml_authn_request_signed_description'] = "The samlp:AuthnRequest messages sent by this SP will be signed.";
$string['auth_onelogin_saml_logout_request_signed'] = "Sign LogoutRequest";
$string['auth_onelogin_saml_logout_request_signed_description'] = "The samlp:logoutRequest messages sent by this SP will be signed.";
$string['auth_onelogin_saml_logout_response_signed'] = "Sign LogoutResponse";
$string['auth_onelogin_saml_logout_response_signed_description'] = "The samlp:logoutResponse messages sent by this SP will be signed.";
$string['auth_onelogin_saml_want_message_signed'] = "Reject Unsigned Messages";
$string['auth_onelogin_saml_want_message_signed_description'] = "Reject unsigned samlp:Response, samlp:LogoutRequest and samlp:LogoutResponse received";
$string['auth_onelogin_saml_want_assertion_signed'] = "Reject Unsigned Assertions";
$string['auth_onelogin_saml_want_assertion_signed_description'] = "Reject unsigned saml:Assertion received";
$string['auth_onelogin_saml_want_assertion_encrypted'] = "Reject Unencrypted Assertions";
$string['auth_onelogin_saml_want_assertion_encrypted_description'] = "Reject unencrypted saml:Assertion received";
$string['auth_onelogin_saml_sp_x509cert'] = "Service Provider X.509 Certificate";
$string['auth_onelogin_saml_sp_x509cert_description'] = "Public x509 certificate of the SP. Leave this field empty if you gonna provide the private key by the sp.crt";
$string['auth_onelogin_saml_sp_privatekey'] = "Service Provider Private Key";
$string['auth_onelogin_saml_sp_privatekey_description'] = "Private Key of the SP. Leave this field empty if you gonna provide the private key by the sp.key";
$string['auth_onelogin_saml_logout_redirect_url'] = "Logout Redirect URL";
$string['auth_onelogin_saml_logout_redirect_url_description'] = "Forces user's browser to be redirected to the specified URL upon logout.";

$string['auth_onelogin_saml_form_has_errors'] = "The SAML settings form has errors";
$string['auth_onelogin_saml_create_or_update_warning'] = "When auto-provisioning or auto-update is enable,";
$string['auth_onelogin_saml_empty_required_value'] = "is a required attribute, provide a valid value";

$string['auth_onelogin_saml_metadatalink'] = 'Go to the metadata of this SP';
$string['auth_onelogin_saml_validatelink'] = 'Once configured, validate here your OneLogin SSO/SAML Settings';

$string['retriesexceeded'] = 'Maximum number of SAML connection retries exceeded  - there must be a problem with the Identity Service.<br />Please try again in a few minutes.';
$string['pluginauthfailed'] = 'The OneLogin SAML authentication plugin failed - user $a disallowed (no user auto-creation?) or dual login disabled.';
$string['pluginauthfailedusername'] = 'The OneLogin SAML authentication plugin failed - user $a disallowed due to invalid username format.';
$string['auth_onelogin_saml_username_email_error'] = 'The identity provider returned a set of data that does not contain the SAML username/email mapping field. Once of this field is required to login. <br />Please check your Username/Email Address Attribute Mapping configuration.';

$string['pluginname'] = 'OneLogin SAML SSO Authentication';

// Notifications in auth.php
$string['notification_debugmode_on'] = 'Debug mode <strong>on</strong>. In production turn it off';
$string['notification_debugmode_off'] = '<strong>off</strong>';
$string['notification_strictmode_on'] = 'Strict mode <strong>on</strong>';
$string['notification_strictmode_off'] = 'Strict mode <strong>off</strong>. In production we recommend to turn it on.';
$string['notification_samlsettings_valid'] = 'SAML settings are <strong>ok</strong>';
$string['notification_samlsettings_invalid'] = 'Found errors while validating SAML settings info.<br>{$a}';
$string['notification_slo_enabled'] = 'Single Log Out is enabled. If the SLO process fail, close your browser to be sure that session of the apps are closed';
$string['notification_slo_disabled'] = 'Single Log Out is disabled. If you log out from Moodle your session at the IdP keeps alive.';
$string['notification_keyonfilesystem'] = 'There is a private key stored at the filesystem. Protect the \'certs\' path. Nobody should be allowed to access:<br>{$a}<br>';
$string['notification_keyindatabase'] = 'There is a private key stored at the database. (An attacker could own your database and get it. Take care)';
$string['notification_dbkeypriority'] = 'Private key/certs stored on database have priority over the private key/cert stored at filesystem';
$string['notification_userautocreate_on'] = 'User will be created if not exists, based on the data sent by the IdP.';
$string['notification_userautocreate_off'] = 'If the user not exists, access is prevented.';
$string['notification_userupdate'] = 'User account will be updated with the data sent by the IdP.';
$string['notification_attributemapping'] = 'Is important to set the attribute and the role mapping when auto-provisioning or account update are active.';
$string['notificaton_usernamemappingrequired'] = 'Username mapping is required in order to enable the SAML Single Sign On';
$string['notification_emailmappingrequired'] = 'Email Address mapping is required in order to enable the SAML Single Sign On';
$string['notification_unmappedattributes'] = 'Notice that there are attributes without mapping:<br>{$a}';
$string['notification_unmappedroles'] = 'Notice that there are roles without mapping:<br>{$a}';

// Errors in functions.php, index.php
$string['error_disabledlogin'] = '[client {$a->remoteaddr}] {$a->wwwroot}  --->  DISABLED LOGIN: {$a->user_saml}';
$string['error_deletedlogin'] = '[client {$a->remoteaddr}] {$a->wwwroot}  --->  DELETED LOGIN: {$a->user_saml}';
$string['error_failedlogin'] = '[client {$a->remoteaddr}] {$a->wwwroot}  --->  FAILED LOGIN: {$a->username}';
$string['error_usernamerequired'] = 'Username is required in order to create the account';
$string['error_idpusernotexists'] = 'User provided by the IdP "{$a->user_saml}" not exists in moodle and auto-provisioning is disabled';
$string['error_setup'] = 'auth_onelogin_saml: Module Setup Error: Review the OneLogin setup instructions for the SAML authentication module';
$string['error_usernotidentified'] = 'auth_onelogin_saml: You could not be identified or created: {$a}';
$string['error_nosamlresponse'] = 'auth_onelogin_saml: No SAML response detected.';
$string['error_missingusernameemail'] = 'auth_onelogin_saml: auth failed due to missing username/email saml attribute: {$a}';
