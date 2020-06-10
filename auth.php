<?php

/* * * * * * * * * *  The OneLogin SAML Authentication module for Moodle  * * * * * * * * *
 *
 * auth.php - extends the Moodle core to embrace SAML
 *
 * @originalauthor OneLogin, Inc
 * @author Harrison Horowitz, Sixto Martin
 * @version 2.8.0
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package auth_onelogin_saml
 * @requires XMLSecLibs v3.0.4
 * @requires php-saml v3.3.1
 * @copyright 2011-2019 OneLogin.com
 *
 * @description
 * Connects to Moodle, builds the configuration, discovers SAML status, and handles the login process accordingly.
 *
 * Security Assertion Markup Language (SAML) is a standard for logging users into applications based
 * on their session in another context. This has significant advantages over logging in using a
 * username/password: no need to type in credentials, no need to remember and renew password, no weak
 * passwords etc.
 *
 * Most companies already know the identity of users because they are logged into their Active Directory
 * domain or intranet. It is natural to use this information to log users into other applications as well
 * such as web-based application, and one of the more elegant ways of doing this by using SAML.
 *
 * SAML is very powerful and flexible, but the specification can be quite a handful. Now OneLogin is
 * releasing this SAML toolkit for your Moodle application to enable you to integrate SAML in seconds
 * instead of months. We’ve filtered the signal from the noise and come up with a simple setup that will
 * work for most applications out there.
 *
 */

require_once '_toolkit_loader.php';

use OneLogin\Saml2\Settings;

global $CFG;

if (strstr(strtolower(PHP_OS), 'win') && strstr(strtolower(PHP_OS), 'darwin') === false) {
    require_once($CFG->libdir.'\authlib.php');
} else {
    require_once($CFG->libdir.'/authlib.php');
}

/*

if (!defined('MOODLE_INTERNAL')) {
    die('Direct access to this script is forbidden.');    ///  It must be included from a Moodle page
}

*/

/**
 * OneLogin SAML for Moodle - base definition
**/
class auth_plugin_onelogin_saml extends auth_plugin_base {

    /**
    * Constructor.
    */
    public function __construct() {
        $this->authtype = 'onelogin_saml';
        $this->roleauth = 'auth_onelogin_saml';
        $config = get_config('auth_onelogin_saml');
        $legacyconfig = get_config('auth/onelogin_saml');
        $this->config = (object)array_merge((array)$legacyconfig, (array)$config);
    }

    /**
    * Old syntax of class constructor. Deprecated in PHP7.
    *
    * @deprecated since Moodle 3.1
    */
    public function auth_plugin_onelogin_saml() {
        debugging('Use of class name as constructor is deprecated', DEBUG_DEVELOPER);
        self::__construct();
    }

    /**
     * Return a single identity provider to display on the login page.
     *
     * @param string|moodle_url $wantsurl The requested URL.
     * @return array List of arrays with keys url, iconurl and name.
     */
    public function loginpage_idp_list($wantsurl) {
        if (!$this->config->dual_login) {
            // OneLogin is the only allowed authentication method
            return [];
        }

        $name = empty($this->config->idp_button) ? get_string('auth_onelogin_saml_idp_button_default', 'auth_onelogin_saml') : $this->config->idp_button;
        return [['url' => new moodle_url('/auth/onelogin_saml/index.php'), 'iconurl' => null, 'name' => $name]];
    }

    /**
    * Returns true if the username and password work and false if they are
    * wrong or don't exist.
    *
    * @param string $username The username (with system magic quotes)
    * @param string $password The password (with system magic quotes)
    * @return bool Authentication success or failure.
    */
    public function user_login($username, $password) {
        global $SESSION;
        // if true, user_login was initiated by onelogin_saml/index.php
        if (isset($SESSION->onelogin_saml_login_attributes)) {
            return true;
        }
        return false;
    }

    /**
    * Returns the user information for 'external' users. In this case the
    * attributes provided by Identity Provider
    *
    * @return array $result Associative array of user data
    */
    public function get_userinfo($username = null) {
        global $SESSION;

        $saml_attributes = $SESSION->onelogin_saml_login_attributes;
        $nameID = $SESSION->onelogin_saml_nameID;
        $mapping = $this->get_attributes();

        $user = array();
        if (empty($saml_attributes)) {
            $user['username'] = $nameID;
            $user['email'] = $user['username'];
        } else {
            foreach ($mapping as $key => $val) {
                if (!empty($val) && isset($saml_attributes[$val]) && !empty($saml_attributes[$val][0])) {
                    $user[$key] = $saml_attributes[$val][0];
                }
            }
        }

        $saml_account_matcher = $this->config->saml_account_matcher;
        if (empty($saml_account_matcher)) {
            $saml_account_matcher = 'username';
        }

        if (($saml_account_matcher == 'username' && empty($user['username']) ||
           ($saml_account_matcher == 'email' && empty($user['email'])))) {
            return false;
        }
        /*

    	print_r($saml_attributes);
    	echo '<br><br>';
    	print_r($user);exit();

        */
        return $user;
    }

    /*
    * Returns array containg attribute mappings between Moodle and Identity Provider.
    */
    public function get_attributes() {

        $moodleattributes = array();
        // If we have custom fields then merge them with user fields.
        $customfields = $this->get_custom_user_profile_fields();
        if (!empty($customfields) && !empty($this->userfields)) {
            $userfields = array_merge($this->userfields, $customfields);
        } else {
            $userfields = $this->userfields;
        }

        foreach ($userfields as $field) {
            if (!empty($this->config->{"field_map_$field"})) {
                $moodleattributes[$field] = trim($this->config->{"field_map_$field"});
                if (preg_match('/,/', $moodleattributes[$field])) {
                    $moodleattributes[$field] = explode(',', $moodleattributes[$field]);
                }
            }
        }

        $moodleattributes['username'] = trim($this->config->field_map_username);
        return $moodleattributes;
    }

    /**
     * Get and map roles from the saml assertion
     */
    public function obtain_roles() {
        global $SESSION;

        $roles = array();

        $saml_attributes = $SESSION->onelogin_saml_login_attributes;
        $roleMapping = $this->config->field_map_role;
        if (!empty($roleMapping) && isset($saml_attributes[$roleMapping]) && !empty($saml_attributes[$roleMapping])) {
            $siteadminMapping = explode(',', $this->config->saml_role_siteadmin_map);
            $coursecreatorMapping = explode(',', $this->config->saml_role_coursecreator_map);
            $managerMapping = explode(',', $this->config->saml_role_manager_map);

            $samlRoles = $saml_attributes[$roleMapping];

            foreach ($samlRoles as $samlRole) {
                if (in_array($samlRole, $siteadminMapping)) {
                    $roles[] = 'siteadmin';
                }
                if (in_array($samlRole, $coursecreatorMapping)) {
                    $roles[] = 'coursecreator';
                }
                if (in_array($samlRole, $managerMapping)) {
                    $roles[] = 'manager';
                }
            }
        }
        return array_unique($roles);
    }

    /**
    * Sync roles for this user - usually creator
    *
    * @param $user object user object (without system magic quotes)
    */
    public function sync_roles($user) {
        global $CFG, $DB;

        $newRoles = $this->obtain_roles();

        // Process siteadmin (special, they are stored at mdl_config)
        if (in_array('siteadmin', $newRoles)) {
            $siteadmins = explode(',', $CFG->siteadmins);
            if (!in_array($user->id, $siteadmins)) {
                $siteadmins[] = $user->id;
                $newAdmins = implode(',', $siteadmins);
                set_config('siteadmins', $newAdmins);
            }
        }

        // Process coursecreator and manager
        $syscontext = context_system::instance();
        if (in_array('coursecreator', $newRoles)) {
            $creatorrole = $DB->get_record('role', array('shortname'=>'coursecreator'), '*', MUST_EXIST);
            role_assign($creatorrole->id, $user->id, $syscontext);
        }
        if (in_array('manager', $newRoles)) {
            $managerrole = $DB->get_record('role', array('shortname'=>'manager'), '*', MUST_EXIST);
            role_assign($managerrole->id, $user->id, $syscontext);
        }
    }

    /**
    * Returns true if this authentication plugin is 'internal'.
    *
    * @return bool
    */
    public function is_internal() {
        return false;
    }


    public function prevent_local_passwords() {
        return true;
    }

    /**
    * Returns true if this authentication plugin can change the user's
    * password.
    *
    * @return bool
    */
    public function can_change_password() {
        return false;
    }

    public function loginpage_hook() {
        global $CFG;

        if ($this->config->dual_login) {
          return;
        }
        // Prevent username from being shown on login page after logout
        $CFG->nolastloggedin = true;

        if (!isset($_GET['normal']) && (empty($_POST['username']) && empty($_POST['password']))) {
            $init_sso_url = $CFG->wwwroot.'/auth/onelogin_saml/index.php';
            redirect($init_sso_url);
        }
    }

    public function logoutpage_hook() {
        global $SESSION, $CFG;

        $logout_url = $CFG->wwwroot.'/auth/onelogin_saml/index.php?logout=1';

        if (!isset($SESSION->isSAMLSessionControlled)) {
            $logout_url .= '&normal';
        }

        require_logout();
        set_moodle_cookie('nobody');
        redirect($logout_url);
    }

    /**
    * Test if settings are ok, print info to output.
    */
    public function test_settings() {
        global $CFG, $OUTPUT;

	require_once 'functions.php';

        $pluginconfig = get_config('auth_onelogin_saml');

        $settings = auth_onelogin_saml_get_settings();

        echo $OUTPUT->notification($settings['debug'] ? get_string('notification_debugmode_on', 'auth_onelogin_saml') : get_string('notification_debugmode_off', 'auth_onelogin_saml'), 'userinfobox notifysuccess');
        echo $OUTPUT->notification($settings['strict'] ? get_string('notification_strictmode_on', 'auth_onelogin_saml') : get_string('notification_srictmode_off', 'auth_onelogin_saml'), 'userinfobox notifysuccess');

        $spPrivatekey = $settings['sp']['x509cert'];
        $spCert = $settings['sp']['privateKey'];

        try {
            $samlSettings = new Settings($settings);
            echo $OUTPUT->notification(get_string('notification_samlsettings_valid', 'auth_onelogin_saml'), 'userinfobox notifysuccess');
        } catch (\Exception $e) {
            echo $OUTPUT->notification(get_string('notification_samlsettings_valid', 'auth_onelogin_saml', $e->getMessage()), 'userinfobox notifyproblem');
        }

        if ($pluginconfig->saml_slo) {
            echo $OUTPUT->notification(get_string('notification_slo_enabled', 'auth_onelogin_saml'), 'userinfobox notifysuccess');
        } else {
            echo $OUTPUT->notification(get_string('notification_slo_disabled', 'auth_onelogin_saml'), 'userinfobox notifysuccess');
        }

        $fileSystemKeyExists = file_exists($CFG->dirroot.'/auth/onelogin_saml/certs/sp.key');
        $fileSystemCertExists = file_exists($CFG->dirroot.'/auth/onelogin_saml/certs/sp.crt');
        if ($fileSystemKeyExists) {
            $privatekey_url = $CFG->wwwroot . '/auth/onelogin_saml/certs/sp.key';
            echo $OUTPUT->notification(get_string('notification_keyonfilesystem', 'auth_onelogin_saml', $privatekey_url), 'userinfobox');
        }

        if ($spPrivatekey && !empty($spPrivatekey)) {
            echo $OUTPUT->notification(get_string('notification_keyindatabase', 'auth_onelogin_saml'), 'userinfobox');
        }

        if (($spPrivatekey && !empty($spPrivatekey) && $fileSystemKeyExists) ||
            ($spCert && !empty($spCert) && $fileSystemCertExists)) {
            echo $OUTPUT->notification(get_string('notification_dbkeypriority', 'auth_onelogin_saml'), 'userinfobox');
        }

        if ($pluginconfig->saml_auto_create_users) {
            echo $OUTPUT->notification(get_string('notification_userautocreate_on', 'auth_onelogin_saml'), 'userinfobox notifysuccess');
        } else {
            echo $OUTPUT->notification(get_string('notification_userautocreate_off', 'auth_onelogin_saml'), 'userinfobox notifysuccess');
        }

        if ($pluginconfig->saml_auto_update_users) {
            echo $OUTPUT->notification(get_string('notification_userupdate', 'auth_onelogin_saml'), 'userinfobox notifysuccess');
        }

        if ($pluginconfig->saml_auto_create_users || $pluginconfig->saml_auto_update_users) {
            echo $OUTPUT->notification(get_string('notification_attributemapping', 'auth_onelogin_saml'), 'userinfobox');
        }

        $attr_mappings = array (
            'field_map_username' => get_string("auth_onelogin_saml_username_map", "auth_onelogin_saml"),
            'field_map_email' => get_string("auth_onelogin_saml_email_map", "auth_onelogin_saml"),
            'field_map_firstname' => get_string("auth_onelogin_saml_firstname_map", "auth_onelogin_saml"),
            'field_map_lastname' => get_string("auth_onelogin_saml_surname_map", "auth_onelogin_saml"),
            'field_map_idnumber' => get_string("auth_onelogin_saml_idnumber_map", "auth_onelogin_saml"),
            'field_map_role' => get_string("auth_onelogin_saml_role_map", "auth_onelogin_saml"),
        );

        $saml_account_matcher = $pluginconfig->saml_account_matcher;
        if (empty($saml_account_matcher)) {
            $saml_account_matcher = 'username';
        }

        $lacked_attr_mappings = array();
        foreach ($attr_mappings as $field => $name) {
            $value = $pluginconfig->{"$field"};
            if (empty($value)) {
                if ($saml_account_matcher == 'username' && $field == 'field_map_username') {
                    echo $OUTPUT->notification(get_string("notification_usernamemappingrequired", "auth_onelogin_saml"), 'userinfobox notifyproblem');
                }
                if ($saml_account_matcher == 'email' && $field == 'field_map_email') {
                    echo $OUTPUT->notification(get_string("notification_emailmappingrequired", "auth_onelogin_saml"), 'userinfobox notifyproblem');
                }
                $lacked_attr_mappings[] = $name;
            }
        }

        if (!empty($lacked_attr_mappings)) {
            echo $OUTPUT->notification(get_string("notification_unmappedattributes", "auth_onelogin_saml", implode('<br>', $lacked_attr_mappings)), 'userinfobox');
        }

        $role_mappings = array (
            'saml_role_siteadmin_map' => get_string("auth_onelogin_saml_rolemapping_head", "auth_onelogin_saml"),
            'saml_role_coursecreator_map' => get_string("auth_onelogin_saml_role_coursecreator_map", "auth_onelogin_saml"),
            'saml_role_manager_map' => get_string("auth_onelogin_saml_role_manager_map", "auth_onelogin_saml"),
        );

        $lacked_role_mappings = array();
        foreach ($role_mappings as $field => $name) {
            $value = $pluginconfig->{"$field"};
            if (empty($value)) {
                $lacked_role_mappings[] = $name;
            }
        }

        if (!empty($lacked_role_mappings)) {
            echo $OUTPUT->notification(get_string("notification_unmappedattributes", "auth_onelogin_saml", implode('<br>', $lacked_role_mappings)), 'userinfobox');
        }
    }

    /**
     * Confirm the new user as registered. This should normally not be used,
     * but it may be necessary if the user auth_method is changed to manual
     * before the user is confirmed.
     *
     * @param string $username
     * @param string $confirmsecret
     */
     function user_confirm($username, $confirmsecret = null) {
         global $DB;

         $user = get_complete_user_data('username', $username);

         if (!empty($user)) {
             if ($user->confirmed) {
                 return AUTH_CONFIRM_ALREADY;
             } else {
                 $DB->set_field("user", "confirmed", 1, array("id"=>$user->id));
                 return AUTH_CONFIRM_OK;
             }
         } else  {
             return AUTH_CONFIRM_ERROR;
         }
     }
}
