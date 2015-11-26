<?php
/**
 *
 * @package mahara
 * @subpackage auth-oidc
 * @author James McQuillan <james.mcquillan@remote-learner.net>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2015 onwards Microsoft Open Technologies, Inc. (http://msopentech.com/)
 */

namespace auth_oidc;

defined('INTERNAL') || die();

require_once('pieforms/pieform.php');

/**
 * Performs local-OIDC account linking forms + functions.
 */
class linker {
    /** @var int|null The auth instance id to use when linking accounts. */
    protected $authinstance = null;

    /** @var string The username of the OpenID Connect user to link to. */
    protected $oidcusername = '';

    /**
     * Constructor.
     *
     * @param array $linkdata Array of OIDC user data and auth instance ID, to link accounts.
     */
    public function __construct($linkdata) {
        $this->authinstance = (isset($linkdata['authinstance'])) ? $linkdata['authinstance'] : null;
        $this->oidcusername = (isset($linkdata['oidcusername'])) ? $linkdata['oidcusername'] : '';
    }

    /**
     * Show the link account form.
     */
    public function showlinkform() {
        global $USER;
        $form = array(
            'name' => 'auth_oidc_loginlink',
            'renderer' => 'div',
            'successcallback' => array($this, 'loginlink_submit'),
            'method' => 'post',
            'plugintype' => 'auth',
            'pluginname' => 'oidc',
            'elements' => array(
                'linklogins' => array(
                    'value' => '<div>'.get_string('linkaccounts', 'auth.oidc', $this->oidcusername, $USER->username).'</div>'
                ),
                'submit' => array(
                    'type'  => 'submitcancel',
                    'value' => array(get_string('confirm','auth.oidc'), get_string('cancel')),
                    'goto'  => get_config('wwwroot'),
                ),
            ),
            'dieaftersubmit' => false,
            'iscancellable'  => true,
        );
        $form = new \Pieform($form);
        $smarty = smarty(array(), array(), array(), array('pagehelp' => false, 'sidebars' => false));
        $smarty->assign('form', $form->build());
        $smarty->assign('PAGEHEADING', get_string('link', 'auth.oidc'));
        $smarty->display('form.tpl');
        die();
    }

    /**
     * Link form callback - link the accounts.
     *
     * @param \Pieform $form Pieform instance.
     * @param array $values Submitted values.
     */
    public function loginlink_submit(\Pieform $form, $values) {
        global $USER, $SESSION;
        if ($this->authinstance === null || empty($this->oidcusername)) {
            // User is not logged in. They should never reach here, but as a failsafe...
            redirect('/');
        }
        db_begin();
        delete_records('auth_remote_user', 'authinstance', $this->authinstance, 'localusr', $USER->id);
        insert_record('auth_remote_user', (object)array(
            'authinstance' => $this->authinstance,
            'remoteusername' => $this->oidcusername,
            'localusr' => $USER->id,
        ));
        db_commit();
        $SESSION->set('auth_oidc_linkdata', null);
        @session_write_close();
        redirect('/');
    }

    /**
     * Show a login form for when a user needs to link an OIDC account but is not yet logged in locally.
     */
    public function showloginform() {
        $smarty = smarty(array(), array(), array(), array('pagehelp' => false, 'sidebars' => false));
        $smarty->assign('pagedescriptionhtml', get_string('logintolinkdesc', 'auth.oidc', $this->oidcusername, get_config('sitename')));
        $smarty->assign('form', '<div id="loginform_container"><noscript><p>{str tag="javascriptnotenabled"}</p></noscript>'.$this->generate_login_form());
        $smarty->assign('PAGEHEADING', get_string('logintolink', 'auth.oidc', get_config('sitename')));
        $smarty->assign('LOGINPAGE', true);
        $smarty->display('form.tpl');
        die();
    }

    /**
     * Generate the login form for $this->showloginform().
     *
     * @return array Array of pieform form information for the login form.
     */
    public function generate_login_form() {
        return get_login_form_js(pieform(array(
            'name' => 'auth_oidc_login',
            'renderer' => 'div',
            'submit' => true,
            'successcallback' => array($this, 'login_submit'),
            'plugintype' => 'auth',
            'pluginname' => 'internal',
            'autofocus' => false,
            'iscancellable'  => true,
            'elements' => array(
                'login_username' => array(
                    'type' => 'text',
                    'title' => get_string('username').':',
                    'description' => get_string('usernamedescription'),
                    'defaultvalue' => (isset($_POST['login_username'])) ? $_POST['login_username'] : '',
                    'rules' => array(
                        'required' => true,
                    ),
                ),
                'login_password' => array(
                    'type' => 'password',
                    'title' => get_string('password').':',
                    'description' => get_string('passworddescription'),
                    'defaultvalue' => '',
                    'rules' => array(
                        'required' => true,
                    ),
                ),
                'submit' => array(
                    'class' => 'btn-primary btn-block',
                    'type'  => 'submitcancel',
                    'value' => array(get_string('login'), get_string('cancel')),
                ),
            ),
        )));
    }

    /**
     * Callback for the login form.
     *
     * This just calls the core login function and redirects back to us so we can show the link form.
     *
     * @param \Pieform $form Pieform form instance.
     * @param array $values Array of submitted values.
     */
    public function login_submit(\Pieform $form, $values) {
        global $USER, $SESSION;
        // Save our OIDC info, because an invalid login will destroy it.
        $oidclinkdata = $SESSION->get('auth_oidc_linkdata');
        try {
            login_submit($form, $values);
        }
        catch (\AuthUnknownUserException $e) {
            $SESSION->set('auth_oidc_linkdata', $oidclinkdata);
            $SESSION->add_error_msg(get_string('loginfailed'));
            redirect('/auth/oidc/link.php');
        }
        if ($USER->is_logged_in()) {
            redirect('/auth/oidc/link.php');
        }
        else {
            $SESSION->set('auth_oidc_linkdata', $oidclinkdata);
            if (empty($_SESSION['messages'])) {
                $SESSION->add_error_msg(get_string('loginfailed'));
            }
            redirect('/auth/oidc/link.php');
        }
    }
}
