<?php
/**
 *
 * @package mahara
 * @subpackage auth-oidc
 * @author James McQuillan <james.mcquillan@remote-learner.net>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2015 onwards Microsoft Open Technologies, Inc. (http://msopentech.com/)
 */

defined('INTERNAL') || die();

/**
 * Update plugin.
 *
 * @param int $oldversion the version we are upgrading from
 * @return bool result
 */
function xmldb_auth_oidc_upgrade($oldversion) {
    $result = true;

    if ($result && $oldversion < 2009072001) {
        // Create the core services tables
        $table = new \XMLDBTable('auth_oidc_state');
        $table->addFieldInfo('id', XMLDB_TYPE_INTEGER, 10, null, XMLDB_NOTNULL, XMLDB_SEQUENCE, null, null, null);
        $table->addFieldInfo('sesskey', XMLDB_TYPE_CHAR, 10, null, null);
        $table->addFieldInfo('state', XMLDB_TYPE_CHAR, 15, null, null);
        $table->addFieldInfo('nonce', XMLDB_TYPE_CHAR, 15, null, null);
        $table->addFieldInfo('timecreated', XMLDB_TYPE_INTEGER, 15, null, null);
        $table->addFieldInfo('additionaldata', XMLDB_TYPE_TEXT, null);
        $table->addKeyInfo('primary', XMLDB_KEY_PRIMARY, array('id'));
        $table->addIndexInfo('state', XMLDB_INDEX_NOTUNIQUE, array('state'));
        $table->addIndexInfo('timecreated', XMLDB_INDEX_NOTUNIQUE, array('timecreated'));
        create_table($table);
    }

    return $result;
}
