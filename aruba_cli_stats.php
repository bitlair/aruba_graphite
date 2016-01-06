<?php
/**
 * Get CLI stats from Aruba controllers and insert into Graphite/Carbon.
 *
 * @author: Arjan Koopen <arjan@koopen.net>
 */

include("common.php");
include("config.php");

foreach ($controllers as $c_name => $ip) {

	$connection = ssh2_connect($ip, 22);
	ssh2_auth_password($connection, $ssh_username, $ssh_password);
	$shell = ssh2_shell($connection,'bash', null, 1000, 10000, SSH2_TERM_UNIT_CHARS);

        sshexec($shell, "show datapath session counters");
        $out = sshexec($shell,"");
        $out = preg_match_all("/Current Entries[ ]+([0-9]+)/i",$out,$matches);
        $sessions = trim($matches[1][0]);

	sendGraphite("datapath.sessions", $sessions);
}
?>
