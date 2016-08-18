<?php
error_reporting(E_ALL ^ E_NOTICE);

$graphite_send = true; // set to false if you only want text output (for debugging)
$graphite_ip = "127.0.0.1";
$graphite_port = 2003;
$graphite_prefix = "wlan.aruba.";

// controller name => IP address
$controllers = array (
        "aruba-master" => "a.b.c.d",
);
// snmp community
$community = "###";
$dot11_types = array (
        "INTEGER: 1" => "5ghz",
        "INTEGER: 2" => "2ghz",
        "INTEGER: 3" => "2ghz",
        "INTEGER: 4" => "dualband"
);
$snmp_base = 16;        // use 11 if your SNMP resolves OIDs

// ssh username/password for CLI script
$ssh_username = "###";
$ssh_password = "###";

// clearpass postgres database details
$clearpass_host = "a.b.c.d";
$clearpass_user = "appexternal";
$clearpass_pass = "###";
$clearpass_db = "tipsdb";
?>