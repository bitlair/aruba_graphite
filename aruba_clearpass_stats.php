<?php
/**
 * Get stats from Aruba ClearPass using PostgreSQL (appexternal) and insert into Graphite/Carbon.
 *
 * @author: Arjan Koopen <arjan@koopen.net>
 */
include("common.php");
include("config.php");

if ($graphite_send) $fsock = fsockopen($graphite_ip, $graphite_port);

$con = pg_connect("host=$clearpass_host dbname=$clearpass_db user=$clearpass_user password=$clearpass_pass")
    or die ("Could not connect to server\n");

$query = "select count(id) from tips_endpoint_profiles;";
$rs = pg_query($con, $query) or die("Cannot execute query: $query\n");
$count = pg_fetch_row($rs);
$count = $count[0];

$query = "select device_category, COUNT(device_category) as cnt from tips_endpoint_profiles GROUP BY device_category  ORDER BY cnt DESC;";
$rs = pg_query($con, $query) or die("Cannot execute query: $query\n");
while ($o = pg_fetch_array($rs)) {
        sendGraphite("endpoint_category." . str_replace(" ", "_", str_replace(".", "_", $o["device_category"])), $o["cnt"]);
}

$query = "select device_family, COUNT(device_family) as cnt from tips_endpoint_profiles GROUP BY device_family  ORDER BY cnt DESC;";
$rs = pg_query($con, $query) or die("Cannot execute query: $query\n");
while ($o = pg_fetch_array($rs)) {
        sendGraphite("endpoint_os_family." . str_replace(" ", "_", str_replace(".", "_", $o["device_family"])), $o["cnt"]);
}
sendGraphite("endpoint_total",$count);


pg_close($con);
fclose($fsock);
?>