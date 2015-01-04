<?php
/**
 * Get SNMP stats from Aruba controllers and insert into Graphite/Carbon.
 *
 * Hacky PHP code ahead, beware :-)
 */

$graphite_send = true; // set to false if you only want text output (for debugging)
$graphite_ip = "127.0.0.1";
$graphite_port = 2003;
$graphite_prefix = "wlan.aruba.";

if ($graphite_send) $fsock = fsockopen($graphite_ip, $graphite_port);

$controllers = array (
        "aruba-master" => "#.#.#.#",
);
$community = "###";
$dot11_types = array (
        "INTEGER: 1" => "5ghz",
        "INTEGER: 2" => "2ghz",
        "INTEGER: 3" => "2ghz",
        "INTEGER: 4" => "dualband"
);
$snmp_base = 16;        // use 11 if your SNMP resolves OIDs

function sendGraphite($field, $value) {
        global $graphite_send, $graphite_prefix, $c_name, $fsock;

        $send = $graphite_prefix . $c_name . "." . $field . " " . $value . " " . time() . "\n";

        if ($graphite_send) {
                 fwrite($fsock, $send, strlen($send));
        }

        echo $send;
}

function get_snmp($oid, $type = "Gauge32") {
        global $ip, $community;

        return $value = sanatize_snmp($type, snmp2_get($ip, $community, $oid));
}

function sanatize_snmp($type, $value) {
        switch ($type) {
                case "Gauge32":
                        $value = str_replace("Gauge32: ", "", $value);
                        break;

                case "STRING":
                        $value = str_replace("\"", "", str_replace("STRING: ", "", $value));
                        break;

                case "INTEGER":
                        $value = str_replace("INTEGER: ", "", $value);
                        break;

                case "Counter64":
                        $value = str_replace("Counter64: ", "", $value);
                        break;
        }
        return $value;
}

foreach ($controllers as $c_name => $ip) {

        /**
         * Totals, CPU, Memory
         */
        sendGraphite("total_aps", get_snmp("1.3.6.1.4.1.14823.2.2.1.1.3.1.0"));
        sendGraphite("total_assoc", get_snmp("1.3.6.1.4.1.14823.2.2.1.1.3.2.0"));
        sendGraphite("cpu_used", get_snmp("1.3.6.1.4.1.14823.2.2.1.2.1.30.0"));
        sendGraphite("memory_used", get_snmp("1.3.6.1.4.1.14823.2.2.1.2.1.31.0"));

        /**
         * Temparature
         */
        $temp = explode(" ", get_snmp("1.3.6.1.4.1.14823.2.2.1.2.1.10.0", "STRING"));
        sendGraphite("internal_temparature", $temp[0]);

        /**
         * BSSID to ESSID table
         */
        $out = snmp2_real_walk($ip, $community, "1.3.6.1.4.1.14823.2.2.1.5.2.1.7.1.2");
        $_bssid_essid = array();

        foreach ($out as $key => $value) {
                $tmp = explode(".",$key);
                $b_key = array();
                for ($i = $snmp_base; $i < count($tmp); $i++) {
                        $b_key[] = $tmp[$i];
                }
                $b_key = implode(".",$b_key);

                $_bssid_essid[$b_key] = sanatize_snmp("STRING", $value);
        }

        /**
         * AP name table
         */
        $out = snmp2_real_walk($ip, $community, "1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.3");
        $_ap_name = array();

        foreach ($out as $key => $value) {
                $tmp = explode(".",$key);
                $a_key = array();
                for ($i = $snmp_base; $i < count($tmp); $i++) {
                        $a_key[] = $tmp[$i];
                }
                $a_key = implode(".",$a_key);

                $_ap_name[$a_key] = sanatize_snmp("STRING", $value);
        }

        /**
         * AP info
         */
        foreach ($_ap_name as $key => $ap_name) {
                sendGraphite("ap.{$ap_name}.status", get_snmp("1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.19.{$key}", "INTEGER"));
                sendGraphite("ap.{$ap_name}.num_bootstraps", get_snmp("1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.20.{$key}", "INTEGER"));
                sendGraphite("ap.{$ap_name}.num_reboots", get_snmp("1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.20.{$key}", "INTEGER"));
        }


        /**
         * Radio Type table
         */
        $out = snmp2_real_walk($ip, $community, "1.3.6.1.4.1.14823.2.2.1.5.2.1.5.1.2");
        $_radio_type = array();

        foreach ($out as $key => $value) {
                $tmp = explode(".",$key);
                $r_key = array();
                for ($i = $snmp_base; $i < count($tmp); $i++) {
                        $r_key[] = $tmp[$i];
                }
                $r_key = implode(".",$r_key);

                $_radio_type[$r_key] = $dot11_types[$value];
        }

        /**
         * Assoc & bytes (from BSSID table)
         */
        $out = snmp2_real_walk($ip, $community, "1.3.6.1.4.1.14823.2.2.1.5.3.1.1.1.2");
        $assoc_essid = array();
        $assoc_radio_essid = array();
        $assoc_ap = array();
        $assoc_radio = array();
        $assoc_radio_type = array();

        $bytes_essid = array();
        $bytes_radio_essid = array();
        $bytes_ap = array();
        $bytes_radio = array();
        $bytes_radio_type = array();


        foreach ($out as $key => $value) {
                $tmp = explode(".",$key);
                $bssid_key = array();
                $ap_key = array();
                $radio_key = array();
                for ($i = $snmp_base; $i < count($tmp); $i++) {
                        $bssid_key[] = $tmp[$i];
                        if ($i <= ($snmp_base + 5)) $ap_key[] = $tmp[$i];
                        if ($i <= ($snmp_base + 6)) $radio_key[] = $tmp[$i];
                }
                $bssid_key = implode(".",$bssid_key);
                $ap_key = implode(".",$ap_key);
                $radio_key = implode(".",$radio_key);

                $essid = $_bssid_essid[$bssid_key];
                $ap = $_ap_name[$ap_key];
                $radio_type = $_radio_type[$radio_key];

                $num = intval(str_replace("INTEGER: ", "", $value));

                if (!isset($assoc_essid[$essid])) $assoc_essid[$essid] = 0;
                $assoc_essid[$essid] += $num;

                if (!isset($assoc_ap[$ap . ".total"])) $assoc_ap[$ap . ".total"] = 0;
                $assoc_ap[$ap . ".total"] += $num;

                if (!isset($assoc_radio[$ap . "." . $radio_type . ".total"])) $assoc_radio[$ap . "." . $radio_type . ".total"] = 0;
                $assoc_radio[$ap . "." . $radio_type . ".total"] += $num;

                if (!isset($assoc_radio_type[$radio_type])) $assoc_radio_type[$radio_type] = 0;
                $assoc_radio_type[$radio_type] += $num;

                $assoc_radio_essid[$ap . "." . $radio_type . "." . $essid] = $num;

                // get num bytes
                $bytes_rx = get_snmp("1.3.6.1.4.1.14823.2.2.1.5.3.1.1.1.23.{$bssid_key}", "Counter64");
                $bytes_tx = get_snmp("1.3.6.1.4.1.14823.2.2.1.5.3.1.1.1.25.{$bssid_key}", "Counter64");

                if (!isset($bytes_essid[$essid . ".tx"])) $bytes_essid[$essid . ".tx"] = 0;
                if (!isset($bytes_essid[$essid . ".rx"])) $bytes_essid[$essid . ".rx"] = 0;
                $bytes_essid[$essid . ".tx"] += $bytes_tx;
                $bytes_essid[$essid . ".rx"] += $bytes_rx;

                if (!isset($bytes_ap[$ap . ".tx.total"])) $bytes_ap[$ap . ".tx.total"] = 0;
                if (!isset($bytes_ap[$ap . ".rx.total"])) $bytes_ap[$ap . ".rx.total"] = 0;
                $bytes_ap[$ap . ".tx.total"] += $bytes_tx;
                $bytes_ap[$ap . ".rx.total"] += $bytes_rx;

                if (!isset($bytes_radio[$ap . "." . $radio_type . ".tx.total"])) $bytes_radio[$ap . "." . $radio_type . ".tx.total"] = 0;
                if (!isset($bytes_radio[$ap . "." . $radio_type . ".rx.total"])) $bytes_radio[$ap . "." . $radio_type . ".rx.total"] = 0;
                $bytes_radio[$ap . "." . $radio_type . ".tx.total"] += $bytes_tx;
                $bytes_radio[$ap . "." . $radio_type . ".rx.total"] += $bytes_rx;

                if (!isset($bytes_radio_type[$radio_type . ".rx"])) $bytes_radio_type[$radio_type . ".rx"] = 0;
                if (!isset($bytes_radio_type[$radio_type . ".tx"])) $bytes_radio_type[$radio_type . ".tx"] = 0;
                $bytes_radio_type[$radio_type . ".rx"] += $bytes_rx;
                $bytes_radio_type[$radio_type . ".tx"] += $bytes_tx;

                $bytes_radio_essid[$ap . "." . $radio_type . "." . $essid . ".tx"] = $bytes_tx;
                $bytes_radio_essid[$ap . "." . $radio_type . "." . $essid . ".rx"] = $bytes_rx;

        }

        $assoc_a = array ("assoc_essid" => "essid", "assoc_ap" => "ap", "assoc_radio" => "ap", "assoc_radio_essid" => "ap", "assoc_radio_type" => "band");
        foreach ($assoc_a as $type => $prefix) {
                foreach ($$type as $key => $value) {
                        sendGraphite("assoc.{$prefix}.{$key}", $value);
                }
        }

        $bytes_a = array ("bytes_essid" => "essid", "bytes_ap" => "ap", "bytes_radio" => "ap", "bytes_radio_essid" => "ap", "bytes_radio_type" => "band");
        foreach ($bytes_a as $type => $prefix) {
                foreach ($$type as $key => $value) {
                        sendGraphite("bytes.{$prefix}.{$key}", $value);
                }
        }


        /**
         * Radio info
         */
        $radio_info = array (   // snmp index to type
                1 => "channel",
                2 => "num_channel_stations",
                9 => "noise",
                10 => "coverage_index",
                11 => "interference_index",
                12 => "frame_retry_rate",
                13 => "frame_low_speed_rate",
                14 => "frame_non_unicast_rate",
                15 => "frame_fragmentation_rate",
                16 => "frame_bandwidth_rate",
                19 => "num_channel_aps",
                35 => "util_rx",
                36 => "util_tx",
                37 => "util"
        );

        foreach ($radio_info as $index => $radio_info_field) {
                $out = snmp2_real_walk($ip, $community, "1.3.6.1.4.1.14823.2.2.1.5.3.1.6.1.{$index}");

                foreach ($out as $key => $value) {
                        $tmp = explode(".",$key);
                        $r_key = array();
                        $a_key = array();
                        for ($i = $snmp_base; $i < count($tmp); $i++) {
                                $r_key[] = $tmp[$i];
                                if ($i < count($tmp) - 1) $a_key[] = $tmp[$i];
                        }
                        $a_key = implode(".",$a_key);
                        $r_key = implode(".",$r_key);

                        $ap = $_ap_name[$a_key];
                        $radio_type = $_radio_type[$r_key];

                        sendGraphite("radio.{$ap}.{$radio_type}.{$radio_info_field}", sanatize_snmp("INTEGER", $value));
                }


        }
}
?>