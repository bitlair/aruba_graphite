<?php
/**
 * Get comma-seperated BSSID list from Aruba controllers and output to STDOUT
 *
 * @author: Arjan Koopen <arjan@koopen.net>
 */
include("common.php");
include("config.php");

foreach ($controllers as $c_name => $ip) {
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
         * BSSID to ESSID table
         */
        $out = snmp2_real_walk($ip, $community, "1.3.6.1.4.1.14823.2.2.1.5.2.1.7.1.2");
        $_bssid_essid = array();
        foreach ($out as $key => $value) {
                $tmp = explode(".",$key);
                $b_key = array();
				$bssid = array();
				$ap_name = "";
				$j = 1;
                for ($i = $snmp_base; $i < count($tmp); $i++) {
                        $b_key[] = $tmp[$i];
						if ($j == 6) {
							$ap_name = $_ap_name[implode(".",$b_key)];
						}
						elseif ($j >= 8) {
							$oct = dechex($tmp[$i]);
							if (strlen($oct) == 1) $oct = "0" . $oct;
							$bssid[] = $oct;
						}
						$j++;
                }
				echo implode(":", $bssid). ";{$ap_name}\n";
        }
}
?>