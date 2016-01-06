<?php
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

                case "Counter32":
                        $value = str_replace("Counter32: ", "", $value);
                        break;

                case "Counter64":
                        $value = str_replace("Counter64: ", "", $value);
                        break;
        }
        return $value;
}

function sshexec($shell, $command, $getoutput = true, $escape = "#") {
        fwrite($shell, $command . PHP_EOL);
        usleep(1500000);

        $out = "";
        if ($getoutput) {
                while ($buf = fgets($shell)) {
                        $out .= $buf;

                        if (strpos($buf, $escape) !== false) {
                                break;
                        }
                }
        }

        return $out;
}
?>
