<?php 

namespace Sncm\Helpers\IcpBrasil;

use phpseclib\File\X509;

class IcpBrasilCertificate
{
    public ?string $commonName = null;
    
    public ?string $name = null;

    public ?string $identifier = null;
    
    public ?string $cpf = null;
    
    public ?string $cnpj = null;

    public function __construct()
    {
    }

    public function parse(): void
    {
        $this->parseCommonName();
        $this->parseSANs();
    }

    private function parseCommonName()
    {
        if (isset($_SERVER['SSL_CLIENT_S_DN_CN'])) {
            $SSL_CLIENT_S_DN_CN = $_SERVER['SSL_CLIENT_S_DN_CN'];
        } else {
            if (!isset($_SESSION)) {
                session_start();
            }
            $SSL_CLIENT_S_DN_CN = $_SESSION['SSL_CLIENT_S_DN_CN'];
        }
        $this->commonName = $SSL_CLIENT_S_DN_CN;
        $cn = explode(':', $SSL_CLIENT_S_DN_CN);
        $this->name = $cn[0];
        if (isset($cn[1]) ) {
            $this->identifier = $cn[1];
            if ( $this->validCpf($cn[1]))
                $this->cpf = $cn[1];
            else if ($this->validCnpj($cn[1]))
                $this->cnpj = $cn[1];    
        }       
    }

    private function parseSANs()
    {
        if (isset($_SERVER['SSL_CLIENT_CERT'])) {
            $SSL_CLIENT_CERT = $_SERVER['SSL_CLIENT_CERT'];
        } else {
            if (!isset($_SESSION)) {
                session_start();
            }
            $SSL_CLIENT_CERT = $_SESSION['SSL_CLIENT_CERT'];
        }

        $x509 = new X509();

        $info = $x509->loadX509($SSL_CLIENT_CERT);

        for ($i = 0; isset($info['tbsCertificate']['extensions'][$i]); $i++) {
            if ($info['tbsCertificate']['extensions'][$i]['extnId'] == 'id-ce-subjectAltName') {
                for ($j = 0; isset($info['tbsCertificate']['extensions'][$i]['extnValue'][$j]); $j++) {
                    if (isset($info['tbsCertificate']['extensions'][$i]['extnValue'][$j]['otherName']['type-id'])) {
                        if ($info['tbsCertificate']['extensions'][$i]['extnValue'][$j]['otherName']['type-id'] == '2.16.76.1.3.1') {
                            $string = base64_decode($info['tbsCertificate']['extensions'][$i]['extnValue'][$j]['otherName']['value']['octetString']);
                            $this->cpf = substr($string, 8, 11);
                        }
                        if ($info['tbsCertificate']['extensions'][$i]['extnValue'][$j]['otherName']['type-id'] == '2.16.76.1.3.3') {
                            $string = base64_decode($info['tbsCertificate']['extensions'][$i]['extnValue'][$j]['otherName']['value']['octetString']);
                            $this->cnpj = $string;
                        }
                    }
                }
            }
        }
    }

    private function validCnpj($cnpj)
    {
        $cnpj = preg_replace('/[^0-9]/', '', $cnpj);  // remove '.', '-' and '/'

        if (strlen($cnpj) != 14) {
            return false;
        }

        $invalid = '/0{14}|1{14}|2{14}|3{14}|4{14}|5{14}|6{14}|7{14}|8{14}|9{14}/';

        if (preg_match($invalid, $cnpj)) {
            return false;
        }

        $CNPJsplit = array();
        $CNPJsplit = str_split($cnpj);

        // check the first verification digit (modulus 11)

        $soma = 0;

        $n = 5;

        for ($i = 0; $i <= 3; $i++) {
            $soma += $CNPJsplit[$i] * ($n - $i);
        }

        $n = 13;

        for ($i = 4; $i <= 11; $i++) {
            $soma += $CNPJsplit[$i] * ($n - $i);
        }

        if (($soma % 11) < 2) {  // remainder 0 or 1 digit is 0
            $dv1 = 0;
        } else {
            $dv1 = 11 - ($soma % 11);
        }

        // if the first is right check the second digit (modulus 11)

        if ($dv1 == $CNPJsplit[12]) {
            $soma = 0;

            $n = 6;

            for ($i = 0; $i <= 4; $i++) {
                $soma += $CNPJsplit[$i] * ($n - $i);
            }

            $n = 14;

            for ($i = 5; $i <= 12; $i++) {
                $soma += $CNPJsplit[$i] * ($n - $i);
            }

            if (($soma % 11) < 2) {  // remainder 0 or 1 digit is 0
                $dv2 = 0;
            } else {
                $dv2 = 11 - ($soma % 11);
            }

            // if the second is right return true

            if ($dv2 == $CNPJsplit[13]) {
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    private function validCpf($cpf)
    {
        $cpf = preg_replace('/[^0-9]/', '', $cpf);  // remove '.' and '-'

        if (strlen($cpf) != 11) {
            return false;
        }

        $invalid = '/0{11}|1{11}|2{11}|3{11}|4{11}|5{11}|6{11}|7{11}|8{11}|9{11}/';

        if (preg_match($invalid, $cpf)) {
            return false;
        }

        $CPFsplit = array();
        $CPFsplit = str_split($cpf);

        // check the first verification digit (modulus 11)

        $soma = 0;

        $n = 10;

        for ($i = 0; $i <= 8; $i++) {
            $soma += $CPFsplit[$i] * ($n - $i);
        }

        if (($soma % 11) < 2) {  // remainder 0 or 1 digit is 0
            $dv1 = 0;
        } else {
            $dv1 = 11 - ($soma % 11);
        }

        // if the first is right check the second digit (modulus 11)

        if ($dv1 == $CPFsplit[9]) {
            $soma = 0;

            $n = 11;

            for ($i = 0; $i <= 9; $i++) {
                $soma += $CPFsplit[$i] * ($n - $i);
            }

            if (($soma % 11) < 2) {  // remainder 0 or 1 digit is 0
                $dv2 = 0;
            } else {
                $dv2 = 11 - ($soma % 11);
            }

            // if the second is right return true

            if ($dv2 == $CPFsplit[10]) {
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
}