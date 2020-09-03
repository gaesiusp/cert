<?php

namespace Sncm\Helpers\Certs;

use Exception;
use phpseclib\File\X509;

class IcpBrasilParser
{
    private $x509 = null;

    public function parseSSL(): void
    {
        $this->loadCert();
        $this->parseCommonName();
        $this->parseSANs();
    }

    public function parseX509(string $x509): void
    {
        try{
            $x509 = new X509();
            $info = $x509->loadX509($x509);

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
        }catch(Exception $e){
            $x509 = null;
        }
        // TODO:: Load String
    }

    private function loadCert($x509 = null): void
    {
        // TODO: if x509 null -> LoadSSL
        // TODO: if x509 not null -> LoadFile
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

    private function parseOIDs(): void
    {
        $san = $cert->getExtension('id-ce-subjectAltName');
        $oids = array();
        foreach ($san as $item) {
            if ( isset($item['otherName']) && isset($item['otherName']['type-id']) ){
                $oids[] = $item['otherName']['type-id'];
            }
        }
        return $oids;
    }
    
}