<?php

namespace Gaesi\Cert\IcpBrasil;

use Exception;
use Gaesi\Cert\IcpBrasil\IcpBrasilCertificate;
use phpseclib\File\X509;


class IcpBrasilParser
{
    private $x509 = null;
    private ?IcpBrasilCertificate $icpBrasilCert = null;
    
    protected function setInstance(IcpBrasilCertificate $icpBrasilCert): void
    {
        $this->icpBrasilCert = $icpBrasilCert;
    }
    
    public function parseSSL(): IcpBrasilCertificate
    {
        return $this->parseX509();
    }

    /**
     * Realiza o parse de um certificado X509 e retorna uma instancia de IcpBrasilCertificate
     * 
     * @param string Certificado X509 no formato PEM
     * 
     * @return mixed Retorna uma instância de IcpBrasilCertificate ou null em caso de erro.
     */
    public function parseX509(string $x509 = null): IcpBrasilCertificate
    {
        try{
            $this->loadCert($x509);
            $this->parseCommonName();
            $this->parseSANs();
        }catch(Exception $e){
            $this->icpBrasilCert = null;
        }
        return $this->icpBrasilCert;
    }

    private function loadCert($cert = null): void
    {
        if ($cert === null) {
            if (isset($_SERVER['HTTP_X_SSL_CERT'])) {
                $cert = urldecode($_SERVER['HTTP_X_SSL_CERT']);
            } else if (isset($_SERVER['SSL_CLIENT_CERT'])) {
                $cert = urldecode($_SERVER['SSL_CLIENT_CERT']);
            } else {
                if (!isset($_SESSION)) {
                    session_start();
                }
                $cert = $_SESSION['SSL_CLIENT_CERT'];
            }
            $x509 = new X509();
            if ($x509->loadX509($cert) === false){
                return;
            }
        }else{
            $x509 = new X509();
            if ($x509->loadX509($cert) === false){
                return;
            }
        }
        if ($this->icpBrasilCert === null ) {
            $this->icpBrasilCert = new IcpBrasilCertificate();
        }
        $this->x509 = $x509;
        $this->icpBrasilCert->setX509($x509);
    }

    private function parseCommonName()
    {
        if (isset($_SERVER['SSL_CLIENT_S_DN_CN'])) {
            $SSL_CLIENT_S_DN_CN = $_SERVER['SSL_CLIENT_S_DN_CN'];
        } else if (isset($_SERVER['HTTP_X_SSL_S_DN'])) {
            $dn = explode(',', $_SERVER['HTTP_X_SSL_S_DN']);
            $rdn = explode('=', $dn[0]); // assumindo que CN seja o primeiro
            $SSL_CLIENT_S_DN_CN = $rdn[1];
        } else {
            if (!isset($_SESSION)) {
                session_start();
            }
            $SSL_CLIENT_S_DN_CN = $_SESSION['SSL_CLIENT_S_DN_CN'];
        }
        return $SSL_CLIENT_S_DN_CN;

    }
    
    private function parseSanOids(): void
    {
        $san = $this->cert->getExtension('id-ce-subjectAltName');
        $oids = array();
        foreach ($san as $item) {
            if ( isset($item['otherName']) && isset($item['otherName']['type-id']) ){
                $value = base64_decode($item['otherName']['value']['octetString']);
                $oids[] = [$item['otherName']['type-id'] => $value];
            }
        }
        $this->icpBrasilCert->setSanOids($oids);
    }

    private function parseSANs(): void
    {
        $san = $this->cert->getExtension('id-ce-subjectAltName');
        foreach ($san as $item) {
            if ( isset($item['otherName']) && isset($item['otherName']['type-id']) ){
                if ($item['otherName']['type-id'] == '2.16.76.1.3.1') {
                    $string = base64_decode($item['otherName']['value']['octetString']);
                    $this->cpf = substr($string, 8, 11);
                }
                if ($item['otherName']['type-id'] == '2.16.76.1.3.3') {
                    $string = base64_decode($item['otherName']['value']['octetString']);
                    $this->cnpj = $string;
                }
            }
        }
    }
    
}