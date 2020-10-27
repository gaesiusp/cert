<?php

namespace Gaesi\Cert\IcpBrasil;

use Exception;
use Gaesi\Cert\IcpBrasil\IcpBrasilCertificate;
use Gaesi\Validator\CNPJ;
use Gaesi\Validator\CPF;
use phpseclib\File\X509;


class IcpBrasilParser
{
    private $x509 = null;
    private ?IcpBrasilCertificate $icpBrasilCert = null;
    
    protected function setInstance(IcpBrasilCertificate $icpBrasilCert): void
    {
        $this->icpBrasilCert = $icpBrasilCert;
    }

    /**
     * Realiza o parse de um Certificado SSL e retorna uma instancia de IcpBrasilCertificate
     * 
     * @return mixed Retorna uma instância de IcpBrasilCertificate ou null em caso de erro.
     */
    public function parseSSL(): ?IcpBrasilCertificate
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
    public function parseX509(string $x509 = null): ?IcpBrasilCertificate
    {
        try{
            $this->loadCert($x509);
            $this->parseSubjectDN();
            $this->parseSANs();
            $this->parseSanOids();
        }catch(Exception $e){
            $this->icpBrasilCert = null;
        }
        return $this->icpBrasilCert;
    }

    /**
     * Método carrega o Certificado SSL client ou Certificado Informado por parâmetro
     * 
     * @param string $cert Certificado que será carregado, formato PEM. 
     * Quando não informado o Certifica SSL é carregado.
     * 
     */
    private function loadCert($cert = null): void
    {
        if ($cert === null) {
            if (isset($_SERVER['HTTP_X_SSL_CERT'])) {
                $cert = urldecode($_SERVER['HTTP_X_SSL_CERT']);
            } else if (isset($_SERVER['SSL_CLIENT_CERT'])) {
                $cert = urldecode($_SERVER['SSL_CLIENT_CERT']);
            } else if (isset($_SERVER['HTTP_SSL_CLIENT_CERT'])) {
                $cert = urldecode($_SERVER['HTTP_SSL_CLIENT_CERT']);
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

    private function parseSubjectDN()
    {
        $dname = $this->x509->getDN(X509::DN_STRING);
        $this->icpBrasilCert->subjectDName = $dname;

        $cn = $this->x509->getDNProp('cn');
        $this->icpBrasilCert->commonName = $cn[0];

        if (!empty($cn) && isset($cn[0]) && preg_match('/.+[\:]{1}.+/',$cn[0]))
            $cn = explode(':', $cn[0]);
        else
            return;
        $name = $cn[0];
        $identifier = $cn[1];
        $this->icpBrasilCert->name = $name;
        $this->icpBrasilCert->cnIdentifier = $identifier;
        if (CPF::validate($identifier)) {
            $this->icpBrasilCert->cpf = $identifier;
        }else if( CNPJ::validate($identifier) ){
            $this->icpBrasilCert->cnpj = $identifier;
        }
    }
    
    private function parseSanOids(): void
    {
        $san = $this->x509->getExtension('id-ce-subjectAltName');
        if (empty($san))
            return;
        $oids = array();
        foreach ($san as $item) {
            if ( isset($item['otherName']) && isset($item['otherName']['type-id']) ){
                $value = base64_decode($item['otherName']['value']['octetString']);
                $oids[$item['otherName']['type-id']] = $value;
            }
        }
        $this->icpBrasilCert->setSanOids($oids);
    }

    private function parseSANs(): void
    {
        $san = $this->x509->getExtension('id-ce-subjectAltName');
        if (empty($san))
            return;
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