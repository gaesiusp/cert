# Gaesi/cert

A PHP library for working with Certificates.

 - ICP-Brasil Support
 - SSL Certificate Parser
 
 ## Usage


 For load the SSL Certificate: 
 ```` php
 use Gaesi\Cert\IcpBrasil\IcpBrasilCertificate;

 $icp = new IcpBrasilCertificate();
 $icp->parseSSL();

 echo $icp->cnpj;   // print the cnpj
 echo $icp->name;   // print the name of the CommonName
 echo $icp->hasOid('2.16.76.1.3.3'); // true

 ````

 For load the Certificate from the text or file:
 ```` php
 use Gaesi\Cert\IcpBrasil\IcpBrasilCertificate;

 string $cert = "-----BEGIN CERTIFICATE-----MIIG4...XLFw==-----END CERTIFICATE-----";
 $icp = new IcpBrasilCertificate();
 $icp->parseX509($cert);
 echo $icp->cnpj;   // print the cnpj

 ````
 ## References

 https://www.gov.br/iti/pt-br/centrais-de-conteudo/doc-icp-04-01-versao-3-3-atribuicao-de-oid-na-icp-brasil-pdf

 ## TODO
  - Verify Certificate Chain
  - Verify Certificate is ICPBrasil