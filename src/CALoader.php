<?php

namespace Gaesi\Cert;

/**
 * Parse of a file repository with trusted CAs 
 */
class CALoader
{
    private $paths = null;

    /** Array with all CAs Loadeds */
    private $CAs = null;

    /** types of file extensions accepted */
    private $extPattern = '/(\.cer)|(\.crt)|(\.pem)|(\.txt)/';

    /**
     * Include the path of a repository of trust CAs and intermediate certs 
     * 
     * @param string $path Path of repository
     */
    public function addRepositoryPath(string $path): void
    {
        $this->paths[] = $path;
    }

    /**
     * Include the trust CAs and intermediate certs
     * 
     * @param string|array $cert Certificates CA ou intermediate
     */
    public function addCerts($cert): void
    {
        $this->addCA($this->splitChainFile($cert));
    }

    /**
     * Get a array with all CAs
     *    
     */
    public function getCAs()
    {
        $this->loadFiles();
        if (!empty($this->CAs))
            $this->CAs = array_unique($this->CAs);
        return $this->CAs;
    }

    private function loadFiles(): void
    {
        if (empty($this->paths)) return;
        foreach ($this->paths as $path) {
            $files = array_diff(scandir($path), array('..', '.'));
            foreach ($files as $f)
                if (preg_match($this->extPattern, strtolower($f)) && is_file($f)){
                    $this->addCA($this->splitChainFile(file_get_contents($f)));
                }
        }
    }

    private function splitChainFile($file)
    {
        if (preg_match_all('/-----BEGIN CERTIFICATE-----/', $file) > 1){
            $files = explode('-----BEGIN CERTIFICATE-----',$file);
            foreach ($files as $key => $value) {
                $files[$key] = preg_replace('/([-]{5}.+[-]{5})|(\n)|(\r)/', '', $value);
            }
            return $files;
        }else{
            return preg_replace('/([-]{5}.+[-]{5})|(\n)|(\r)/', '', $file);
        }
    }

    private function addCA($file): void
    {
        if (is_array($file)) {
            foreach ($file as $f) {
                if (!empty($f))
                    $this->CAs[] = $f;
            }
        }else{
            if (!empty($file))
                $this->CAs[] = $file;
        }
    }
}