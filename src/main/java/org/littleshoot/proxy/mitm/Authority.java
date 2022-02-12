package org.littleshoot.proxy.mitm;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

public interface Authority {


    KeyStore keyStore();

    Certificate getCACertificate();

    PrivateKey privateKey();

    String alias();

    char[] password();

    String commonName();

    String organization();

    String organizationalUnitName();
}
