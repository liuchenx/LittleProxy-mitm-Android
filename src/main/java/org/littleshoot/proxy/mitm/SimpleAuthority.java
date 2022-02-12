package org.littleshoot.proxy.mitm;

import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x500.style.BCStyle;
import org.spongycastle.cert.jcajce.JcaX509CertificateHolder;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class SimpleAuthority implements Authority {

    private final KeyStore keyStore;

    private final String alias;

    private final char[] password;

    private final String commonName;

    private final String organization;

    private final String organizationalUnitName;

    private final X509Certificate certificate;

    private final PrivateKey privateKey;

    /**
     * Create a parameter object with the given certificate and certificate
     * authority informations
     */
    public SimpleAuthority(KeyStore keyStore, String alias, char[] password) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateEncodingException {
        super();
        this.keyStore = keyStore;
        this.alias = alias;
        this.password = password;
        this.certificate = (X509Certificate) keyStore.getCertificate(alias);
        this.privateKey = (PrivateKey) keyStore.getKey(alias, password);

        X500Name issuer = new JcaX509CertificateHolder(certificate).getIssuer();

        this.commonName = issuer.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
        this.organization = issuer.getRDNs(BCStyle.O)[0].getFirst().getValue().toString();
        this.organizationalUnitName = issuer.getRDNs(BCStyle.OU)[0].getFirst().getValue().toString();
    }

    @Override
    public Certificate getCACertificate() {
        return certificate;
    }

    @Override
    public PrivateKey privateKey() {
        return privateKey;
    }

    @Override
    public KeyStore keyStore() {
        return keyStore;
    }

    @Override
    public String alias() {
        return alias;
    }

    @Override
    public char[] password() {
        return password;
    }

    @Override
    public String commonName() {
        return commonName;
    }

    @Override
    public String organization() {
        return organization;
    }

    @Override
    public String organizationalUnitName() {
        return organizationalUnitName;
    }
}
