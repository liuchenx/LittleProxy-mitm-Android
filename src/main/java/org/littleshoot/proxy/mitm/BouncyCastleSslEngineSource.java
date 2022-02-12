package org.littleshoot.proxy.mitm;

import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;


import org.spongycastle.operator.OperatorCreationException;
import org.littleshoot.proxy.SslEngineSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

/**
 * A {@link SslEngineSource} which creates a key store with a Root Certificate
 * Authority. The certificates are generated lazily if the given key store file
 * doesn't yet exist.
 * 
 * The root certificate is exported in PEM format to be used in a browser. The
 * proxy application presents for every host a dynamically created certificate
 * to the browser, signed by this certificate authority.
 * 
 * This facilitates the proxy to handle as a "Man In The Middle" to filter the
 * decrypted content in clear text.
 * 
 * The hard part was done by mawoki. It's derived from Zed Attack Proxy (ZAP).
 * ZAP is an HTTP/HTTPS proxy for assessing web application security. Copyright
 * 2011 mawoki@ymail.com Licensed under the Apache License, Version 2.0
 */
public class BouncyCastleSslEngineSource implements SslEngineSource {

    private static final Logger LOG = LoggerFactory.getLogger(BouncyCastleSslEngineSource.class);

    /**
     * The P12 format has to be implemented by every vendor. Oracles proprietary
     * JKS type is not available in Android.
     */
    private static final String KEY_STORE_TYPE = "PKCS12";

    private static final String KEY_STORE_FILE_EXTENSION = ".p12";

    private final Authority authority;

    private final boolean trustAllServers;
    private final boolean sendCerts;

    private SSLContext sslContext;


    private Cache<String, SSLContext> serverSSLContexts;

    /**
     * Creates a SSL engine source create a Certificate Authority if needed and
     * initializes a SSL context. Exceptions will be thrown to let the manager
     * decide how to react. Don't install a MITM manager in the proxy in case of
     * a failure.
     * 
     * @param authority
     *            a parameter object to provide personal informations of the
     *            Certificate Authority and the dynamic certificates.
     * 
     * @param trustAllServers
     * 
     * @param sendCerts
     * 
     * @param sslContexts
     *            a cache to store dynamically created server certificates.
     *            Generation takes between 50 to 500ms, but only once per
     *            thread, since there is a connection cache too. It's save to
     *            give a null cache to prevent memory or locking issues.
     */
    public BouncyCastleSslEngineSource(Authority authority,
                                       boolean trustAllServers, boolean sendCerts,
                                       Cache<String, SSLContext> sslContexts)
            throws GeneralSecurityException, OperatorCreationException,
            RootCertificateException, IOException {
        this.authority = authority;
        this.trustAllServers = trustAllServers;
        this.sendCerts = sendCerts;
        this.serverSSLContexts = sslContexts;
        initializeSSLContext();
    }

    /**
     * Creates a SSL engine source create a Certificate Authority if needed and
     * initializes a SSL context. This constructor defaults a cache to store
     * dynamically created server certificates. Exceptions will be thrown to let
     * the manager decide how to react. Don't install a MITM manager in the
     * proxy in case of a failure.
     * 
     * @param authority
     *            a parameter object to provide personal informations of the
     *            Certificate Authority and the dynamic certificates.
     * 
     * @param trustAllServers
     * 
     * @param sendCerts
     */
    public BouncyCastleSslEngineSource(Authority authority,
                                       boolean trustAllServers, boolean sendCerts)
            throws RootCertificateException, GeneralSecurityException,
            IOException, OperatorCreationException {
        this(authority, trustAllServers, sendCerts,
                initDefaultCertificateCache());
    }

    private static Cache<String, SSLContext> initDefaultCertificateCache() {
        return CacheBuilder.newBuilder() //
                .expireAfterAccess(5, TimeUnit.MINUTES) //
                .concurrencyLevel(16) //
                .build();
    }

    private void filterWeakCipherSuites(SSLEngine sslEngine) {
        List<String> ciphers = new LinkedList<String>();
        for (String each : sslEngine.getEnabledCipherSuites()) {
            if (each.equals("TLS_DHE_RSA_WITH_AES_128_CBC_SHA") || each.equals("TLS_DHE_RSA_WITH_AES_256_CBC_SHA")) {
                LOG.debug("Removed cipher {}", each);
            } else {
                ciphers.add(each);
            }
        }
        sslEngine.setEnabledCipherSuites(ciphers.toArray(new String[ciphers.size()]));
        if (LOG.isDebugEnabled()) {
            if (sslEngine.getUseClientMode()) {
                LOG.debug("Enabled server cipher suites:");
            } else {
                String host = sslEngine.getPeerHost();
                int port = sslEngine.getPeerPort();
                LOG.debug("Enabled client {}:{} cipher suites:", host, port);
            }
            for (String each : ciphers) {
                LOG.debug(each);
            }
        }
    }

    public SSLEngine newSslEngine() {
        SSLEngine sslEngine = sslContext.createSSLEngine();
        filterWeakCipherSuites(sslEngine);
        return sslEngine;
    }

    @Override
    public SSLEngine newSslEngine(String remoteHost, int remotePort) {
        SSLEngine sslEngine = sslContext
                .createSSLEngine(remoteHost, remotePort);
        sslEngine.setUseClientMode(true);
        if (!tryHostNameVerificationJava7(sslEngine)) {
            LOG.debug("Host Name Verification is not supported, causes insecure HTTPS connection");
        }
        filterWeakCipherSuites(sslEngine);
        return sslEngine;
    }

    private boolean tryHostNameVerificationJava7(SSLEngine sslEngine) {
        for (Method method : SSLParameters.class.getMethods()) {
            // method is available since Java 7
            if ("setEndpointIdentificationAlgorithm".equals(method.getName())) {
                SSLParameters sslParams = new SSLParameters();
                try {
                    method.invoke(sslParams, "HTTPS");
                } catch (IllegalAccessException e) {
                    LOG.debug(
                            "SSLParameters#setEndpointIdentificationAlgorithm",
                            e);
                    return false;
                } catch (InvocationTargetException e) {
                    LOG.debug(
                            "SSLParameters#setEndpointIdentificationAlgorithm",
                            e);
                    return false;
                }
                sslEngine.setSSLParameters(sslParams);
                return true;
            }
        }
        return false;
    }


    private void initializeSSLContext() throws GeneralSecurityException {
        KeyStore ks = authority.keyStore();

        TrustManager[] trustManagers;
        if (trustAllServers) {
            trustManagers = InsecureTrustManagerFactory.INSTANCE
                    .getTrustManagers();
        } else {
            trustManagers = new TrustManager[] { new MergeTrustManager(ks) };
        }

        KeyManager[] keyManagers;
        if (sendCerts) {
            keyManagers = CertificateHelper.getKeyManagers(ks, authority.password());
        } else {
            keyManagers = new KeyManager[0];
        }

        sslContext = CertificateHelper.newClientContext(keyManagers,
                trustManagers);
        SSLEngine sslEngine = sslContext.createSSLEngine();
        if (!tryHostNameVerificationJava7(sslEngine)) {
            LOG.warn("Host Name Verification is not supported, causes insecure HTTPS connection to upstream servers.");
        }
    }


    /**
     * Generates an 1024 bit RSA key pair using SHA1PRNG. Thoughts: 2048 takes
     * much longer time on older CPUs. And for almost every client, 1024 is
     * sufficient.
     * 
     * Derived from Zed Attack Proxy (ZAP). ZAP is an HTTP/HTTPS proxy for
     * assessing web application security. Copyright 2011 mawoki@ymail.com
     * Licensed under the Apache License, Version 2.0
     * 
     * @param commonName
     *            the common name to use in the server certificate
     * 
     * @param subjectAlternativeNames
     *            a List of the subject alternative names to use in the server
     *            certificate, could be empty, but must not be null
     * 
     * @see org.parosproxy.paros.security.SslCertificateServiceImpl.createCertForHost(String)
     * @see org.parosproxy.paros.network.SSLConnector.getTunnelSSLSocketFactory(
     *      String)
     */
    public SSLEngine createCertForHost(final String commonName,
            final SubjectAlternativeNameHolder subjectAlternativeNames)
            throws GeneralSecurityException, OperatorCreationException,
            IOException, ExecutionException {
        if (commonName == null) {
            throw new IllegalArgumentException(
                    "Error, 'commonName' is not allowed to be null!");
        }
        if (subjectAlternativeNames == null) {
            throw new IllegalArgumentException(
                    "Error, 'subjectAlternativeNames' is not allowed to be null!");
        }

        SSLContext ctx;
        if (serverSSLContexts == null) {
            ctx = createServerContext(commonName, subjectAlternativeNames);
        } else {
            ctx = serverSSLContexts.get(commonName, new Callable<SSLContext>() {
                @Override
                public SSLContext call() throws Exception {
                    return createServerContext(commonName,
                            subjectAlternativeNames);
                }
            });
        }
        return ctx.createSSLEngine();
    }

    private SSLContext createServerContext(String commonName,
            SubjectAlternativeNameHolder subjectAlternativeNames)
            throws GeneralSecurityException, IOException,
            OperatorCreationException {

        MillisecondsDuration duration = new MillisecondsDuration();

        KeyStore ks = CertificateHelper.createServerCertificate(commonName,
                authority.organization(),
                authority.organizationalUnitName(),
                subjectAlternativeNames,
                authority.alias(),
                authority.password(),
                authority.getCACertificate(),
                authority.privateKey());
        KeyManager[] keyManagers = CertificateHelper.getKeyManagers(ks, authority.password());

        SSLContext result = CertificateHelper.newServerContext(keyManagers);

        LOG.info("Impersonated {} in {}ms", commonName, duration);
        return result;
    }


}

class MillisecondsDuration {
    private final long mStartTime = System.currentTimeMillis();

    @Override
    public String toString() {
        return String.valueOf(System.currentTimeMillis() - mStartTime);
    }
}
