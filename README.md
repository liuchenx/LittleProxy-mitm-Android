![CI](https://github.com/liuchenx/LittleProxy-mitm-Android/actions/workflows/gradle-publish.yml/badge.svg)

LittleProxy - Man-In-The-Middle
===============================



### Important Security Note

**Please use your browser directly for every security-critical transmission.** 
Mozilla Firefox and Google Chrome implements her own certificate handling for a 
reason. Handling security in Java like here must be less secure in most 
situations. See http://www.cs.utexas.edu/~shmat/shmat_ccs12.pdf "The Most 
Dangerous Code in the World: Validating SSL Certificates in Non-Browser 
Software".

### Getting the library

Add this dependency to your Maven build:

```groovy
repositories {
    maven {
        url = uri("https://maven.pkg.github.com/liuchenx/LittleProxy-mitm-Android")
    }
}

dependencies {
    implementation("me.liuyichen.yuna:littleproxy-mitm-android:1.1.0")
}
```
The version corresponds to LittleProxy since the intention was to integrate it 
as a module.

### Wiring everything together

Once you've included LittleProxy-mitm, you can start the server with the following:

```java
HttpProxyServer server =
    DefaultHttpProxyServer.bootstrap()
        .withPort(9090) // for both HTTP and HTTPS
        .withManInTheMiddle(new CertificateSniffingMitmManager())
        .start();
```

Please give an `Authority` in the constructor to personalize your application. 
You impersonate certificates which is normally a bad thing. You have to describe 
the reason for.

Please refer to the documentation of 
[LittleProxy](https://github.com/adamfisk/LittleProxy) and [Netty](https://netty.io/) especially the Javadoc of `org.littleshoot.proxy.HttpFiltersSource`, `org.littleshoot.proxy.HttpFilters` and [io.netty.channel.ChannelPipeline](https://netty.io/4.1/api/index.html) to filter HTTP/S contents. FAQ: [#25](https://github.com/ganskef/LittleProxy-mitm/issues/25#issuecomment-533908538), [#32](https://github.com/ganskef/LittleProxy-mitm/issues/32#issuecomment-533904216)

### Resolving URI in case of HTTPS

Mostly you will need an URL to handle content in your filters. With HTTP it's 
provided by `originalRequest.getUri()`, but with HTTPS you have to get the host 
name from the initiating `CONNECT` request. Therefore you have to do something 
like this in your `HttpFiltersSource` implementation: 

```java
    private static final AttributeKey<String> CONNECTED_URL = AttributeKey.valueOf("connected_url");

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, ChannelHandlerContext clientCtx) {
        String uri = originalRequest.getUri();
        if (originalRequest.getMethod() == HttpMethod.CONNECT) {
            if (clientCtx != null) {
                String prefix = "https://" + uri.replaceFirst(":443$", "");
                clientCtx.channel().attr(CONNECTED_URL).set(prefix);
            }
            return new HttpFiltersAdapter(originalRequest, clientCtx);
        }
        String connectedUrl = clientCtx.channel().attr(CONNECTED_URL).get();
        if (connectedUrl == null) {
            return new MyHttpFilters(uri);
        }
        return new MyHttpFilters(connectedUrl + uri);
    }
```

 * On `CONNECT` you must **always** return a `HttpFiltersAdapter`, since it has 
 to  bypass all filtering. 
 * Without a saved `connected_url` in the context it's plain HTTP, no HTTPS.
 * Following requests on this channel have to concatenate the saved 
 `connected_url` with the URI from the `originalRequest`.

### Workarounds for Known Problems

 * HTTPS fails with Exception: Handshake has already been started on Android Version 5+ (https://github.com/netty/netty/issues/4718). It's fixed with [PR #4767](https://github.com/netty/netty/pull/4764). Using Netty 4.1.0.CR2-SNAPSHOT MITM works well with Android 5.0, 5.1, and 6.0, just as Java platforms too.

 * Connection failure with some HTTPS sites like https://www.archlinux.org/ for example. You have to use [Java Cryptography Extension](http://en.wikipedia.org/wiki/Java_Cryptography_Extension) to fix it.
```
387481 2015-05-19 21:34:39,061 WARN  [LittleProxy-ProxyToServerWorker-6] impl.ProxyToServerConnection - (HANDSHAKING) [id: 0x7e0de7f2, /192.168.178.30:1475 => www.archlinux.org/66.211.214.131:443]: Caught exception on proxy -> web connection
io.netty.handler.codec.DecoderException: java.lang.RuntimeException: Could not generate DH keypair
    at io.netty.handler.codec.ByteToMessageDecoder.callDecode(ByteToMessageDecoder.java:346)
...
Caused by: java.security.InvalidAlgorithmParameterException: Prime size must be multiple of 64, and can only range from 512 to 1024 (inclusive)
    at com.sun.crypto.provider.DHKeyPairGenerator.initialize(DHKeyPairGenerator.java:120)
...
```
 * I'm not a natural English speaker/writer. So feel free to fix me if I'm wrong 
 (or always in generally) and don't feel sad about a phrase.

### FAQ - Answered Questions

[Issues labeled with question](https://github.com/ganskef/LittleProxy-mitm/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3Aquestion+) which could be interesting for you too.