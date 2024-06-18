package org.webkernel.https;

import lv.lumii.pqc.InjectableFrodoKEM;
import lv.lumii.pqc.InjectableLiboqsKEM;
import lv.lumii.pqc.InjectableLiboqsSigAlg;
import lv.lumii.pqc.InjectableSphincsPlus;
import lv.lumii.tls.auth.FileToken;
import lv.lumii.tls.auth.Token;
import lv.lumii.smartcard.InjectableSmartCardRSA;
import lv.lumii.smartcard.SmartCardSignFunction;
import nl.altindag.ssl.SSLFactory;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tls.injection.InjectableAlgorithms;
import org.bouncycastle.tls.injection.InjectableKEMs;
import org.bouncycastle.tls.injection.InjectionPoint;
import org.openquantumsafe.Common;
import org.openquantumsafe.KEMs;
import org.openquantumsafe.Sigs;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;


import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;



public class HttpsTest {

    private static final String MAIN_DIRECTORY = mainDirectory();
    private static String mainDirectory() {
        File f = new File(HttpsTest.class.getProtectionDomain().getCodeSource().getLocation().getPath());
        String mainExecutable = f.getAbsolutePath();
        String mainDirectory = f.getParent();

        // Fix for debug purposes when launching from the IDE:
        if (mainExecutable.replace('\\', '/').endsWith("/build/classes/java/main")) {
            mainDirectory = mainExecutable.substring(0, mainExecutable.length() - "/build/classes/java/main".length());
            mainExecutable = "java";
        }
        if (mainExecutable.replace('\\', '/').endsWith("/build/classes/java/test")) {
            mainDirectory = mainExecutable.substring(0, mainExecutable.length() - "/build/classes/java/test".length());
            mainExecutable = "java";
        }
        return mainDirectory;
    }

    class MyHttpResponseHandler implements HttpClientResponseHandler {

        @Override
        public Object handleResponse(ClassicHttpResponse classicHttpResponse) throws HttpException, IOException {
            return null;
        }
    }

    public static void main(String[] args) throws Exception {

        Common.loadNativeLibrary();
        Token token = new FileToken(MAIN_DIRECTORY+File.separator+"client.pfx", "client-keystore-pass", "client");

        injectPQC(false, (message) -> token.signed(message));

        try {
            KeyStore trustStore = KeyStore.getInstance(new File(MAIN_DIRECTORY+File.separator+"ca.truststore"), "ca-truststore-pass".toCharArray());

            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("SunX509");
            trustMgrFact.init(trustStore);

            SSLFactory sslf2 = SSLFactory.builder()
                        .withIdentityMaterial(token.key(), token.password(), token.certificateChain())
                        .withNeedClientAuthentication()
                        .withWantClientAuthentication()
                        .withProtocols("TLSv1.3")
                        .withTrustMaterial(trustMgrFact)
                        .withSecureRandom(SecureRandom.getInstanceStrong())
                        .withCiphers("TLS_AES_256_GCM_SHA384")
                        .build();

            /*final SSLConnectionSocketFactory sslsf =
                    new SSLConnectionSocketFactory(sslf2.getSslContext(), NoopHostnameVerifier.INSTANCE);

            final Registry<ConnectionSocketFactory> socketFactoryRegistry =
                    RegistryBuilder.<ConnectionSocketFactory> create()
                            .register("https", sslsf)
                            .register("http", new PlainConnectionSocketFactory())
                            .build();

            final BasicHttpClientConnectionManager connectionManager =
                    new BasicHttpClientConnectionManager(socketFactoryRegistry);


            CloseableHttpClient httpClient = HttpClients.custom()
                    .setConnectionManager(connectionManager)
                    .build();

            HttpGet request = new HttpGet("https://127.0.0.1:4433");
            httpClient.execute(request, (classicHttpResponse)->{
                byte[] b = classicHttpResponse.getEntity().getContent().readAllBytes();
                String s = new String(b, "UTF-8");
                System.out.println("BODY="+s);
                return classicHttpResponse;
            });*/


            Optional<X509ExtendedTrustManager> tm = sslf2.getTrustManager();

            OkHttpClient client = new OkHttpClient.Builder()
                .sslSocketFactory(sslf2.getSslSocketFactory(), tm.get())
                .build();

            Request request = new Request.Builder()
                    .url("https://127.0.0.1:4433")
                    //.url("http://127.0.0.1:8080")
                    .build();

            try (Response response = client.newCall(request).execute()) {
                if (!response.isSuccessful()) throw new IOException("Unexpected code " + response);

                System.out.println(response.body().string());
            }
        }
        catch (Exception e) {
            System.err.println("Some exception occurred.123456");
            e.printStackTrace();
        }

    }

    private static void injectPQC(boolean insteadDefaultKems, SmartCardSignFunction smartCardSignFunction) {
        // PQC signatures are huge; increasing the max handshake size:
        System.setProperty("jdk.tls.maxHandshakeMessageSize", String.valueOf(32768 * 32));

        InjectableSphincsPlus mySphincs = new InjectableSphincsPlus();
        InjectableSmartCardRSA myRSA = new InjectableSmartCardRSA(smartCardSignFunction);

        String oqsName = "SPHINCS+-SHA2-128f-simple";
        List<String> oqsAliases = Arrays.asList(new String[] {"SPHINCS+-SHA2-128F", "SPHINCS+", "SPHINCSPLUS"});
        InjectableLiboqsSigAlg oqsSphincs = new InjectableLiboqsSigAlg(oqsName, oqsAliases, mySphincs.oid(), mySphincs.codePoint());

        for (String s : KEMs.get_enabled_KEMs()) {
            System.out.println("ENABLED KEM "+s);
        }

        for (String s : KEMs.get_supported_KEMs()) {
            System.out.println("SUPPORTED KEM "+s);
        }

        for (String s : Sigs.get_enabled_sigs()) {
            System.out.println("ENABLED SIG "+s);
        }

        for (String s : Sigs.get_supported_sigs()) {
            System.out.println("SUPPORTED SIG "+s);
        }
        String oqsDilithiumName = "Dilithium2";
        int oqsDilithiumCodePoint = 0xfea0;
        ASN1ObjectIdentifier oqsDilithiumOid = new ASN1ObjectIdentifier("1.3.6.1.4.1.2.267.7.4").branch("4");
        Collection<String> oqsDilithiumAliases = Arrays.asList(new String[]{});
        InjectableLiboqsSigAlg oqsDilithium2 = new InjectableLiboqsSigAlg(oqsDilithiumName, oqsDilithiumAliases, oqsDilithiumOid, oqsDilithiumCodePoint);

        InjectableAlgorithms algs = new InjectableAlgorithms()
                //.withSigAlg(oqsSphincs.name(), oqsAliases, oqsSphincs.oid(), oqsSphincs.codePoint(), oqsSphincs)
                //.withSigAlg(oqsDilithiumName, oqsDilithiumAliases, oqsDilithiumOid, oqsDilithiumCodePoint, oqsDilithium2)

                //.withSigAlg(mySphincs.name(), mySphincs.aliases(), mySphincs.oid(), mySphincs.codePoint(), mySphincs)

                // for SC (2 lines):
                .withSigAlg("SHA256WITHRSA", List.of(new String[]{}), myRSA.oid(), myRSA.codePoint(), myRSA)
                .withSigAlg("RSA", List.of(new String[]{}), myRSA.oid(), myRSA.codePoint(), myRSA)
                //.withSigAlg("SHA256WITHRSA", myRSA.oid(), myRSA.codePoint(), myRSA)
                //.withSigAlg("RSA", myRSA.oid(), myRSA.codePoint(), myRSA)
                // RSA must be _after_ SHA256WITHRSA, since they share the same code point, and BC TLS uses "RSA" as a name for finding client RSA certs (however, SHA256WITHRSA is also needed for checking client cert signatures)

                //.withKEM(InjectableFrodoKEM.NAME, InjectableFrodoKEM.CODE_POINT,
                //       InjectableFrodoKEM::new, InjectableKEMs.Ordering.BEFORE)

                .withKEM(InjectableFrodoKEM.NAME, InjectableFrodoKEM.CODE_POINT,
                        ()->new InjectableLiboqsKEM(InjectableFrodoKEM.NAME, InjectableFrodoKEM.CODE_POINT), InjectableKEMs.Ordering.AFTER);//.BEFORE);

        // TODO: ML-KEM-512, 0x0247
        if (insteadDefaultKems)
            algs = algs.withoutDefaultKEMs();


        InjectionPoint.theInstance().push(algs);
    }



}
