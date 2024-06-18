package org.webkernel.https;

import lv.lumii.tls.auth.FileToken;
import lv.lumii.tls.auth.Token;
import lv.lumii.qkd.InjectableEtsiKEM;
import lv.lumii.tls.auth.TrustStore;
import nl.altindag.ssl.SSLFactory;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.bouncycastle.tls.injection.InjectableAlgorithms;
import org.bouncycastle.tls.injection.InjectableKEMs;
import org.bouncycastle.tls.injection.InjectionPoint;
import org.openquantumsafe.Common;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;


public class QkdHttpsTestClient {

    private static final String MAIN_DIRECTORY = mainDirectory();

    private static String mainDirectory() {
        File f = new File(QkdHttpsTestClient.class.getProtectionDomain().getCodeSource().getLocation().getPath());
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

    public static void main(String[] args) throws Exception {

        Common.loadNativeLibrary();

        injectQKD(()->{
            Token saeToken = new FileToken(
                    new String[] {MAIN_DIRECTORY + File.separator + "sae-1.crt.pem"},
                    MAIN_DIRECTORY + File.separator + "sae-1.key.pem",
                    "");
            TrustManagerFactory trustMgrFact = new TrustStore(new String[]{MAIN_DIRECTORY + File.separator+"ca.crt.pem"}).trustManagerFactory();

            try {
                SSLFactory sslf1 = SSLFactory.builder()
                        .withIdentityMaterial(saeToken.key(), saeToken.password(), saeToken.certificateChain())
                        .withNeedClientAuthentication()
                        .withWantClientAuthentication()
                        .withProtocols("TLSv1.3")
                        .withTrustMaterial(trustMgrFact)
                        .withSecureRandom(SecureRandom.getInstanceStrong())
                        .withCiphers("TLS_AES_256_GCM_SHA384")
                        .build();
                return sslf1;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        try {
            Token token = new FileToken(MAIN_DIRECTORY + File.separator + "client.pfx", "client-keystore-pass", "client");

            KeyStore trustStore = KeyStore.getInstance(new File(MAIN_DIRECTORY + File.separator + "ca.truststore"), "ca-truststore-pass".toCharArray());

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
                    .url("https://127.0.0.1:8443")
                    //.url("https://127.0.0.1:1234")
                    //.url("https://127.0.0.1:4433")
                    //.url("http://127.0.0.1:8080")
                    .build();

            try (Response response = client.newCall(request).execute()) {
                if (!response.isSuccessful()) throw new IOException("Unexpected code " + response);

                System.out.println(response.body().string());
            }
        } catch (Exception e) {
            System.err.println("Some exception occurred.1234567");
            e.printStackTrace();
        }

    }

    private static void injectQKD(InjectableEtsiKEM.SSLFactoryFactory sslf1) {
        InjectionPoint injectionPoint = InjectionPoint.theInstance();
        final InjectableAlgorithms initialAlgs = new InjectableAlgorithms();
        injectionPoint.push(initialAlgs);

        final CompletableFuture<InjectableAlgorithms> algsWithEtsi = new CompletableFuture<>();

        algsWithEtsi.complete( // = assign the value, which can be used using algsWithEtsi.get()
                initialAlgs
                        .withoutDefaultKEMs()
                        .withKEM("QKD-ETSI",
                                0xFEFE, // from the reserved-for-private-use range, i.e., 0xFE00..0xFEFF for KEMs
                                () -> new InjectableEtsiKEM(
                                        sslf1,
                                        "localhost:8010",
                                        "c565d5aa-8670-4446-8471-b0e53e315d2a",
                                        () -> {
                                            try {
                                                injectionPoint.pop(algsWithEtsi.get());
                                            } catch (Exception e) {
                                                e.printStackTrace();
                                                throw new RuntimeException(e);
                                            }
                                        },
                                        () -> {
                                            try {
                                                injectionPoint.pushAfter(algsWithEtsi.get(), initialAlgs);
                                            } catch (Exception e) {
                                                e.printStackTrace();
                                                throw new RuntimeException(e);
                                            }
                                        }
                                ),
                                InjectableKEMs.Ordering.BEFORE));
        try {
            injectionPoint.pushAfter(algsWithEtsi.get(), initialAlgs);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }


}
