package org.webkernel.https;

import lv.lumii.qkd.InjectableEtsiKEM;
import lv.lumii.tls.auth.FileToken;
import lv.lumii.tls.auth.Token;
import lv.lumii.tls.auth.TrustStore;
import nl.altindag.ssl.SSLFactory;
import org.bouncycastle.tls.injection.InjectableAlgorithms;
import org.bouncycastle.tls.injection.InjectableKEMs;
import org.bouncycastle.tls.injection.InjectionPoint;
import org.bouncycastle.tls.injection.kems.KemFactory;
import org.openquantumsafe.Common;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.concurrent.CompletableFuture;


public class QkdTlsTestClient {

    private static final String MAIN_DIRECTORY = mainDirectory();

    private static String mainDirectory() {
        File f = new File(QkdTlsTestClient.class.getProtectionDomain().getCodeSource().getLocation().getPath());
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


        injectQKD(() -> {
            /*Token saeToken = new FileToken(
                    new String[] {MAIN_DIRECTORY + File.separator + "sae-1.crt.pem"},
                    MAIN_DIRECTORY + File.separator + "sae-1.key.pem",
                    "");*/
            Token saeToken = new FileToken(
                    new String[]{MAIN_DIRECTORY + File.separator + "sae-1.crt.pem"},
                    MAIN_DIRECTORY + File.separator + "encrypted-sae-1.key.pem",
                    "abc");
            TrustManagerFactory trustMgrFact = new TrustStore(new String[]{MAIN_DIRECTORY + File.separator + "ca.crt.pem"}).trustManagerFactory();

            try {
                SSLFactory sslf1 = SSLFactory.builder()
                        .withIdentityMaterial(saeToken.key(), saeToken.password(), saeToken.certificateChain())
                        .withNeedClientAuthentication()
                        .withWantClientAuthentication()
                        .withProtocols("TLSv1.3")
                        .withHostnameVerifier((hostname, session) -> {
                            // Trusting the KME host name
                            return true;
                        })
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
            //For PKCS12 (.pfx):
            Token token = new FileToken(MAIN_DIRECTORY + File.separator + "client.pfx", "client-keystore-pass", "client");

            //For PEM cert+key:
            /*Token token = new FileToken(
                    new String[] {MAIN_DIRECTORY + File.separator + "client.crt.pem"},
                    MAIN_DIRECTORY + File.separator + "client.key.pem",
                    "abc");*/
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

            try (SSLSocket sslSocket = (SSLSocket) sslf2.getSslSocketFactory().createSocket("127.0.0.1", 8443);
                 BufferedReader reader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
                 PrintWriter writer = new PrintWriter(sslSocket.getOutputStream(), true)) {

                // Send message to the server
                writer.println("Hello, server!");

                // Read server response
                String response = reader.readLine();
                System.out.println("Server response: " + response);
            }

        } catch (Exception e) {
            System.err.println("Some exception occurred.");
            e.printStackTrace();
        }

    }

    private static void injectQKD(InjectableEtsiKEM.SSLFactoryFactory sslf1) {
        InjectionPoint injectionPoint = InjectionPoint.theInstance();
        final InjectableAlgorithms initialAlgs = new InjectableAlgorithms();
        injectionPoint.push(initialAlgs);

        final CompletableFuture<InjectableAlgorithms> algsWithEtsi = new CompletableFuture<>();

        KemFactory qkdKemFactory = () -> new InjectableEtsiKEM(
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
        );

        algsWithEtsi.complete( // = assign the value, which can be used using algsWithEtsi.get()
                initialAlgs
                        .withoutDefaultKEMs()
                        .withKEM("QKD-ETSI",
                                0xFEFE, // from the reserved-for-private-use range, i.e., 0xFE00..0xFEFF for KEMs
                                qkdKemFactory,
                                InjectableKEMs.Ordering.BEFORE));
        try {
            injectionPoint.pushAfter(algsWithEtsi.get(), initialAlgs);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }


}
