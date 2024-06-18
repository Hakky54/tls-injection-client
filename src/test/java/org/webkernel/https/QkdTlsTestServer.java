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

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.concurrent.CompletableFuture;

public class QkdTlsTestServer {

    private static final String MAIN_DIRECTORY = mainDirectory();

    private static String mainDirectory() {
        File f = new File(QkdTlsTestServer.class.getProtectionDomain().getCodeSource().getLocation().getPath());
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

    private static final int PORT = 8443;
    private static final String KEYSTORE_PATH = "mykeystore.jks";
    private static final String KEYSTORE_PASSWORD = "password"; // Change to your keystore password

    public static void main(String[] args) {
        Common.loadNativeLibrary();


        injectQKD(() -> {
            Token saeToken = new FileToken(
                    new String[]{MAIN_DIRECTORY + File.separator + "sae-2.crt.pem"},
                    MAIN_DIRECTORY + File.separator + "sae-2.key.pem",
                    "");
            TrustManagerFactory trustMgrFact = new TrustStore(new String[]{MAIN_DIRECTORY + File.separator + "ca.crt.pem"}).trustManagerFactory();

            try {
                return SSLFactory.builder()
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
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        try {
            //For PKCS12 (.pfx):
            //Token token = new FileToken(MAIN_DIRECTORY + File.separator + "server.pfx", "server-keystore-pass", "server");

            //For PEM cert+key:
            Token token = new FileToken(
                    new String[]{MAIN_DIRECTORY + File.separator + "server.crt"},
                    MAIN_DIRECTORY + File.separator + "server.key",
                    "");

            KeyStore trustStore = KeyStore.getInstance(new File(MAIN_DIRECTORY + File.separator + "ca.truststore"), "ca-truststore-pass".toCharArray());

            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("SunX509");
            trustMgrFact.init(trustStore);

            SSLFactory sslf2 = SSLFactory.builder()
                    .withIdentityMaterial(token.key(), token.password(), token.certificateChain())
                    .withNeedClientAuthentication()
                    .withWantClientAuthentication()
                    .withProtocols("TLSv1.3")
                    .withTrustMaterial(trustMgrFact) // or just trustStore
                    .withSecureRandom(SecureRandom.getInstanceStrong())
                    .withCiphers("TLS_AES_256_GCM_SHA384")
                    .build();

            // Initialize SSLContext with the KeyManager
            SSLContext sslContext = sslf2.getSslContext();

            TrustManager[] trustManagers = trustMgrFact.getTrustManagers();
            sslContext.init(sslf2.getKeyManagerFactory().get().getKeyManagers(), trustManagers, null);

            // Create SSLServerSocketFactory
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

            // Create SSLServerSocket
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(PORT);
            sslServerSocket.setNeedClientAuth(true); // <<<<< this is very important line; otherwise, all clients are let in!
            sslServerSocket.setEnabledCipherSuites(sslServerSocket.getSupportedCipherSuites());

            System.out.println("TLS server started on port " + PORT);

            while (true) {
                // Accept client connections
                try {
                    Socket socket = sslServerSocket.accept();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

                    // Read client message
                    String message = reader.readLine();
                    System.out.println("Received: " + message);

                    // Send response to client
                    writer.println("Hello, client! Your message was: " + message);

                } catch (Exception clientEx) {
                    clientEx.printStackTrace();
                }
            }

        } catch (Exception e) {
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
                "localhost:8020",
                "25840139-0dd4-49ae-ba1e-b86731601803",
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

        try {
            InjectableEtsiKEM kem = (InjectableEtsiKEM) qkdKemFactory.create();
            kem.touchKME();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }


    }


}
