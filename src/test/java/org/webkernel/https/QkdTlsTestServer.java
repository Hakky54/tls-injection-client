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

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.concurrent.CompletableFuture;

/**
 * A TLS server that uses QKD keys to secure TLS sessions.
 *
 * For testing purposes, you can use QKD KME simulator from here: https://github.com/next-door-key/py-qkd-kme-sim
 */
public class QkdTlsTestServer {

    private static final String MAIN_DIRECTORY = mainDirectory();

    // >>>>> Credentials and trust store to connect to our KME:
    private static final Token saeToken = new FileToken(
            new String[]{MAIN_DIRECTORY + File.separator + "sae-2.crt"},
            MAIN_DIRECTORY + File.separator + "sae-2.key",
            "");
    private static final TrustStore saeTrustStore = new TrustStore(new String[]{MAIN_DIRECTORY + File.separator + "ca.crt"});
    private static final String KME_HOST_AND_PORT = "127.0.0.1:9000";
    private static final String OTHER_SAE_ID = "foo-bar";
    // <<<<<

    // >>>>> Our server credentials + trust store to verify clients.
    //For PKCS12 (.pfx):
    //  private static final Token token = new FileToken(MAIN_DIRECTORY + File.separator + "server.pfx", "server-keystore-pass", "server");
    //For PEM cert+key:
    private static final Token token = new FileToken(
            new String[]{MAIN_DIRECTORY + File.separator + "server.crt"},
            MAIN_DIRECTORY + File.separator + "server.key",
            "");
    private static final TrustStore trustStore = new TrustStore(MAIN_DIRECTORY + File.separator + "ca.truststore", "ca-truststore-pass");
    // <<<<<

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

    public static void main(String[] args) {
        Common.loadNativeLibrary();


        injectQKD(() -> {

            try {
                return SSLFactory.builder()
                        .withIdentityMaterial(saeToken.key(), saeToken.password(), saeToken.certificateChain())
                        .withNeedClientAuthentication()
                        .withWantClientAuthentication()
                        .withProtocols("TLSv1.3", "TLSv1.2")
                        .withHostnameVerifier((hostname, session) -> {
                            // Trusting the KME host name
                            return true;
                        })
                        .withTrustMaterial(saeTrustStore.trustManagerFactory()) // or just saeTrustStore.asKeyStore()
                        .withSecureRandom(SecureRandom.getInstanceStrong())
                        //.withCiphers("TLS_AES_256_GCM_SHA384") // do not specify TLS_AES_256_GCM_SHA384 for TLSv1.2
                        .build();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        try {


            SSLFactory sslf2 = SSLFactory.builder()
                    .withIdentityMaterial(token.key(), token.password(), token.certificateChain())
                    .withNeedClientAuthentication()
                    .withWantClientAuthentication()
                    .withProtocols("TLSv1.3")
                    .withTrustMaterial(trustStore.trustManagerFactory()) // or just trustStore.asKeyStore()
                    .withSecureRandom(SecureRandom.getInstanceStrong())
                    .withCiphers("TLS_AES_256_GCM_SHA384")
                    .build();

            // Initialize SSLContext with the KeyManager
            SSLContext sslContext = sslf2.getSslContext();

            sslContext.init(sslf2.getKeyManagerFactory().get().getKeyManagers(), trustStore.trustManagerFactory().getTrustManagers(), SecureRandom.getInstanceStrong());

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
                KME_HOST_AND_PORT,
                OTHER_SAE_ID,
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
