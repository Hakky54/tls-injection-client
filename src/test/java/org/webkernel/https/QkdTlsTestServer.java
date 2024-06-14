package org.webkernel.https;


import lv.lumii.qkd.InjectableEtsiKEM;
import lv.lumii.qrng.clienttoken.FileToken;
import lv.lumii.qrng.clienttoken.Token;
import nl.altindag.ssl.SSLFactory;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.bouncycastle.tls.injection.InjectableAlgorithms;
import org.bouncycastle.tls.injection.InjectableKEMs;
import org.bouncycastle.tls.injection.InjectionPoint;
import org.openquantumsafe.Common;

import javax.net.ssl.*;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import java.io.*;
import java.net.Socket;
import java.security.KeyStore;

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
        Token token = new FileToken(MAIN_DIRECTORY + File.separator + "server.pfx", "server-keystore-pass", "server");

        CompletableFuture<SSLFactory> sslFactory = new CompletableFuture<>();
        injectQKD(() -> {
            try {
                return sslFactory.get();
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });

        try {
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
            sslFactory.complete(sslf2);


            // Initialize SSLContext with the KeyManager
            SSLContext sslContext = sslf2.getSslContext();

            sslContext.init(sslf2.getKeyManagerFactory().get().getKeyManagers(), trustMgrFact.getTrustManagers(), null);

            // Create SSLServerSocketFactory
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

            // Create SSLServerSocket
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(PORT);
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

    private static void injectQKD(InjectableEtsiKEM.SSLFactoryFactory sslf2) {
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
                                        sslf2,
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
