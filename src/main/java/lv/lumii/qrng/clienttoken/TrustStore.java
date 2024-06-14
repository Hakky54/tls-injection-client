package lv.lumii.qrng.clienttoken;

import org.cactoos.scalar.Unchecked;

import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class TrustStore {

    private final Unchecked<KeyStore> trustStore;
    public TrustStore(String pfxFileName, String password) {
        this.trustStore = new Unchecked<>(()->loadTrustStore(pfxFileName, password));
    }

    public TrustStore(String[] pemCertFileNames) {
        this.trustStore = new Unchecked<>(()->createTrustStore(pemCertFileNames));
    }

    private KeyStore loadTrustStore(String pfxFileName, String password) throws Exception {
        KeyStore trustStore = KeyStore.getInstance(new File(pfxFileName), password.toCharArray());
        return trustStore;
    }

    private KeyStore createTrustStore(String[] pemCertFileNames) throws Exception {

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);

        // Load the certificates from PEM file into the trustStore...
        for (String certFileName : pemCertFileNames) {

            FileInputStream certReader = new FileInputStream(certFileName);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certReader);
            certReader.close();
            trustStore.setCertificateEntry(certFileName, certificate);
        }

        return trustStore;
    }

    public TrustManagerFactory trustManagerFactory() {
        // Create a TrustManagerFactory using the KeyStore
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            //tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(this.trustStore.value());
            return tmf;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
