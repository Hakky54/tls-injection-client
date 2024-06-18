package lv.lumii.tls.auth;

public interface SignFunction {
    byte[] sign(byte[] message);
}
