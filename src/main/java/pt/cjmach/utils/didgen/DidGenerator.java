package pt.cjmach.utils.didgen;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import id.walt.crypto.keys.jwk.JWKKey;
import id.walt.did.dids.DidService;
import id.walt.did.dids.registrar.DidResult;
import id.walt.did.dids.registrar.dids.DidCreateOptions;
import id.walt.did.dids.registrar.dids.DidJwkCreateOptions;
import id.walt.did.dids.registrar.dids.DidKeyCreateOptions;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.CompletableFuture;
import kotlin.Result;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.EmptyCoroutineContext;

/**
 *
 * @author cmachado
 */
public class DidGenerator {

    private static final CertificateFactory X509_FACTORY;

    static {
        try {
            X509_FACTORY = CertificateFactory.getInstance("X509");
        } catch (CertificateException ex) {
            throw new ExceptionInInitializerError(ex);
        }
        DidService.INSTANCE.minimalInitBlocking();
    }
    
    public JWK generateJWK(X509Certificate certificate) throws CertificateException {
        try {
            JWK jwk = JWK.parse(certificate);
            return jwk;
        } catch (JOSEException ex) {
            throw new CertificateException(ex);
        }
    }

    public JWK generateJWK(InputStream x509Input) throws CertificateException {
        X509Certificate certificate = (X509Certificate) X509_FACTORY.generateCertificate(x509Input);
        return generateJWK(certificate);
    }

    public String generateDID(JWK jwk, String method) {
        JWKKey key = new JWKKey(jwk);
        DidCreateOptions options;
        switch (method) {
            case "key":
                options = new DidKeyCreateOptions(key.getKeyType(), true);
                break;
                
            case "jwk":
                options = new DidJwkCreateOptions(key.getKeyType());
                break;
                
            default:
                throw new IllegalArgumentException("Unsupported DID method: " + method);
        }
        Continuation<DidResult> continuation = createContinuation();
        DidResult result = (DidResult) DidService.INSTANCE.registerByKey("key", key, options, continuation);
        if (result != null) {
            return result.getDid();
        }
        return null;
    }
    
    public String generateDID(InputStream x509Input, String method) throws CertificateException {
        JWK jwk = generateJWK(x509Input);
        return generateDID(jwk, method);
    }
    
    private static <T> Continuation<T> createContinuation() {
        Continuation<T> continuation = new Continuation<>() {
            private final CompletableFuture<T> future = new CompletableFuture<>();
            
            @Override
            public void resumeWith(Object o) {
                if (o instanceof Result.Failure failure) {
                    future.completeExceptionally(failure.exception);
                } else {
                    future.complete((T) o);
                }
            }

            @Override
            public CoroutineContext getContext() {
                return EmptyCoroutineContext.INSTANCE;
            }
        };
        return continuation;
    }
}
