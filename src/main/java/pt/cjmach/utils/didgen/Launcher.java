package pt.cjmach.utils.didgen;

import com.nimbusds.jose.jwk.JWK;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.concurrent.Callable;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 *
 * @author cmachado
 */
@Command(name = "didgen", description = "Generates a Decentralized ID (DID) from a X.509 certificate.")
public class Launcher implements Callable<Integer> {
    
    @Option(names = {"-i", "--input"}, paramLabel = "FILE", required = true,
            description = "Path to X.509 certificate file. The file must be DER-encoded and may be supplied in binary or printable encoding (PEM).")
    private File inputFile;
    
    @Option(names = {"-j", "--jwk"}, defaultValue = "false",
            description = "Also output JSON Web Key (JWK) to stderr.")
    private boolean printJwk;
    
    @Option(names = {"-v", "--version"}, versionHelp = true, description = "Print version and exit.")
    @SuppressWarnings("FieldMayBeFinal")
    private boolean versionRequested = false;
    /**
     * 
     */
    @Option(names = {"-h", "--help"}, usageHelp = true, description = "Print help and exit.")
    @SuppressWarnings("FieldMayBeFinal")
    private boolean helpRequested = false;
    
    @Override
    public Integer call() throws Exception {
        DidGenerator generator = new DidGenerator();
        try (FileInputStream input = new FileInputStream(inputFile)) {
            JWK jwk = generator.generateJWK(input);
            if (printJwk) {
                System.err.println(jwk.toJSONString());
            }
            String did = generator.generateDID(jwk);
            System.out.println(did);
            return 0;
        }
    }

    public static void main(String[] args) throws Exception {
        CommandLine cmdLine = new CommandLine(new Launcher());
        cmdLine.setCaseInsensitiveEnumValuesAllowed(true);
        int exitCode = cmdLine.execute(args);
        if (cmdLine.isVersionHelpRequested()) {
            String version = getVersion();
            System.out.println("[INFO] didgen " + version); // NOI18N
        }
        System.exit(exitCode);
    }
    
    /**
     * 
     * @return 
     */
    private static String getVersion() {
        try {
            Manifest manifest = new Manifest(Launcher.class.getResourceAsStream("/META-INF/MANIFEST.MF")); // NOI18N
            Attributes attributes = manifest.getMainAttributes();
            String version = attributes.getValue("Implementation-Version"); // NOI18N
            return version;
        } catch (IOException ex) {
            System.err.println("[ERROR] Could not read MANIFEST.MF file.");
            System.err.println(ex);
            return "";
        }
    }
}
