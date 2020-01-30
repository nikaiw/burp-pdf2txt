package burp;

import com.pdf2txt.ProxyListener;

import java.io.PrintWriter;
import java.util.concurrent.ConcurrentHashMap;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private static final String name = "Burp-pdf2txt";
    private static final String version = "1.00";
    PrintWriter stdout;
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        callbacks.setExtensionName(name);
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.write("Loaded " + name + " v" + version);
        callbacks.registerHttpListener(new ProxyListener(callbacks));
        //callbacks.registerProxyListener(new ProxyListener(callbacks));
    }

    @Override
    public void extensionUnloaded() {

    }
}