package nl.rb9.cve;
import java.net.http.*;
import java.net.URI;

/**
 * "Vulnerable" client to showcase CVE-2022-21449
 */
public class App 
{
	private static void testConnectionToServer(String url) {
        	// Code modified from
        	// https://stackoverflow.com/a/66236352
        	HttpClient client = HttpClient.newHttpClient();
        	try {
        	        System.out.println("[!] Attempting to talk to " + url);
        	        HttpRequest request = HttpRequest.newBuilder()
        	              .uri(URI.create(url))
        	              .build();

        	        System.out.println("[!] Response:");
        	        client.sendAsync(request, HttpResponse.BodyHandlers.ofString())
        	              .thenApply(HttpResponse::body)
        	              .thenAccept(body -> System.out.println(body.substring(0, body.length() > 256 ? 256 : body.length())))
        	              .get();

        	        System.out.println("[+] " + url + " test succeeded");
        	}
        	catch (Exception e) {
        	        System.out.println("[-] " + url + " test failed");
        	        System.out.println(e);
        	}

    	}

    	public static void main(String[] args) throws Exception {
    	    testConnectionToServer("https://untrusted-root.badssl.com");
    	    testConnectionToServer("https://www.google.com/hello");
    	}
}
