# Author:     Josh Stroschein
# Date:       15 December 2020
# Resources:  
#   YouTube:  https://youtu.be/un8I6dfuDVQ
#   Sample:   https://github.com/jstrosch/malware-samples/tree/master/maldocs/unknown/2020/December

def get_string(addr, size):
  out = ""
  for offset in range(addr, (addr + size)):
      out += chr(Byte(offset))
  return out
 
def decrypt(key,cipher,size):
  decrypted_string = ""
  cnt = 0
  for cnt in range(0,size):
    decrypted_string = decrypted_string + chr(ord(cipher[cnt]) ^ ord(key[cnt  % len(key)]))
  return str(decrypted_string)
 
print "[*] Attempting to decrypt strings in malware... "
for x in XrefsTo(0x10001210, flags=0):
  addr = idc.PrevHead(x.frm)
  obfuscated_string = GetOperandValue(addr, 0)

  addr = idc.PrevHead(addr)
  key = GetOperandValue(addr,0)

  addr = idc.PrevHead(addr)
  size = GetOperandValue(addr,0)

  print "Addr: 0x%x  | Key: 0x%x | Cipher: 0x%x | Size: %d" %  (x.frm,key, obfuscated_string, size)

  decrypted_string = decrypt(get_string(obfuscated_string, size), get_string(key, size),size)
  print "Decrypted: %s" % (decrypted_string)

  MakeComm(idc.NextHead(idc.NextHead(x.frm)), "[*] " + decrypted_string)