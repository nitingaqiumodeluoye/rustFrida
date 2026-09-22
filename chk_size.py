import struct,sys
d=open(sys.argv[1],'rb').read()
ph=struct.unpack_from('<Q',d,0x20)[0]; es,en=struct.unpack_from('<HH',d,0x36)
for i in range(en):
    o=ph+i*es; t,f=struct.unpack_from('<II',d,o)
    if t==1 and f&1:
        off,va,pa,fsz,msz=struct.unpack_from('<QQQQQ',d,o+8)
        print('EXEC filesz=%d bytes; page slack=%d; %s'%(fsz,4096-fsz,'OK' if fsz<=4096 else 'OVER-4096-SPAWN-WILL-FAIL'))
