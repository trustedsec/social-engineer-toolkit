cp ../../html/unsigned/unsigned.jar Java_Exploit.jar
jar ufm Java_Exploit.jar manifest.mf
#jarsigner -storetype pkcs12 -keystore /root/certs/MyCert.pfx Java_Exploit.jar "1"
jarsigner -storetype pkcs12 -keystore /root/certs/goat.p12 Java_Exploit.jar "1"
cp Java_Exploit.jar Signed_Update.jar.orig
cp Java_Exploit.jar ../../html/Signed_Update.jar.orig
