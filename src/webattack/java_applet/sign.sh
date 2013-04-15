cp ../../html/unsigned/unsigned.jar Java_Exploit.jar
jarsigner -verbose Java_Exploit.jar MyCert
cp Java_Exploit.jar Signed_Update.jar.orig
cp Java_Exploit.jar ../../html/Signed_Update.jar.orig
