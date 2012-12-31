<br><br>
<p><b>Web Attack Email Options through SET Config is turned to ON</b><p>
<input type="checkbox" name="webattack_email" value="1"> E-Mail Attack Single Email Address<br>				
<input type="checkbox" name="webattack_email" value="2"> E-Mail Attack Mass Mailer<br>
<br>
If your using mass emailer, browser to file with email addresses: <input type="file" name="massmailer_file" size="5">
<br>
<br>
Enter who you want to send the email to: <input type="text" name="emailto" /><br />
<br><br>
<input type="checkbox" name="webattack_account" value="1"> Use a GMAIL account for your email attack<br>
<input type="checkbox" name="webattack_account" value="2"> Use your own open-relay SMTP Server<br>
<br><br>
<p><b>THIS OPTION FOR OPEN-RELAY ONLY</b></p>
<br>
Enter your email address you want to come from: <input type="text" name="emailfrom_relay" /><br />
Enter your username for open relay (leave blank if there is none): <input type="text" name="username_relay" /><br />
Enter your password for open relay (leave blank if there is none): <input type="password" name="password_relay" /><br />
Enter the SMTP Server address for the open relay: <input type="text" name="smtp_relay" /><br/>
Enter the port number for the SMTP server: <input type="text" name="smtp_port_relay" value="25" size="3" /><br/>
<br><br>
<p><b>THIS OPTION FOR GMAIL ATTACK ONLY!</b></p><br>
Enter your email address: <input type="text" name="emailfrom" /><br />
Enter your password for the email address: <input type="password" name="password" /><br />
<br><br>
<p><b>Required fields below</b></p>
Enter the subject for the email: <input type="text" name="subject" /><br />
<br><br>
<input type="checkbox" name="webattack_message" value="1"> Use HTML for the email attack<br>
<input type="checkbox" name="webattack_message" value="2"> Use Plain text for the email attack<br>
<br><br>
Enter your email message here<br><TEXTAREA NAME="comments" COLS=40 ROWS=6></TEXTAREA>
<br>
