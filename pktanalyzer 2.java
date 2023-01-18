import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Scanner;

/**
 * pktanalyzer.java
 *
 * Version :    1.1
 *
 * Usage : java pktanalyzer datafile
 **/

public class pktanalyzer {
    public static void main(String[] args) throws IOException {
        String file = parseArgs(args);
        byte[] byteData =  Files.readAllBytes(Paths.get(file));
        int n = byteData.length;
        byte[] ipHeadByte = new byte[n - 14];
        byte[] ether = new byte[14];
        System.arraycopy(byteData, 0, ether, 0, 14);
        System.out.println("-------- Ether Header --------");
        System.out.println("Packet size = " + n + " " + "bytes");
        ethernet_head(ether);
        System.arraycopy(byteData, 14, ipHeadByte, 0, n - 14);
        ip_head(ipHeadByte);
    }

    static String parseArgs(String[] args) {
        String pathname = "";
        if(args.length == 1)pathname = args[0];
        else if(args.length == 0){
        	System.out.println("Enter Filepath of packet = ");
            Scanner sc = new Scanner(System.in);
            pathname = sc.nextLine();
            sc.close();}
        else{
            System.out.println("Enter in correct format: java pktanalyzer filename");
            System.exit(1);}
        return pathname;
        }

     public static void ethernet_head(byte[] bytedata) {
         System.out.print("Destination = ");
         for (int i = 0; i <= 5; i++) {
             String s = String.format("%02X", bytedata[i]).toLowerCase();
             if (i != 5) {
            	 System.out.print(s + ":");
             } else {
            	 System.out.print(s + ",");
             }
         }
         System.out.print("\nSource = ");
         for (int i = 6; i <= 11; i++) {
             String s = String.format("%02X", bytedata[i]).toLowerCase();
             if (i != 11) {
            	 System.out.print(s + ":");
             } else {
            	 System.out.print(s + ",");
             }
         }

         System.out.print("\nEthertype = ");
         for (int i = 12; i <= 13; i++) {
        	 String s = String.format("%02X", bytedata[i]);
        	 if(i != 13) {
                 System.out.print(s);
             }
             else {
                 System.out.print(s + " (IP)"\n);
             }
         }
         System.out.print("\n");
     }

     public static void ip_head(byte[] bytedata){
         byte[] headerdata = new byte[argument2.length];
         int[] ipdata = new int[bytedata.length];
         for(int i=0; i<bytedata.length; i++) {
             ipdata[i] = bytedata[i]&0xff;
         }
         System.out.println("-------- IP Header --------");
         System.out.println("Version = " + (ipdata[0]>>4));
         System.out.println("Header Length = " + (((ipdata[0]&(1<<4)-1)*32)/8) + " bytes");
         System.out.println("Types of Service = 0x" + (String.format("%02X", ipdata[1])));
         System.out.println("    xxx. .... = 0 (precedence)");
         (ipdata[1]>>4&(1<<1)-1) == 0 ? System.out.println("    ...0 .... = Normal Delay") : System.out.println("    ...1 .... = Low Delay");
         (ipdata[1]>>3&(1<<1)-1) == 0 ? System.out.println("    .... 0... = Normal Throughput") : System.out.println("    .... 1... = High Throughput");
         (ipdata[1]>>2&(1<<1)-1) == 0 ? System.out.println("    .... .0.. = Normal Reliability") : System.out.println("    .... .1.. = High Reliability");     
         System.out.println("Total length = " + (ipdata[2]<<8|ipdata[3]) + " bytes");
         System.out.println("Identification = " + (ipdata[4]<<8|ipdata[5]));
         System.out.println("Flags = 0x" + (String.format("%02X", ipdata[6]>>5)));
         (ipdata[6]>>6&(1<<1)-1) == 0 ? System.out.println("    .0.. .... = do fragment") : System.out.println("    .1.. .... = do not fragment");
         (ipdata[6]>>5&(1<<1)-1) == 0 ? System.out.println("    ..0. .... = last fragment") : System.out.println("    ..1. .... = more fragments");
         System.out.println("Fragment offset = " + (((ipdata[6]&31)<<8)|ipdata[7]) + " bytes");
         System.out.println("Time to live = " + ipdata[8] + " seconds/hops");
         if(bytedata[9] == 1) System.out.println("Protocol = " + ipdata[9] + " (ICMP)");
         else if (bytedata[9] == 6) System.out.println("Protocol = " + ipdata[9] + " (TCP)");
         else if (bytedata[9] == 17) System.out.println("Protocol = " + ipdata[9] + " (UDP)");
         else System.out.println("Protocol = " + ipdata[9] + " (ARP)");
         System.out.println("Header checksum = 0x" + (String.format("%02X", (ipdata[10]<<8)| ipdata[11])).toLowerCase());
         System.out.println("Source IP address = " + ipdata[12] + "." + ipdata[13] + "." + ipdata[14] + "." +
                 ipdata[15]);
         System.out.println("Destination IP address = " + ipdata[16] + "." + ipdata[17] + "." + ipdata[18] + "."
                 + ipdata[19]);
         if ((ipdata[0]&(1<<4)-1) > 5){
             int size = ((ipdata[0]&(1<<4)-1)*32)/8;
             System.arraycopy(bytedata, 20 + size - 20, headerdata, 0, bytedata.length - size);
             System.out.println("Options = " + (size - 20) + " bytes");
         } else {
             System.arraycopy(bytedata, 20, headerdata, 0, bytedata.length - 20);
             System.out.println("No options");
         }
         if (bytedata[9] == 1){
        	 icmp_head(headerdata);
         }
         else if (bytedata[9] == 6){
             tcp_head(headerdata);
         }
         else if (bytedata[9] == 17){
             udp_head(headerdata);
         }
         else{
             arp_head(bytedata);
         }
    }

    public static void udp_head(byte[] headerdata){
        int n = 0;
        int[] bytedata = new int[headerdata.length];
        int len1 = bytedata.length;
        for(int i=0; i<headerdata.length; i++) {
            bytedata[i] = headerdata[i]&0xff;
        }
        System.out.println("-------- UDP Header --------");
        System.out.println("Source port = " + ((bytedata[0]<<8)|bytedata[1]));
        System.out.println("Destination port = " + ((bytedata[2]<<8)|bytedata[3]));
        System.out.println("Length = " + (bytedata[5]|(bytedata[4]<<8)));
        System.out.println("Checksum = 0x" + (String.format("%02X", (bytedata[6]<<8)|bytedata[7])).toLowerCase());
        byte[] printdata = new byte[len1 - 8];
        int len2 = printdata.length;
        System.arraycopy(headerdata, 8, printdata, 0, len2);
        System.out.println("Data = (first 64 bytes)\n ");
        for (int i = 8; i<len1; i++) {
        	if(n % 8 != 0) {
        		n++;
                System.out.print(String.format("%02X", (bytedata[i])).toLowerCase() + " ");
        	}
        	else {
        		System.out.print("\n");
        	}
        }
        System.out.println("\n");
    }

    public static void tcp_head(byte[] bytedata){
        int n = 0;
        byte[] headerdata = new byte[bytedata.length];
        long[] databytes = new long[bytedata.length];
        for(int i=0; i<bytedata.length; i++) {
            databytes[i] = bytedata[i]&0xff;
        }
        System.out.println("----- TCP Header -----");
        System.out.println("Source port = " + ((databytes[0]<<8)|databytes[1]));
        System.out.println("Destination port = " + ((databytes[2]<<8)|databytes[3]));
        System.out.println("Sequence Number = " + ((databytes[4]<<24)|(databytes[5]<<16)| (databytes[6]<<8)|databytes[7]));
        System.out.println("Acknowledgement Number = " + (((databytes[8]<<24)| (databytes[9]<<16)|(databytes[10]<<8)|
                databytes[11])));
        System.out.println("Data Offset = " + (databytes[12]>>4&(1<<4)-1) + " 32 bytes");
        System.out.println("Flags = 0x" + (String.format("%02X", ((databytes[13]&((1<<6)-1))))));
        (databytes[13]>>5&(1<<1)-1) == 0 ? System.out.println("    ..0. .... = No Urgent Pointer") : System.out.println("    ..1. .... = Urgent Pointer");
        (databytes[13]>>4&(1<<1)-1) == 0 ? System.out.println("    ...0 .... = No Acknowledgement") : System.out.println("    ...1 .... = Acknowledgement");
        (databytes[13]>>3&(1<<1)-1) == 0 ? System.out.println("    .... 0... = No Push Request") : System.out.println("    .... 1... = Push Request");
        (databytes[13]>>2&(1<<1)-1) == 0 ? System.out.println("    .... .0.. = No Reset") : System.out.println("    .... .1.. = Reset");
        (databytes[13]>>1&(1<<1)-1) == 0 ? System.out.println("    .... ..0. = No Syn") : System.out.println("    .... ..1. = Syn");
        
        (databytes[13]&(1<<1)-1) == 0 ? System.out.println("    .... ...0 = No Fin") : System.out.println("    .... ...1 = Fin");
        System.out.println("Window = " + ((databytes[14]<<8)|databytes[15]));
        System.out.println("TCP Checksum = 0x" + (String.format("%02X", (databytes[16]<<8)|
                (databytes[17]))).toLowerCase());
        System.out.println("Urgent Pointer = " + ((databytes[18]<<8)|databytes[19]));
        if (databytes[12]>>4 >5) {
            int lengthdata = (int) ((databytes[12]>>4)*32)/8;
            System.arraycopy(bytedata, lengthdata - 20, headerdata, 0, databytes.length - lengthdata);
            System.out.println("TCP Header has Options of length " + (lengthdata - 20) + " bytes");
        } else {
            System.arraycopy(bytedata, 20, headerdata, 0, databytes.length - 20);
            System.out.println("TCP Header has No options");
        }
        System.out.println("TCP Payload/Data:\n ");
        System.out.println("Hexadecimal Values = ");
        for (int i = 0; i<databytes.length; i++) {
            n++;
            System.out.print(String.format("%02X", (headerdata[i])) + " ");
            if (n%8 == 0){
                System.out.print("\n");
            }
        }
        System.out.println("\n");
    }

    public static void icmp_head(byte[] bytedata){
        long[] icmpheader = new long[bytedata.length];
        for(int i=0; i<bytedata.length; i++) {
            icmpheader[i] = bytedata[i]& 0xff;
        }
        System.out.println("-------- ICMP Header --------");
        System.out.println("Message Type = " + (icmpheader[0]));
        System.out.println("Code = " + (icmpheader[1]));
        System.out.println("ICMP Checksum = 0x" + (String.format("%02x", (icmpheader[2]<<8)|(icmpheader[3]))));
    }

    public static void arp_head(byte[] bytedata){
        long[] arpheader = new long[bytedata.length];
        for(int i=0; i<bytedata.length; i++) {
            arpheader[i] = bytedata[i]& 0xff;
        }
        System.out.println("-------- ARP Header --------");
        System.out.println("From Opcode");
        if (((arpheader[6]<<8)|arpheader[7]) != 1) {
            System.out.println("ARP Response");
        }
        else{
            System.out.println("ARP Request");
        }
        System.out.println("Hardware Type = " + ((arpheader[0]<<8)|arpheader[1]));
        System.out.print("Protocol Type = 0x" + (String.format("%02x", (arpheader[2]<<8)|arpheader[3])));
        if (((arpheader[2]<<8)|arpheader[3]) == 2048){
            System.out.println(" (IPv4)");
        }
        System.out.println("Hardware Address Length = " + (arpheader[4]));
        System.out.println("Protocol Address Length = " + (arpheader[5]));
        System.out.print("Operation Request Code = " + ((arpheader[6]<<8)|arpheader[7]));
        if (((arpheader[6]<<8)|arpheader[7]) != 1) {
            System.out.println(" (ARP Response)");
        }
        else{
            System.out.println(" (ARP Request)");
        }
        System.out.print("Source Hardware Address = ");
        for (int i = 8; i < 14; i++) {
            String s = String.format("%02X", arpheader[i]);
            if (i == 13) {
                System.out.println(s);
            } else {
                System.out.print(s + ":");
            }
        }
        System.out.print("Source Protocol Address = ");
        String sourceaddr = "";
        for (int i = 14; i < 18; ++i)
        {
            long t = 0xFF & arpheader[i];
            sourceaddr += "." + t;
        }
        sourceaddr = sourceaddr.substring(1);
        System.out.println(sourceaddr);
        System.out.print("Target Hardware Address = ");
        for (int i = 18; i < 24; i++) {
            String st = String.format("%02X", arpheader[i]);
            if (i == 23) {
                System.out.println(st);
            } else {
                System.out.print(st + ":");
            }
        }
        System.out.print("Target Protocol Address = ");
        StringBuilder targetaddr = new StringBuilder();
        for (int i = 24; i <= 27; ++i)
        {
            long t = 0xFF & arpheader[i];
            targetaddr.append(".").append(t);
        }
        targetaddr = new StringBuilder(targetaddr.substring(1));
        System.out.println(targetaddr);
    }
}
