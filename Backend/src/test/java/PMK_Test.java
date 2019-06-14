import org.junit.Test;
import uk.elliotalexander.Connection;
import org.pcap4j.packet.Packet;

import junit.framework.TestCase;

import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsQuestion;
import com.google.common.io.BaseEncoding;

public class PMK_Test extends TestCase {

	@Test
	public void testGenerateTKSuccessfully(){
		/*
         * EAPOL HANDSHAKE AT 9545
         */
        final byte[] AA = BaseEncoding.base16().decode("e4956e4400e6".toUpperCase());
        final byte[] SPA = BaseEncoding.base16().decode("448500dc39ee".toUpperCase());
        final byte[] EAPOL1 = BaseEncoding.base16().decode("88023a01448500dc39eee4956e4400e6e4956e4400e600000700aaaa03000000888e0203005f02008a00100000000000000001cbc4f0a9f9879a00ef6317c7d67300c20db915717c8180991d2a99a054679dee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b4261a22".toUpperCase());
        final byte[] EAPOL2 = BaseEncoding.base16().decode("88013a01e4956e4400e6448500dc39eee4956e4400e600000700aaaa03000000888e0103007502010a00000000000000000001bd2735ca00654390ef452863d853d2d2760c36c85997af77c05ca33a272ec55c00000000000000000000000000000000000000000000000000000000000000005ef597651ffbab7c38d302f3aa9abefe001630140100000fac040100000fac040100000fac020000c03578e7".toUpperCase());
        final byte[] PMK = BaseEncoding.base16().decode("8c36c8f2e805fea9e153ff1ed457b3c1cf87f428de5432566b77e7e91a8ab5aa".toUpperCase());


        byte[] packet_id_1 = {EAPOL1[39], EAPOL1[40]};
        byte[] packet_id_2 = {EAPOL2[39], EAPOL2[40]};

		Connection connection = new Connection(SPA, AA, PMK);
		try {
			connection.addEapolMessage(EAPOL1, packet_id_1);
			connection.addEapolMessage(EAPOL2, packet_id_2);
			connection.generateTk();
		} catch (Exception e){
			fail("Failed to genertate EAPOL Handshake.");
		}
	}
}

