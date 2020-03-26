package com.github.smallru8.driver.tuntap;

/* 
 * #根據WireShark撈到的封包格式#
 * FramePacket 格式
 * packet[0]~packet[5] : Dest MAC addr
 * packet[6]~packet[11] : src MAC addr
 * packet[12]~packet[13] : ipv
 * packet[14]開始為IP header
 * */

public class Analysis {

	private byte[] packet;
	
	public Analysis() {
		
	}
	/*init===========================================================================*/
	public byte packetType() {//ARP 0x06, IPv4 0x00, IPv6 0xDD 
		if(packet[12]==0x08&&packet[13]==0x06)//ARP
			return (byte) 0x06;
		else if(packet[12]==0x86&&packet[13]==0xDD)
			return (byte) 0xDD;
		return (byte) 0x00;
	}
	
	public boolean compareChecksum() {//比對checksum
		if(packet[12]==0x08&&packet[13]==0x06) {//this packet is ARP
			return false;
		}
		int headerLen = getPacketHeaderLen();
		int sum = 0;
		sum+= ((packet[14]&0xFF)<<8|(packet[15]&0xFF))+((packet[16]&0xFF)<<8|(packet[17]&0xFF));
		sum+= ((packet[18]&0xFF)<<8|(packet[19]&0xFF))+((packet[20]&0xFF)<<8|(packet[21]&0xFF));
		sum+= ((packet[22]&0xFF)<<8|(packet[23]&0xFF));
		sum+= ((packet[26]&0xFF)<<8|(packet[27]&0xFF))+((packet[28]&0xFF)<<8|(packet[29]&0xFF));
		sum+= ((packet[30]&0xFF)<<8|(packet[31]&0xFF))+((packet[32]&0xFF)<<8|(packet[33]&0xFF));
		if(headerLen==24)
			sum+= ((packet[34]&0xFF)<<8|(packet[35]&0xFF))+((packet[36]&0xFF)<<8|(packet[37]&0xFF));
		sum = ((sum&0x00FF0000)>>16)+(sum&0x0000FFFF);
		if(~sum == getChecksum())
			return true;
		return false;
	}
	
	public void setFramePacket(byte[] data) {
		packet = data;
	}
	
	public byte[] getFramePacket() {
		return packet;
	}
	/*Packet===========================================================================*/
	public byte getIPVersion() {
		byte ipv = 4;
		ipv = (byte) (packet[14]>>4);
		return ipv;
	}
	
	public byte getPacketHeaderLen() {
		byte headLen = 0;
		headLen = (byte) (packet[14]&0b00001111);
		return headLen;
	}
	
	public void setPacketHeaderLen(byte headerLen) {//
		packet[14] = (byte) ((packet[14]&0xFF)&0b11110000|((headerLen&0xFF)&0b00001111));
	}
	
	public byte getServiceType() {
		return packet[15];
	}
	
	public void setServiceType(byte serviceType) {//
		packet[15] = serviceType;
	}
	
	public short getPacketTotalLen() {
		return (short) (((packet[16]&0xFF)<<8)|(packet[17]&0xFF));
	}
	
	public void setPacketTotalLen(short packetTotalLen) {//
		packet[16] = (byte) (packetTotalLen>>8);
		packet[17] = (byte) (packetTotalLen&0x00FF);
	}
	
	public short getIdentification() {
		return (short) ((packet[18]&0xFF)<<8|(packet[19]&0xFF));
	}
	
	public void setIdentification(short identification) {//
		packet[18] = (byte) (identification>>8);
		packet[19] = (byte) (identification&0x00FF);
	}
	
	public byte getFlags() {
		return (byte) (packet[20]>>5);
	}
	
	public void setFlags(byte flags) {//0b00000xxx
		packet[20] = (byte) ((packet[20]&0xFF)&0b00011111|(flags<<5));
	}
	
	public short getFragmentOffset() {
		return (short) ((((packet[20]&0xFF)&0b00011111)<<8)|(packet[21]&0xFF));
	}
	
	public void setFragmentOffset(short fragmentOffset) {//0b000xxxxx xxxxxxxx
		packet[20] = (byte) ((packet[20]&0xFF)&0b11100000|(fragmentOffset>>8));
		packet[21] = (byte) (fragmentOffset&0x00FF);
	}
	
	public byte getTimeToLive() {
		return packet[22];
	}
	
	public void setTimeToLive(byte timeToLive) {//
		packet[22] = timeToLive;
	}
	
	public byte getProrocol() {
		return packet[23];
	}
	
	public void setProrocol(byte protocol) {//
		packet[23] = protocol;
	}
	
	public short getChecksum() {
		return (short) ((packet[24]&0xFF)<<8|(packet[25]&0xFF));
	}
	
	public void setChecksum() {//計算checksum並填入
		if(packet[12]==0x08&&packet[13]==0x00) {//IP packet
			int headerLen = getPacketHeaderLen();
			int sum = 0;
			sum+= ((packet[14]&0xFF)<<8|(packet[15]&0xFF))+((packet[16]&0xFF)<<8|(packet[17]&0xFF));
			sum+= ((packet[18]&0xFF)<<8|(packet[19]&0xFF))+((packet[20]&0xFF)<<8|(packet[21]&0xFF));
			sum+= ((packet[22]&0xFF)<<8|(packet[23]&0xFF));
			sum+= ((packet[26]&0xFF)<<8|(packet[27]&0xFF))+((packet[28]&0xFF)<<8|(packet[29]&0xFF));
			sum+= ((packet[30]&0xFF)<<8|(packet[31]&0xFF))+((packet[32]&0xFF)<<8|(packet[33]&0xFF));
			if(headerLen==24)
				sum+= ((packet[34]&0xFF)<<8|(packet[35]&0xFF))+((packet[36]&0xFF)<<8|(packet[37]&0xFF));
			sum = ((sum&0x00FF0000)>>16)+(sum&0x0000FFFF);
			
			short sum_2byte = (short) ~sum;
			packet[24] = (byte) (sum_2byte>>8);
			packet[25] = (byte) (sum_2byte&0x00FF);
		}
	}
	
	public int getSrcIPaddress() {
		return (((packet[26]&0xFF)<<24)|((packet[27]&0xFF)<<16)|((packet[28]&0xFF)<<8)|(packet[29]&0xFF));
	}
	
	public void setSrcIPaddress(byte a,byte b,byte c,byte d) {//
		packet[26] = a;
		packet[27] = b;
		packet[28] = c;
		packet[29] = d;
	}
	
	public int getDesIPaddress() {
		return (((packet[30]&0xFF)<<24)|((packet[31]&0xFF)<<16)|((packet[32]&0xFF)<<8)|(packet[33]&0xFF));
	}
	
	public void setDesIPaddress(byte a,byte b,byte c,byte d) {//
		packet[30] = a;
		packet[31] = b;
		packet[32] = c;
		packet[33] = d;
	}
	
	/*Frame===========================================================================*/
	
	/**
	 * Get destination MAC address.
	 * @return 
	 */
	public byte[] getFrameDesMACAddr() {
		byte[] addr = new byte[6];
		for(int i=0;i<6;i++) {
			addr[i] = packet[i];
		}
		return addr;
	}
	
	public void setFrameDesMACAddr(byte[] addr) {
		for(int i=0;i<6;i++) {
			packet[i] = addr[i];
		}
	}
	
	/**
	 * Get source MAC address.
	 * @return
	 */
	public byte[] getFrameSrcMACAddr() {
		byte[] addr = new byte[6];
		for(int i=6;i<12;i++) {
			addr[i-6] = packet[i];
		}
		return addr;
	}
	
	public void setFrameSrcMACAddr(byte[] addr) {
		for(int i=6;i<12;i++) {
			packet[i] = addr[i-6];
		}
	}
	
}
