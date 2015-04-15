----------------------------------------------------------------
-- IRONSIDES - DNS SERVER
--
-- By: Martin C. Carlisle and Barry S. Fagin
--     Department of Computer Science
--     United States Air Force Academy
--
-- This is free software; you can redistribute it and/or
-- modify without restriction.  We do ask that you please keep
-- the original author information, and clearly indicate if the
-- software has been modified.
--
-- This software is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty
-- of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
----------------------------------------------------------------

with System;
with Protected_SPARK_IO_05;
with DNS_Types;
with Unsigned_Types;
with DNS_Table_PKG;
with DNS_Network_Receive;
use type DNS_Types.Packet_Bytes_Range;
use type DNS_Types.Packet_Length_Range;
use type DNS_Types.Byte;
use type DNS_Types.Query_Type;
USE TYPE DNS_Types.Query_Class;
use type Unsigned_Types.Unsigned8;
use type Unsigned_Types.Unsigned16;
use type Unsigned_Types.Unsigned32;
use type DNS_Types.Unsigned_Short;
use type DNS_Types.QNAME_PTR_RANGE;
use type System.Bit_Order;
--with Ada.Text_Io;
with ada.Unchecked_Conversion;
package body Process_Dns_Request is
   procedure Set_Unsigned_32(
         Bytes : in out DNS_Types.Bytes_Array_Type;
         Start_Byte : in DNS_Types.Packet_Bytes_Range;
         Value : in Unsigned_Types.Unsigned32) is
   begin
      Bytes(Start_Byte) := DNS_Types.Byte(Value/2**24);
      Bytes(Start_Byte+1) := DNS_Types.Byte((Value/2**16) mod 256);
      Bytes(Start_Byte+2) := DNS_Types.Byte((Value/2**8) mod 256);
      Bytes(Start_Byte+3) := DNS_Types.Byte(Value mod 256);
   end Set_Unsigned_32;
   procedure Set_Unsigned_16(
         Bytes : in out DNS_Types.Bytes_Array_Type;
         Start_Byte : in DNS_Types.Packet_Bytes_Range;
         Value : in Unsigned_Types.Unsigned16) is
   begin
      Bytes(Start_Byte) := DNS_Types.Byte((Value/2**8) mod 256);
      Bytes(Start_Byte+1) := DNS_Types.Byte(Value mod 256);
   end Set_Unsigned_16;

   procedure Set_TTL_Data_IP(
         Bytes : in out DNS_Types.Bytes_Array_Type;
         Start_Byte : in DNS_Types.Packet_Bytes_Range;
         A_Record : in Rr_Type.A_Record_Type.ARecordType) is
   begin
         -- TTL
         Set_Unsigned_32(Bytes,Start_Byte,A_Record.ttlInSeconds);
         -- DATA 4 bytes
         Set_Unsigned_16(Bytes,Start_Byte+4,4);
         -- IP address
         Set_Unsigned_32(Bytes,Start_Byte+6,A_Record.ipv4);
   end Set_TTL_Data_IP;

   --base64 conversion
   FUNCTION Lookup(Arg: IN Character) RETURN DNS_Types.Byte IS
      ans : DNS_Types.Byte;
   BEGIN
      CASE Arg IS
         WHEN 'A'..'Z' => ans := Character'Pos(Arg) - Character'Pos('A');
         WHEN 'a'..'z' => ans := (Character'Pos(Arg) - Character'Pos('a'))+26;
         WHEN '0'..'9' => ans := (Character'Pos(Arg) - Character'Pos('0'))+52;
         WHEN '+' => ans := 62;
         WHEN '/' => ans := 63;
         WHEN OTHERS => ans := 0;
      end case;
      return ans;
   END Lookup;

   --see http://rfc-ref.org/RFC-TEXTS/4034/chapter2.html for DNSKEY record format
   procedure Set_TTL_Data_DNSKEY( --BSF
         Bytes : in out DNS_Types.Bytes_Array_Type;
         Start_Byte : in DNS_Types.Packet_Bytes_Range;
         DNSKEY_Record : IN Rr_Type.DNSKEY_Record_Type.DNSKEYRecordType;
         dstbytes : out rr_type.dnskey_record_type.keyLengthValueType) IS
         srcByte : Integer;
         KeyLength : Rr_Type.Dnskey_Record_Type.KeyLengthValueType;
         SrcNum0, SrcNum1, SrcNum2, SrcNum3: Dns_Types.Byte;
         dstNum0, dstNum1, dstNum2 : dns_types.byte;
   begin
         -- TTL (4 bytes)
         Set_Unsigned_32(Bytes,Start_Byte,DNSKEY_Record.ttlInSeconds);
         -- RDLENGTH (2 bytes, value is 4 plus the length of the key, placeholder at this point)
         Set_Unsigned_16(Bytes,Start_Byte+4,4+Unsigned_Types.Unsigned16(DNSKEY_Record.keyLength));
         -- RDATA (4 bytes)
         --   flags (2 bytes)
         Set_Unsigned_16(Bytes,Start_Byte+6,DNSKEY_Record.Flags);
         --   protocol (1 byte)
         Bytes(Start_Byte+8) := DNS_types.Byte(DNSKEY_Record.Protocol);
         --   algorithm (1 byte)
         Bytes(Start_Byte+9) := DNS_types.Byte(DNSKEY_Record.Algorithm);
         --   key field
         srcByte := 1;
         dstBytes := 1;
         keyLength := DNSKEY_Record.KeyLength;
         while srcByte + 3 <= keyLength loop  --since it's base64 encoded, src key will always contain an exact multiple of 4 bytes
            --# assert srcByte + 3 <= KeyLength and
            --# KeyLength <= rr_type.DNSKEY_Record_Type.MaxDNSKeyLength and KeyLength = DNSKEY_Record.KeyLength and
            --# dstBytes >= 1 and dstBytes <= srcByte and
            --# Start_Byte <= DNS_Types.Packet_Bytes_Range'Last-10-DNS_Types.Packet_Bytes_Range(DNSKEY_Record.keyLength);
            srcNum0 := Lookup(DNSKEY_Record.Key(srcByte));     --00aaaaaa
            srcNum1 := Lookup(DNSKEY_Record.Key(srcByte+1));   --00bbbbbb
            srcNum2 := Lookup(DNSKEY_Record.Key(srcByte+2));   --00cccccc
            SrcNum3 := Lookup(DNSKEY_Record.Key(SrcByte+3));   --00dddddd

            DstNum0 := SrcNum0*4 + (Srcnum1/16);   --aaaaaa00 + 000000bb = aaaaaabb
            DstNum1 := Srcnum1*16 + (SrcNum2/4);   --bbbb0000 + 0000cccc = bbbbcccc
            DstNum2 := SrcNum2*64 + SrcNum3;       --cc000000 + 00dddddd = ccdddddd

            Bytes((Start_Byte+9)+DNS_Types.Packet_Bytes_Range(DstBytes)) := DstNum0;
            Bytes((Start_Byte+9)+DNS_Types.Packet_Bytes_Range(DstBytes+1)) := DstNum1;
            Bytes((Start_Byte+9)+DNS_Types.Packet_Bytes_Range(DstBytes+2)) := DstNum2;

            srcByte := srcByte + 4;
            DstBytes := DstBytes + 3;
         END LOOP;
         -- RDLENGTH (2 bytes, value is 4 plus the length of the key, which we now know)
         dstBytes := dstbytes-1; --this is also an out parameter of this procedure
         Set_Unsigned_16(Bytes,Start_Byte+4,4+Unsigned_Types.Unsigned16(dstBytes));
   END Set_TTL_Data_DNSKEY;

--see http://tools.ietf.org/rfc/rfc3845.txt for NSEC wire format.  If you're a masochist.
   procedure Set_TTL_Data_NSEC( --BSF
         Bytes : in out DNS_Types.Bytes_Array_Type;
         Start_Byte : in DNS_Types.Packet_Bytes_Range;
         NSEC_Record : IN Rr_Type.NSEC_Record_Type.NSECRecordType;
         Dstbytes : OUT DNS_Types.Packet_Length_Range) IS --bytes used in RRDATA section
         Current_Name_Length : RR_Type.WireStringTypeIndex;
         blockOffset : DNS_Types.Packet_Bytes_Range;
   BEGIN
      -- TTL (4 bytes)
      Set_Unsigned_32(Bytes,Start_Byte,NSEC_Record.TtlInSeconds);
      -- RDLENGTH (2 bytes, value will be the length of the domain name plus the length of the bitmapped RRList)
      -- placeholder for now
      Set_Unsigned_16(Bytes,Start_Byte+4,Unsigned_Types.Unsigned16(0));

      -- NEXT DOMAIN NAME (Current_Name_Length bytes)
      Current_Name_Length := RR_Type.WireNameLength(NSEC_Record.NextDomainName);
      for i in RR_Type.WireStringTypeIndex range 1..Current_Name_Length loop
         --# assert Start_Byte <= (DNS_Types.Packet_Bytes_Range'Last-6)-DNS_Types.Packet_Bytes_Range(Current_Name_Length)
         --# and i>=RR_Type.WireStringTypeIndex'First and i<= RR_Type.WireStringTypeIndex'Last
         --# and Current_Name_Length >= RR_Type.WireStringTypeIndex'First and Current_Name_Length <= RR_Type.WireStringTypeIndex'Last
         --# and (for all J in RR_Type.WireStringTypeIndex => (Character'Pos(NSEC_Record.NextDomainName(J)) >= 0 and (Character'Pos(NSEC_Record.NextDomainName(J)) <= 255)));
         Bytes(((Start_Byte+6)-1)+DNS_Types.Packet_Bytes_Range(i)) := DNS_Types.Byte(Character'Pos(NSEC_Record.NextDomainName(i)));
      END LOOP;

      -- RR bitmap section (ugh)
      dstBytes := 0;
      BlockOffset := (((Start_Byte+6)-1)+DNS_Types.Packet_Bytes_Range(Current_Name_Length));
      FOR block IN rr_type.nsec_record_type.blockNumberValue range 1..NSEC_Record.NumberOfBlocks LOOP
         --# assert Start_Byte <= (DNS_Types.Packet_Bytes_Range'Last-6)-DNS_Types.Packet_Bytes_Range(Current_Name_Length)
         --# and Current_Name_Length >= RR_Type.WireStringTypeIndex'First and Current_Name_Length <= RR_Type.WireStringTypeIndex'Last
         --# and blockOffset >= dns_types.packet_bytes_range'first
         --# and blockOffset <= (((Start_Byte+6)-1)+DNS_Types.Packet_Bytes_Range(Current_Name_Length))
         --#  + DNS_Types.Packet_Bytes_Range((block-1)*(2+rr_type.nsec_record_type.BlockLengthValue'last))
         --# and dstBytes <= dns_types.packet_length_range((block-1)*rr_type.nsec_record_type.BlockLengthValue'last)
         --# and NSEC_Record.BlockLengths(Block) >= rr_type.nsec_record_type.BlockLengthValue'first
         --# and NSEC_Record.BlockLengths(Block) <= rr_type.nsec_record_type.BlockLengthValue'last;
         DstBytes := DstBytes + dns_types.Packet_Length_Range(NSEC_Record.BlockLengths(Block)); --sum up the block lengths, needed below
         Bytes(BlockOffset +1) := NSEC_Record.BlockNumbers(Block);
         Bytes(BlockOffset +2) := Dns_Types.Byte(NSEC_Record.BlockLengths(Block));
         FOR Byte IN rr_type.nsec_record_type.BlockLengthValue range 1..NSEC_Record.BlockLengths(Block) LOOP
            --# assert Start_Byte <= (DNS_Types.Packet_Bytes_Range'Last-6)-DNS_Types.Packet_Bytes_Range(Current_Name_Length)
            --# and Current_Name_Length >= RR_Type.WireStringTypeIndex'First and Current_Name_Length <= RR_Type.WireStringTypeIndex'Last
            --# and blockOffset >= dns_types.packet_bytes_range'first
            --# and blockOffset <= (((Start_Byte+6)-1)+DNS_Types.Packet_Bytes_Range(Current_Name_Length))
            --#  + DNS_Types.Packet_Bytes_Range((block-1)*(2+rr_type.nsec_record_type.BlockLengthValue'last))
            --# and dstBytes <= dns_types.packet_length_range(block*rr_type.nsec_record_type.BlockLengthValue'last)
            --# and byte >= rr_type.nsec_record_type.BlockLengthValue'first and byte <= rr_type.nsec_record_type.BlockLengthValue'last
            --# and block = block%;
            Bytes((BlockOffset+2)+Dns_Types.Packet_Bytes_Range(Byte)) := NSEC_Record.BitMaps(Block)(Byte);
         END LOOP;
         BlockOffset := (BlockOffset + 2) +  dns_types.Packet_Bytes_Range(NSEC_Record.BlockLengths(Block));
      END LOOP;
      DstBytes := DstBytes + dns_types.Packet_Length_Range(NSEC_Record.NumberOfBlocks*2);   --add in the bytes for the block numbers and the block lengths
      DstBytes := (DstBytes + dns_types.Packet_Length_Range(Current_Name_Length));   --sets final value of OUT parameter
      -- RDLENGTH (2 bytes, can now set final value as the length of the domain name plus the length of the bitmapped RRList)
      Set_Unsigned_16(Bytes,Start_Byte+4,unsigned_types.unsigned16(dstBytes));
   END Set_TTL_Data_NSEC;

   --see http://www.rfc-editor.org/rfc/rfc4034.txt for RRSIG record format
   procedure Set_TTL_Data_RRSIG( --BSF
         Bytes : in out DNS_Types.Bytes_Array_Type;
         Start_Byte : in DNS_Types.Packet_Bytes_Range;
         RRSIG_Record : IN Rr_Type.RRSIG_Record_Type.RRSIGRecordType;
         dstBytes : OUT DNS_Types.Packet_Bytes_Range) IS
         WireVersion : RR_Type.WireStringType;
         Current_Name_Length : RR_Type.WireStringTypeIndex;
         srcByte : Integer;
         sigLength : Rr_Type.Rrsig_Record_Type.sigLengthValueType;
         sigOffset : DNS_Types.Packet_Bytes_Range;
         SrcNum0, SrcNum1, SrcNum2, SrcNum3: Dns_Types.Byte;
         DstNum0, DstNum1, DstNum2 : Dns_Types.Byte;
         function From_Query_Type is new Ada.Unchecked_Conversion(DNS_Types.Query_Type,Unsigned_Types.Unsigned32);
         function From_Bytes_Range is new Ada.Unchecked_Conversion(DNS_Types.Packet_Bytes_Range,Unsigned_Types.Unsigned32);
   BEGIN
         -- TTL (4 bytes)
         Set_Unsigned_32(Bytes,Start_Byte,RRSIG_Record.ttlInSeconds);
         -- RDLENGTH (2 bytes, value is 18 plus the length of the name plus the length of the signature, placeholder at this point)
         Set_Unsigned_16(Bytes,Start_Byte+4,0);
         -- TYPE COVERED (2 bytes)
         --# accept Warning, 12, From_Query_Type, "unchecked conversions ok";
         -- Ugh.  The things we do to make SPARK happy.  mod is superfluous, used only to convince SPARK that the value is in type.
         Set_Unsigned_16(Bytes,Start_Byte+6,Unsigned_Types.Unsigned16(from_query_type(RRSIG_Record.typeCovered) mod 65536));
         -- ALGORITHM (1 byte)
         Bytes(Start_Byte+8) := DNS_Types.Byte(RRSIG_Record.Algorithm);
         -- LABELS (1 byte)
         Bytes(Start_Byte+9) := DNS_Types.Byte(RRSIG_Record.numLabels);
         -- ORIG TTL (4 bytes)
         Set_Unsigned_32(Bytes,Start_Byte+10,RRSIG_Record.OrigTTL);
         -- SIG EXPIRATION (4 bytes)
         Set_Unsigned_32(Bytes,Start_Byte+14,RRSIG_Record.SigExpiration);
         -- SIG INCEPTION (4 bytes) (starring Leonardo DiCaprio)
         Set_Unsigned_32(Bytes,Start_Byte+18,RRSIG_Record.SigInception);
         -- KEY TAG (2 bytes)
         Set_Unsigned_16(Bytes,Start_Byte+22,RRSIG_Record.KeyTag);

         -- SIGNER'S NAME (Current_Name_Length bytes)
         WireVersion := Rr_Type.ConvertDomainNameToWire(RRSIG_Record.SignerName);
         Current_Name_Length := RR_Type.WireNameLength(WireVersion);
         for i in RR_Type.WireStringTypeIndex range 1..Current_Name_Length loop
            --# assert Start_Byte <= (DNS_Types.Packet_Bytes_Range'Last-24)-DNS_Types.Packet_Bytes_Range(Current_Name_Length)
            --# and i>=RR_Type.WireStringTypeIndex'First and i<= RR_Type.WireStringTypeIndex'Last
            --# and Current_Name_Length >= RR_Type.WireStringTypeIndex'First and Current_Name_Length <= RR_Type.WireStringTypeIndex'Last
            --# and (for all J in RR_Type.WireStringTypeIndex => (Character'Pos(WireVersion(J)) >= 0 and (Character'Pos(WireVersion(J)) <= 255)));
            Bytes(((Start_Byte+24)-1)+DNS_Types.Packet_Bytes_Range(i)) := DNS_Types.Byte(Character'Pos(WireVersion(i)));
         END LOOP;

         -- SIGNATURE
         srcByte := 1;
         dstBytes := 1;
         sigLength := RRSIG_Record.SignatureLength;
         sigOffset := (((Start_Byte+24)-1)+DNS_Types.Packet_Bytes_Range(Current_Name_Length)); --this+1 is the index of the first byte of the signature
         while (srcByte + 3 <= sigLength) loop  --since it's base64 encoded, src key will always contain an exact multiple of 4 bytes
            --# assert srcByte + 3 <= sigLength and
            --# sigLength <= rr_type.RRSIG_Record_Type.MaxRRSIGLength and sigLength = RRSIG_Record.signatureLength and
            --# dstBytes >= DNS_Types.Packet_Bytes_Range(1) and dstBytes <= DNS_Types.Packet_Bytes_Range(srcByte) and
            --# Start_Byte <= DNS_Types.Packet_Bytes_Range'Last-24-DNS_Types.Packet_Bytes_Range(rr_type.MaxDomainNameLength)-DNS_Types.Packet_Bytes_Range(sigLength)
            --# and Current_Name_Length >= RR_Type.WireStringTypeIndex'First and Current_Name_Length <= RR_Type.WireStringTypeIndex'Last
            --# and sigOffset = Start_Byte+24-1+DNS_Types.Packet_Bytes_Range(Current_Name_Length);
            srcNum0 := Lookup(RRSIG_Record.signature(srcByte));     --00aaaaaa
            srcNum1 := Lookup(RRSIG_Record.signature(srcByte+1));   --00bbbbbb
            srcNum2 := Lookup(RRSIG_Record.signature(srcByte+2));   --00cccccc
            SrcNum3 := Lookup(RRSIG_Record.signature(SrcByte+3));   --00dddddd

            DstNum0 := SrcNum0*4 + (Srcnum1/16);   --aaaaaa00 + 000000bb = aaaaaabb
            DstNum1 := Srcnum1*16 + (SrcNum2/4);   --bbbb0000 + 0000cccc = bbbbcccc
            DstNum2 := SrcNum2*64 + SrcNum3;       --cc000000 + 00dddddd = ccdddddd

            Bytes(sigOffset + dstBytes) := DstNum0;
            Bytes(sigOffset + (dstBytes+1)) := DstNum1;
            Bytes(sigOffset + (dstBytes+2)) := DstNum2;

            srcByte := srcByte + 4;
            dstBytes := dstBytes + 3;
         END LOOP;

         -- Finally, we know how many bytes have been used on the wire (24 plus the length of the signer's name plus the length of the key)
         dstBytes := DNS_Types.Packet_Bytes_Range(24+Current_Name_Length)+(dstBytes-DNS_Types.Packet_Bytes_Range(1)); --sets the out parameter of this procedure
         -- and we can set RDLENGTH (2 bytes, value is 18 plus the length of the signer's name plus the length of the key)
	   --# accept Warning, 12, From_Bytes_Range, "unchecked conversions ok";
         -- The things we do to make SPARK happy.
         Set_Unsigned_16(Bytes,Start_Byte+4,Unsigned_Types.Unsigned16(from_bytes_range(dstBytes-6) mod 65536));
         -- sets RDLENGTH field (TTL and RDLENGTH fields don't count, so subtract 4+2=6 bytes)

   END Set_TTL_Data_RRSIG;

   procedure Set_TTL_Data_NS_Response(
         Bytes               : in out DNS_Types.Bytes_Array_Type;
         Start_Byte          : in DNS_Types.Packet_Bytes_Range;
         NS_Record           : in Rr_Type.ns_record_type.NSRecordType;
         Current_Name_Length : in RR_Type.WireStringTypeIndex) is
   begin
         -- TTL
         Set_Unsigned_32(Bytes,Start_Byte,NS_Record.ttlInSeconds);
         -- DATA # bytes is equal to length of WireString
         Set_Unsigned_16(Bytes,Start_Byte+4,Unsigned_Types.Unsigned16(Current_name_Length));
         -- copy NS record
         for i in RR_Type.WireStringTypeIndex range 1..Current_Name_Length loop
            --# assert Start_Byte <= (DNS_Types.Packet_Bytes_Range'Last-6)-DNS_Types.Packet_Bytes_Range(Current_Name_Length) and
            --# i>=RR_Type.WireStringTypeIndex'First and i<= RR_Type.WireStringTypeIndex'Last;
            Bytes((Start_Byte+5)+DNS_Types.Packet_Bytes_Range(I)) := DNS_Types.Byte(
               Character'Pos(NS_Record.nameServer(i)));
         end loop;
   end Set_TTL_Data_NS_Response;

   procedure Set_TTL_Data_PTR_Response(
         Bytes               : in out DNS_Types.Bytes_Array_Type;
         Start_Byte          : in DNS_Types.Packet_Bytes_Range;
         PTR_Record           : in Rr_Type.ptr_record_type.PTRRecordType;
         Current_Name_Length : in RR_Type.WireStringTypeIndex) is
   begin
         -- TTL
         Set_Unsigned_32(Bytes,Start_Byte,PTR_Record.ttlInSeconds);
         -- DATA # bytes is equal to length of WireString
         Set_Unsigned_16(Bytes,Start_Byte+4,Unsigned_Types.Unsigned16(Current_name_Length));
         -- copy NS record
         for i in RR_Type.WireStringTypeIndex range 1..Current_Name_Length loop
            --# assert Start_Byte <= (DNS_Types.Packet_Bytes_Range'Last-6)-DNS_Types.Packet_Bytes_Range(Current_Name_Length) and
            --# i>=RR_Type.WireStringTypeIndex'First and i<= RR_Type.WireStringTypeIndex'Last;
            Bytes((Start_Byte+5)+DNS_Types.Packet_Bytes_Range(I)) := DNS_Types.Byte(
               Character'Pos(PTR_Record.domainname(i)));
         end loop;
   end Set_TTL_Data_PTR_Response;


   procedure Set_TTL_Data_MX_Response(
         Bytes               : in out DNS_Types.Bytes_Array_Type;
         Start_Byte          : in DNS_Types.Packet_Bytes_Range;
         MX_Record           : in Rr_Type.MX_record_type.MXRecordType;
         Current_Name_Length : in RR_Type.WireStringTypeIndex) is
   begin
         -- TTL
         Set_Unsigned_32(Bytes,Start_Byte,MX_Record.ttlInSeconds);
         -- DATA # bytes is equal to length of WireString + 2
         Set_Unsigned_16(Bytes,Start_Byte+4,Unsigned_Types.Unsigned16(Current_Name_Length+2));
         -- MAIL exchanger preference
         Set_Unsigned_16(Bytes,Start_Byte+6,MX_Record.pref);
         -- copy NS record
         for i in RR_Type.WireStringTypeIndex range 1..Current_Name_Length loop
            --# assert Start_Byte <= (DNS_Types.Packet_Bytes_Range'Last-8)-DNS_Types.Packet_Bytes_Range(Current_Name_Length) and
            --# i>=RR_Type.WireStringTypeIndex'First and i<= RR_Type.WireStringTypeIndex'Last;
            Bytes((Start_Byte+7)+DNS_Types.Packet_Bytes_Range(I)) := DNS_Types.Byte(
               Character'Pos(MX_Record.mailExchanger(i)));
         end loop;
   end Set_TTL_Data_MX_Response;

   procedure Set_TTL_Data_SRV_Response(
         Bytes               : in out DNS_Types.Bytes_Array_Type;
         Start_Byte          : in DNS_Types.Packet_Bytes_Range;
         SRV_Record           : in Rr_Type.SRV_record_type.SRVRecordType;
         Current_Name_Length : in RR_Type.WireStringTypeIndex) is
   begin
         -- TTL
         Set_Unsigned_32(Bytes,Start_Byte,SRV_Record.ttlInSeconds);
         -- DATA # bytes is equal to length of WireString + 6
         Set_Unsigned_16(Bytes,Start_Byte+4,Unsigned_Types.Unsigned16(Current_Name_Length+6));
         -- Server preference
         Set_Unsigned_16(Bytes,Start_Byte+6,SRV_Record.pref);
         -- Server weight
         Set_Unsigned_16(Bytes,Start_Byte+8,SRV_Record.weight);
         -- Server port
         Set_Unsigned_16(Bytes,Start_Byte+10,SRV_Record.portNum);
         -- copy NS record
         for i in RR_Type.WireStringTypeIndex range 1..Current_Name_Length loop
            --# assert Start_Byte <= (DNS_Types.Packet_Bytes_Range'Last-12)-DNS_Types.Packet_Bytes_Range(Current_Name_Length) and
            --# i>=RR_Type.WireStringTypeIndex'First and i<= RR_Type.WireStringTypeIndex'Last;
            Bytes((Start_Byte+11)+DNS_Types.Packet_Bytes_Range(I)) := DNS_Types.Byte(
               Character'Pos(SRV_Record.ServerName(i)));
         end loop;
   end Set_TTL_Data_SRV_Response;

   procedure Set_TTL_Data_SOA_Response(
         Bytes                  : in out DNS_Types.Bytes_Array_Type;
         Start_Byte             : in DNS_Types.Packet_Bytes_Range;
         SOA_Record             : in Rr_Type.SOA_record_type.SOARecordType;
         Nameserver_Name_Length : in RR_Type.WireStringTypeIndex;
         Mailbox_Name_Length    : in RR_Type.WireStringTypeIndex) is
      Current_Byte : DNS_Types.Packet_Bytes_Range;
   begin
      -- TTL
      Set_Unsigned_32(Bytes,Start_Byte,SOA_Record.ttlInSeconds);
      -- DATA # bytes is equal to length of both WireStrings + 20
      Set_Unsigned_16(Bytes,Start_Byte+4,Unsigned_Types.Unsigned16(
         Nameserver_Name_Length + (Mailbox_Name_Length+20)));
      -- copy NS record
      for i in RR_Type.WireStringTypeIndex range 1..Nameserver_Name_Length loop
         --# assert Start_Byte <= (DNS_Types.Packet_Bytes_Range'Last-20)-
         --# DNS_Types.Packet_Bytes_Range(Mailbox_Name_Length+Nameserver_Name_Length) and
         --# i>=RR_Type.WireStringTypeIndex'First and i<= RR_Type.WireStringTypeIndex'Last;
         Bytes((Start_Byte+5)+DNS_Types.Packet_Bytes_Range(I)) := DNS_Types.Byte(
            Character'Pos(SOA_Record.nameServer(i)));
      end loop;
      Current_Byte := Start_Byte+DNS_Types.Packet_Bytes_Range(
         5+(Nameserver_Name_Length));
      -- copy MB record
      for i in RR_Type.WireStringTypeIndex range 1..Mailbox_Name_Length loop
         --# assert Current_Byte>=1 and Current_Byte <= (DNS_Types.Packet_Bytes_Range'Last-20)-
         --# DNS_Types.Packet_Bytes_Range(Mailbox_Name_Length) and
         --# i>=RR_Type.WireStringTypeIndex'First and i<= RR_Type.WireStringTypeIndex'Last;
         Bytes(Current_Byte+DNS_Types.Packet_Bytes_Range(I)) := DNS_Types.Byte(
            Character'Pos(SOA_Record.email(i)));
      end loop;
      Current_Byte := Start_Byte+DNS_Types.Packet_Bytes_Range(
         6+(Nameserver_Name_Length + Mailbox_Name_Length));
      -- serial number
      Set_Unsigned_32(Bytes,Current_Byte,SOA_Record.SerialNumber);
      -- refresh interval
      Set_Unsigned_32(Bytes,Current_Byte+4,SOA_Record.refresh);
      -- retry interval
      Set_Unsigned_32(Bytes,Current_Byte+8,SOA_Record.retry);
      -- expiration limit
      Set_Unsigned_32(Bytes,Current_Byte+12,SOA_Record.expiry);
      -- minimum TTL
      Set_Unsigned_32(Bytes,Current_Byte+16,SOA_Record.minimum);
   end Set_TTL_Data_SOA_Response;


   procedure Set_TTL_Data_AAAA_IP(
         Bytes : in out DNS_Types.Bytes_Array_Type;
         Start_Byte : in DNS_Types.Packet_Bytes_Range;
         AAAA_Record : in Rr_Type.AAAA_Record_Type.AAAARecordType) is
   begin
      -- TTL
      Set_Unsigned_32(Bytes,Start_Byte,AAAA_Record.ttlInSeconds);
      -- DATA 16 bytes
      Set_Unsigned_16(Bytes,Start_Byte+4,16);
      for i in rr_type.aaaa_record_type.IPV6AddrTypeIndex loop
         --# assert true;
         -- IP address
         Set_Unsigned_16(Bytes,Start_Byte+
            DNS_Types.Packet_Bytes_Range(6+2*(I-Rr_Type.Aaaa_Record_Type.IPV6AddrTypeIndex'First)),
            AAAA_Record.Ipv6(i));
      end loop;
   end Set_TTL_Data_AAAA_IP;


   procedure Get_Query_Name_Type_Class(
         Input_Packet  : in DNS_Types.DNS_Packet;
         Input_Bytes   : in DNS_Types.Packet_Length_Range;
         Domainname    : out RR_Type.wireStringType;
         Query_Type    : out DNS_Types.Query_Type;
         Query_Class   : out DNS_Types.Query_Class;
         End_Byte      : out Dns_types.Packet_Bytes_Range) is
      Byte : Dns_types.Packet_Bytes_Range := DNS_Types.Packet_Bytes_Range'First;
      I : Natural := RR_Type.WireStringType'First;
      QT_Natural, QC_Natural : Natural;
      function Type_To_Natural is new Ada.Unchecked_Conversion(Dns_Types.Query_Type,Natural);
      function to_type is new ada.Unchecked_Conversion(natural,dns_types.query_type);
      function class_to_natural is new ada.Unchecked_Conversion(dns_types.query_class,natural);
      function To_Class is new Ada.Unchecked_Conversion(Natural,Dns_Types.Query_Class);
   begin
      Domainname := RR_Type.WireStringType'(others => ' ');
      while Integer(Byte) <= Integer(Input_Bytes-5) and then Input_Packet.Bytes(Byte)/=0
         and then I < RR_Type.WireStringType'Last loop
         --# assert I>=RR_Type.WireStringType'First and I < RR_Type.WireStringType'Last and
         --# Byte >= DNS_Types.Packet_Bytes_Range'First and Integer(Byte) <= Integer(Input_Bytes-5);
         Domainname(I) := Character'Val(Input_Packet.Bytes(Byte));
         I := I + 1;
         Byte := Byte + 1;
      end loop;
      Domainname(I) := Character'Val(0);
--      for I in Byte-2..Byte+4 loop
--         Ada.Text_IO.Put_Line("byte: " & Dns_Types.Packet_Bytes_Range'Image(I) & ":" &
--            Natural'Image(natural(Input_Packet.Bytes(I))));
--      end loop;
      QT_Natural := Natural(Input_Packet.Bytes(Byte+1))*256+Natural(Input_Packet.Bytes(Byte+2));
      QC_Natural := Natural(Input_Packet.Bytes(Byte+3))*256+Natural(Input_Packet.Bytes(Byte+4));
--      ada.Text_IO.put_line("qt: " & natural'image(qt_natural));
--      ada.Text_IO.put_line("qc: " & natural'image(qc_natural));
      --# accept Warning, 12, type_To_Natural, "unchecked conversions ok";
      if QT_Natural >= type_To_Natural(DNS_Types.Query_Type'First) and QT_Natural <= type_To_Natural(DNS_Types.Query_Type'Last) then
      --# end accept;
         --# accept Warning, 12, To_Type, "unchecked conversions ok";
         Query_Type := To_Type(QT_Natural);
         --# end accept;
         if not Query_Type'Valid then
            Query_Type := DNS_Types.UNIMPLEMENTED;
         end if;
      else
         Query_Type := DNS_Types.UNIMPLEMENTED;
      end if;
      --# accept Warning, 12, class_To_Natural, "unchecked conversions ok";
      if QC_Natural >= class_to_natural(DNS_Types.Query_Class'First) and QC_Natural <= class_to_natural(DNS_Types.Query_Class'Last) then
      --# end accept;
         --# accept Warning, 12, To_Class, "unchecked conversions ok";
         Query_Class := To_Class(QC_Natural);
         --# end accept;
         if not Query_Class'Valid then
            Query_Class := DNS_Types.NONE_CLASS;
         end if;
      else
         Query_Class := DNS_Types.NONE_CLASS;
      end if;
      End_Byte := Byte + 4;
   end Get_Query_Name_Type_Class;

   procedure Create_Response_Error(
         Input_Bytes   : in DNS_Types.Packet_Length_Range;
         Output_Packet : in out DNS_Types.DNS_Packet;
         Output_Bytes  : out DNS_Types.Packet_Length_Range) is
   begin
      Output_Packet.Header.AA := True;
      Output_Packet.Header.RCODE   := DNS_Types.Not_Implemented;
      Output_Packet.Header.ANCount := 0;
      Output_Bytes := Input_Bytes;
   end Create_Response_Error;

   procedure Create_Response_AAAA(
         Start_Byte    : in DNS_Types.Packet_Bytes_Range;
         Domainname    : in RR_Type.WireStringType;
         Qname_Location : in DNS_Types.QNAME_PTR_RANGE;
         Output_Packet : in out DNS_Types.DNS_Packet;
         Answer_Count    : in out DNS_Types.Unsigned_Short;
         Output_Bytes  : out DNS_Types.Packet_Length_Range) is
      Current_Byte  : DNS_Types.Packet_Bytes_Range;
      ReturnedAAAARecords : Rr_Type.AAAA_Record_Type.AAAARecordBucketType;
      NumFound : Natural;
      Response_Counter : Natural;
	NumAFound : Natural;
   begin
         -- accept Flow, 23, ReturnedAAAARecords, "it will fill in enough";
         DNS_Table_Pkg.DNS_Table.QueryAAAARecords(DomainName => Domainname,
         ReturnedRecords => ReturnedAAAARecords, HowMany => NumFound);
         -- end accept;
         Current_Byte := Start_Byte;

         if NumFound>=1 then
            Response_Counter := 1;
            while Response_Counter <= NumFound and Integer(Current_Byte) < DNS_Types.Packet_Size-(28+DNS_Types.Header_Bits/8) loop
               --# assert Response_Counter >=1 and Response_Counter <= NumFound
               --# and Answer_Count = Answer_Count~
               --# and Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords)
               --# and Current_Byte = Start_Byte +
               --#        DNS_Types.Packet_Bytes_Range(28*(Response_Counter-1))
               --# and Integer(Current_Byte) < DNS_Types.Packet_Size-(28+DNS_Types.Header_Bits/8)
               --# and numfound <= rr_type.MaxNumRecords ;
               -- PTR to character of message
               Set_Unsigned_16(Output_Packet.Bytes,Current_Byte+1,Unsigned_Types.Unsigned16(Qname_Location)+16#C000#);
               -- AAAA
               Output_Packet.Bytes(Current_Byte+3) := 16#00#;
               Output_Packet.Bytes(Current_Byte+4) := 16#1C#;
               -- IN
               Output_Packet.Bytes(Current_Byte+5) := 16#00#;
               Output_Packet.Bytes(Current_Byte+6) := 16#01#;
               Set_TTL_Data_AAAA_IP(Output_Packet.Bytes,Current_Byte+7,ReturnedAAAARecords(ReturnedAAAARecords'First+(Response_Counter-1)));
               Response_Counter := Response_Counter + 1;
               Current_Byte := Current_Byte + 28;
            end loop;
            --Output_Bytes := Input_Bytes+DNS_Types.Packet_Length_Range(28*(Response_Counter-1));
         else
         	DNS_Table_Pkg.DNS_Table.CountARecords(DomainName => Domainname,
            	  HowMany => NumAFound);
		if NumAFound > 0 then
		   Output_Packet.Header.AA := True;
		end if;
         end if;
         Output_Bytes := DNS_Types.Packet_Length_Range(Current_Byte + DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8));
         Answer_Count := Answer_Count + DNS_Types.Unsigned_Short(numFound);
      -- accept Flow, 602, Output_Packet, ReturnedAAAARecords,  "initialization is unneeded";
   end Create_Response_AAAA;

   procedure Create_Response_A(
         Start_Byte    : in DNS_Types.Packet_Bytes_Range;
         Domainname    : in RR_Type.WireStringType;
         Qname_Location : in DNS_Types.QNAME_PTR_RANGE;
         Output_Packet : in out DNS_Types.DNS_Packet;
         Answer_Count    : in out DNS_Types.Unsigned_Short;
         Output_Bytes  : out DNS_Types.Packet_Length_Range) is
      Current_Byte  : DNS_Types.Packet_Bytes_Range;
      ReturnedARecords : Rr_Type.A_Record_Type.ARecordBucketType;
      NumFound : Natural;
      Response_Counter : Natural;
	NumAAAAFound : Natural;
   begin
         -- accept Flow, 23, ReturnedARecords, "it will fill in enough";
         DNS_Table_Pkg.DNS_Table.QueryARecords(DomainName => Domainname,
            ReturnedRecords => ReturnedARecords, HowMany => NumFound);
         -- end accept;
         Current_Byte := Start_Byte;


         if NumFound>=1 then
            Response_Counter := 1;
            while Response_Counter <= NumFound and Integer(Current_Byte) < DNS_Types.Packet_Size-(16+DNS_Types.Header_Bits/8) loop
               --# assert Response_Counter >=1 and Response_Counter <= NumFound
               --# and Integer(Start_Byte) <= DNS_Types.Packet_Size
               --# and Answer_Count = Answer_Count~
               --# and Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords)
               --# and Current_Byte = Start_Byte +
               --#        DNS_Types.Packet_Bytes_Range(16*(Response_Counter-1))
               --# and Integer(Current_Byte) < DNS_Types.Packet_Size-(16+DNS_Types.Header_Bits/8)
               --# and numfound <= rr_type.MaxNumRecords ;
               -- PTR to character of message
               Set_Unsigned_16(Output_Packet.Bytes,Current_Byte+1,Unsigned_Types.Unsigned16(Qname_Location)+16#C000#);
               -- A
               Output_Packet.Bytes(Current_Byte+3) := 16#00#;
               Output_Packet.Bytes(Current_Byte+4) := 16#01#;
               -- IN
               Output_Packet.Bytes(Current_Byte+5) := 16#00#;
               Output_Packet.Bytes(Current_Byte+6) := 16#01#;
               Set_TTL_Data_IP(Output_Packet.Bytes,Current_Byte+7,ReturnedARecords(ReturnedARecords'First+(Response_Counter-1)));
               Response_Counter := Response_Counter + 1;
               Current_Byte := Current_Byte + 16;
            end loop;
            --Output_Bytes := Input_Bytes+DNS_Types.Packet_Length_Range(16*(Response_Counter-1));
         else
         	DNS_Table_Pkg.DNS_Table.CountAAAARecords(DomainName => Domainname,
            	  HowMany => NumAAAAFound);
		if NumAAAAFound > 0 then
		   Output_Packet.Header.AA := True;
		end if;
         end if;
         Output_Bytes := DNS_Types.Packet_Length_Range(Current_Byte + DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8));
         Answer_Count := Answer_Count + DNS_Types.Unsigned_Short(numFound);
      -- accept Flow, 602, Output_Packet, ReturnedARecords,  "initialization is unneeded";
   end Create_Response_A;

--DNSSEC code here {DNSKEY, NSEC, RRSIG}  --BSF
   procedure Create_Response_DNSKEY(
         Start_Byte    : in DNS_Types.Packet_Bytes_Range;
         Domainname    : in RR_Type.WireStringType;
         Qname_Location : in DNS_Types.QNAME_PTR_RANGE;
         Output_Packet : in out DNS_Types.DNS_Packet;
         Answer_Count    : in out DNS_Types.Unsigned_Short;
         Output_Bytes  : OUT DNS_Types.Packet_Length_Range) IS
      Current_Byte  : DNS_Types.Packet_Bytes_Range;
      ReturnedDNSKEYRecords : Rr_Type.DNSKEY_Record_Type.DNSKEYRecordBucketType;
      NumFound : Natural;
      Response_Counter : Natural;
      CurrentRec : Rr_Type.DNSKEY_Record_Type.DNSKEYRecordType;
      bytesUsedInEncodedKey : rr_type.dnskey_record_type.keyLengthValueType;
   BEGIN
         -- accept Flow, 23, ReturnedDNSKEYRecords, "it will fill in enough";
         DNS_Table_Pkg.DNS_Table.QueryDNSKEYRecords(DomainName => Domainname,
            ReturnedRecords => ReturnedDNSKEYRecords, HowMany => NumFound);
         -- end accept;
         Current_Byte := Start_Byte; -- actually the last byte of the question section
         if NumFound>=1 then
            Response_Counter := 1;
            CurrentRec := ReturnedDNSKEYRecords(Response_Counter);
            --loop to build the return message
            WHILE Response_Counter <= NumFound AND
               Integer(Current_Byte) < DNS_Types.Packet_Size-((16 + Rr_Type.DNSKEY_Record_Type.MaxDNSKeyLength) + DNS_Types.Header_Bits/8) LOOP
               --# assert Response_Counter >=1 and Response_Counter <= NumFound
               --# and Integer(Start_Byte) <= DNS_Types.Packet_Size
               --# and Answer_Count = Answer_Count~
               --# and Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords)
               --# and Integer(Current_Byte) < DNS_Types.Packet_Size-(16 + Rr_Type.DNSKEY_Record_Type.MaxDNSKeyLength + DNS_Types.Header_Bits/8)
               --# and numfound <= rr_type.MaxNumRecords;
               -- NAME (2 bytes, PTR to name)
               Set_Unsigned_16(Output_Packet.Bytes,Current_Byte+1,Unsigned_Types.Unsigned16(Qname_Location)+16#C000#);
               -- TYPE (2 bytes, DNSKEY --> 48)
               Output_Packet.Bytes(Current_Byte+3) := 16#00#;
               Output_Packet.Bytes(Current_Byte+4) := 16#30#;
               -- CLASS (2 bytes, IN --> 1)
               Output_Packet.Bytes(Current_Byte+5) := 16#00#;
               Output_Packet.Bytes(Current_Byte+6) := 16#01#;
               --set TTL (4 bytes), RDLENGTH (2 bytes) and RDATA (4 bytes + keylength) fields
               Set_TTL_Data_DNSKEY(Output_Packet.Bytes,Current_Byte+7,CurrentRec,bytesUsedInEncodedKey);
               Current_Byte := Current_Byte + DNS_Types.Packet_Bytes_Range(16 + bytesUsedInEncodedKey);
               Response_Counter := Response_Counter + 1;
               if Response_Counter <= NumFound then
                  CurrentRec := ReturnedDNSKEYRecords(Response_Counter);
               END IF;
            END LOOP;
         end if; --NumFound >= 1
         Output_Bytes := DNS_Types.Packet_Length_Range(Current_Byte + DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8));
         Answer_Count := Answer_Count + DNS_Types.Unsigned_Short(numFound);
      -- accept Flow, 602, Output_Packet, ReturnedDNSKEYRecords,  "initialization is unneeded";
   END Create_Response_DNSKEY;

   procedure Create_Response_NSEC(
         Start_Byte     : in DNS_Types.Packet_Bytes_Range;
         Domainname     : in RR_Type.WireStringType;
         Qname_Location : in DNS_Types.QNAME_PTR_RANGE;
         Output_Packet  : in out DNS_Types.DNS_Packet;
         Answer_Count   : in out DNS_Types.Unsigned_Short;
         Output_Bytes   : OUT DNS_Types.Packet_Length_Range) IS
      Current_Byte  : DNS_Types.Packet_Bytes_Range;
      ReturnedNSECRecords : Rr_Type.NSEC_Record_Type.NSECRecordBucketType;
      NumFound : Natural;
      Response_Counter : Natural;
      CurrentRec : Rr_Type.NSEC_Record_Type.NSECRecordType;
      bytesUsedInRRData  : DNS_Types.Packet_Length_Range;
   BEGIN
      -- accept Flow, 23, ReturnedNSECRecords, "it will fill in enough";
      DNS_Table_Pkg.DNS_Table.QueryNSECRecords(DomainName => Domainname,
         ReturnedRecords => ReturnedNSECRecords, HowMany => NumFound);
      -- end accept;
      Current_Byte := Start_Byte; -- actually the last byte of the question section
      if NumFound>=1 then
         Response_Counter := 1;
         CurrentRec := ReturnedNSECRecords(Response_Counter);
         WHILE Response_Counter <= NumFound AND Integer(Current_Byte) <
           DNS_Types.Packet_Size-((((12 + Rr_Type.NSEC_Record_Type.MaxRRDataLength)
           + rr_type.maxDomainNameLength)+1) + DNS_Types.Header_Bits/8) LOOP
            -- NAME (2 bytes, PTR to name)
            Set_Unsigned_16(Output_Packet.Bytes,Current_Byte+1,Unsigned_Types.Unsigned16(Qname_Location)+16#C000#);
            -- TYPE (2 bytes, NSEC --> 47)
            Output_Packet.Bytes(Current_Byte+3) := 16#00#;
            Output_Packet.Bytes(Current_Byte+4) := 16#2f#;
            -- CLASS (2 bytes, IN --> 1)
            Output_Packet.Bytes(Current_Byte+5) := 16#00#;
            Output_Packet.Bytes(Current_Byte+6) := 16#01#;
            --set TTL (4 bytes), RDLENGTH (2 bytes) and RDATA (domainNameLength + rrListLength) fields
            Set_TTL_Data_NSEC(Output_Packet.Bytes,Current_Byte+7,CurrentRec,bytesUsedInRRData);
            --# assert Response_Counter >=1 and Response_Counter <= NumFound
            --# and Integer(Start_Byte) <= DNS_Types.Packet_Size
            --# and Answer_Count = Answer_Count~
            --# and Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords)
            --# and Integer(Current_Byte) < DNS_Types.Packet_Size-((12 + Rr_Type.NSEC_Record_Type.MaxRRDataLength)
            --#   + (rr_type.maxDomainNameLength+1) + DNS_Types.Header_Bits/8)
            --# and bytesUsedInRRData <= DNS_Types.Packet_Length_Range(Rr_Type.NSEC_Record_Type.MaxRRDataLength)
            --# and numfound <= rr_type.MaxNumRecords;
            Current_Byte := Current_Byte + DNS_Types.Packet_Bytes_Range(12 + bytesUsedInRRData);
            Response_Counter := Response_Counter + 1;
            if Response_Counter <= NumFound then
               CurrentRec := ReturnedNSECRecords(Response_Counter);
            END IF;
         END LOOP;
      end if; --NumFound >= 1
      Output_Bytes := DNS_Types.Packet_Length_Range(Current_Byte + DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8));
      Answer_Count := Answer_Count + DNS_Types.Unsigned_Short(numFound);
      -- accept Flow, 602, Output_Packet, ReturnedNSECRecords,  "initialization is unneeded";
   END Create_Response_NSEC;

   procedure Create_Response_RRSIG(
         Start_Byte    : in DNS_Types.Packet_Bytes_Range;
         Domainname    : in RR_Type.WireStringType;
         Qname_Location : in DNS_Types.QNAME_PTR_RANGE;
         Output_Packet : in out DNS_Types.DNS_Packet;
         Answer_Count    : in out DNS_Types.Unsigned_Short;
         Output_Bytes  : OUT DNS_Types.Packet_Length_Range) IS
      Current_Byte  : DNS_Types.Packet_Bytes_Range;
      ReturnedRRSIGRecords : Rr_Type.RRSIG_Record_Type.RRSIGRecordBucketType;
      NumFound : Natural;
      Response_Counter : Natural;
      CurrentRec : Rr_Type.RRSIG_Record_Type.RRSIGRecordType;
      bytesUsedOnWire : DNS_Types.Packet_Bytes_Range;
   BEGIN
      -- accept Flow, 23, ReturnedRRSIGRecords, "it will fill in enough";
      DNS_Table_Pkg.DNS_Table.QueryRRSIGRecords(DomainName => Domainname,
         ReturnedRecords => ReturnedRRSIGRecords, HowMany => NumFound);
      -- end accept;
      Current_Byte := Start_Byte; -- actually the last byte of the question section
      IF NumFound>=1 THEN
         Response_Counter := 1;
         CurrentRec := ReturnedRRSIGRecords(Response_Counter);
         --loop to build the return message
         WHILE Response_Counter <= NumFound AND
            Integer(Current_Byte) < DNS_Types.Packet_Size-(((30 + Rr_Type.MaxDomainNameLength) + Rr_Type.Rrsig_Record_Type.maxrrsigLength) + DNS_Types.Header_Bits/8) LOOP
            --# assert Response_Counter >=1 and Response_Counter <= NumFound
            --# and Integer(Start_Byte) <= DNS_Types.Packet_Size
            --# and Answer_Count = Answer_Count~
            --# and Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords)
            --# and Integer(Current_Byte) < DNS_Types.Packet_Size-(((30 + Rr_Type.MaxDomainNameLength) + Rr_Type.Rrsig_Record_Type.maxrrsigLength) + DNS_Types.Header_Bits/8)
            --# and numfound <= rr_type.MaxNumRecords;
            -- NAME (2 bytes, PTR to name)
            Set_Unsigned_16(Output_Packet.Bytes,Current_Byte+1,Unsigned_Types.Unsigned16(Qname_Location)+16#C000#);
            -- TYPE (2 bytes, DNSKEY --> 46)
            Output_Packet.Bytes(Current_Byte+3) := 16#00#;
            Output_Packet.Bytes(Current_Byte+4) := 16#2E#;
            -- CLASS (2 bytes, IN --> 1)
            Output_Packet.Bytes(Current_Byte+5) := 16#00#;
            Output_Packet.Bytes(Current_Byte+6) := 16#01#;
            --set TTL (4 bytes), RDLENGTH (2 bytes) and RDATA (18 bytes + name length + sig length) fields
            Set_TTL_Data_RRSIG(Output_Packet.Bytes,Current_Byte+7,CurrentRec,bytesUsedOnWire);
            Current_Byte := (Current_Byte + 6) + bytesUsedOnWire;
            Response_Counter := Response_Counter + 1;
            if Response_Counter <= NumFound then
               CurrentRec := ReturnedRRSIGRecords(Response_Counter);
            END IF;
         end loop;
      end if; --NumFound >= 1
      Output_Bytes := DNS_Types.Packet_Length_Range(Current_Byte + DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8));
      Answer_Count := Answer_Count + DNS_Types.Unsigned_Short(numFound);
      -- accept Flow, 602, Output_Packet, ReturnedRRSIGRecords,  "initialization is unneeded";
   END Create_Response_RRSIG;

   procedure Create_Response_NS(
         Start_Byte      : in DNS_Types.Packet_Bytes_Range;
         Domainname      : in RR_Type.WireStringType;
         Num_Found       : out RR_Type.NumberOfRecordsType;
         Qname_Location  : in DNS_Types.QNAME_PTR_RANGE;
         Qname_Locations : out QNAME_PTR_RANGE_Array;
         Replies         : out RR_Type.ns_record_type.NSRecordBucketType;
         Output_Packet   : in out DNS_Types.DNS_Packet;
         Answer_Count    : in out DNS_Types.Unsigned_Short;
         Output_Bytes    : out DNS_Types.Packet_Length_Range) is
      Response_Counter : Natural;
      Current_Byte  : DNS_Types.Packet_Bytes_Range;
      Current_Name_Length : RR_Type.WireStringTypeIndex;
   begin
      Qname_Locations := QNAME_PTR_RANGE_Array'(others => 0);
      Current_Byte := Start_Byte;
      -- accept Flow, 23, Replies, "it will fill in enough";
      DNS_Table_Pkg.DNS_Table.QueryNSRecords(
         DomainName      => Domainname,
         ReturnedRecords => Replies,
         HowMany         => Num_Found);
      -- end accept;
      if Num_Found>=1 then
         Response_Counter := 1;
         Current_Name_Length := RR_Type.WireNameLength(Replies(Response_Counter).nameServer);
         while Response_Counter <= Num_Found and then
            Integer(Current_Byte) < (DNS_Types.Packet_Size-(12+DNS_Types.Header_Bits/8))-
               (Current_Name_Length) loop
            --# assert Response_Counter >=1 and Response_Counter <= Num_Found
            --# and current_name_length >=1 and current_name_length<=rr_type.WireStringTypeIndex'last
            --# and Num_Found <= rr_type.MaxNumRecords
            --# and Integer(Start_Byte) <= DNS_Types.Packet_Size
            --# and Answer_Count = Answer_Count~
            --# and Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords)
            --# and Integer(Current_Byte) < (DNS_Types.Packet_Size-(12+DNS_Types.Header_Bits/8))-
            --#    (Current_Name_Length)
            --# and Current_Byte >= 0;
            -- PTR to character of message
            Set_Unsigned_16(Output_Packet.Bytes,Current_Byte+1,Unsigned_Types.Unsigned16(Qname_Location)+16#C000#);
            -- NS
            Output_Packet.Bytes(Current_Byte+3) := 16#00#;
            Output_Packet.Bytes(Current_Byte+4) := 16#02#;
            -- IN
            Output_Packet.Bytes(Current_Byte+5) := 16#00#;
            Output_Packet.Bytes(Current_Byte+6) := 16#01#;
            Qname_Locations(Response_Counter) := DNS_Types.QNAME_PTR_RANGE(
               (Current_Byte+12)+ DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8));
            Set_TTL_Data_NS_Response(Output_Packet.Bytes,Current_Byte+7,
               Replies(Response_Counter),Current_Name_Length);
            Response_Counter := Response_Counter + 1;
            Current_Byte := (Current_Byte + 12) + DNS_Types.Packet_Bytes_Range(Current_Name_Length);
            if Response_Counter <= Num_Found then
               Current_Name_Length := RR_Type.WireNameLength(Replies(Response_Counter).nameServer);
            end if;
         end loop;
      end if;
      Output_Bytes := DNS_Types.Packet_Length_Range(Current_Byte + DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8));
      Answer_Count := Answer_Count + DNS_Types.Unsigned_Short(Num_Found);
      -- accept Flow, 602, Output_Packet, Replies,  "initialization is unneeded";
      -- accept Flow, 602, Output_Bytes, Replies,  "initialization is unneeded";
      -- accept Flow, 602, Replies, Replies,  "initialization is unneeded";
      -- accept Flow, 602, Qname_Locations, Replies,  "initialization is unneeded";
   end Create_Response_NS;

   procedure Create_Response_PTR(
         Start_Byte      : in DNS_Types.Packet_Bytes_Range;
         Domainname      : in RR_Type.WireStringType;
         Qname_Location  : in DNS_Types.QNAME_PTR_RANGE;
         Output_Packet   : in out DNS_Types.DNS_Packet;
         Answer_Count    : in out DNS_Types.Unsigned_Short;
         Output_Bytes    : out DNS_Types.Packet_Length_Range) is
      Num_Found           : RR_Type.NumberOfRecordsType;
      Response_Counter    : Natural;
      Current_Byte        : DNS_Types.Packet_Bytes_Range;
      Current_Name_Length : RR_Type.WireStringTypeIndex;
      Replies             : RR_Type.PTR_record_type.PTRRecordBucketType;
   begin
      Current_Byte := Start_Byte;
      -- accept Flow, 23, Replies, "it will fill in enough";
      DNS_Table_Pkg.DNS_Table.QueryPTRRecords(
         DomainName      => Domainname,
         ReturnedRecords => Replies,
         HowMany         => Num_Found);
      -- end accept;
      if Num_Found>=1 then
         Response_Counter := 1;
         Current_Name_Length := RR_Type.WireNameLength(Replies(Response_Counter).domainname);
         while Response_Counter <= Num_Found and then
            Integer(Current_Byte) < (DNS_Types.Packet_Size-(12+DNS_Types.Header_Bits/8))-
               (Current_Name_Length) loop
            --# assert Response_Counter >=1 and Response_Counter <= Num_Found
            --# and current_name_length >=1 and current_name_length<=rr_type.WireStringTypeIndex'last
            --# and Num_Found <= rr_type.MaxNumRecords
            --# and Integer(Start_Byte) <= DNS_Types.Packet_Size
            --# and Answer_Count = Answer_Count~
            --# and Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords)
            --# and Integer(Current_Byte) < (DNS_Types.Packet_Size-(12+DNS_Types.Header_Bits/8))-
            --#    (Current_Name_Length)
            --# and Current_Byte >= 0;
            -- PTR to character of message
            Set_Unsigned_16(Output_Packet.Bytes,Current_Byte+1,Unsigned_Types.Unsigned16(Qname_Location)+16#C000#);
            -- PTR
            Output_Packet.Bytes(Current_Byte+3) := 16#00#;
            Output_Packet.Bytes(Current_Byte+4) := 16#0C#;
            -- IN
            Output_Packet.Bytes(Current_Byte+5) := 16#00#;
            Output_Packet.Bytes(Current_Byte+6) := 16#01#;
            Set_TTL_Data_PTR_Response(Output_Packet.Bytes,Current_Byte+7,
               Replies(Response_Counter),Current_Name_Length);
            Response_Counter := Response_Counter + 1;
            Current_Byte := (Current_Byte + 12) + DNS_Types.Packet_Bytes_Range(Current_Name_Length);
            if Response_Counter <= Num_Found then
               Current_Name_Length := RR_Type.WireNameLength(Replies(Response_Counter).domainname);
            end if;
         end loop;
      end if;
      Output_Bytes := DNS_Types.Packet_Length_Range(Current_Byte + DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8));
      Answer_Count := Answer_Count + DNS_Types.Unsigned_Short(Num_Found);
      -- accept Flow, 602, Output_Packet, Replies,  "initialization is unneeded";
      -- accept Flow, 602, Output_Bytes, Replies,  "initialization is unneeded";
   end Create_Response_PTR;

   procedure Create_Response_MX(
         Start_Byte      : in DNS_Types.Packet_Bytes_Range;
         Domainname      : in RR_Type.WireStringType;
         Num_Found       : out RR_Type.NumberOfRecordsType;
         Qname_Location  : in DNS_Types.QNAME_PTR_RANGE;
         Qname_Locations : out QNAME_PTR_RANGE_Array;
         Replies         : out RR_Type.mx_record_type.MXRecordBucketType;
         Output_Packet   : in out DNS_Types.DNS_Packet;
         Answer_Count    : in out DNS_Types.Unsigned_Short;
         Output_Bytes    : out DNS_Types.Packet_Length_Range) is
      Response_Counter : Natural;
      Current_Byte  : DNS_Types.Packet_Bytes_Range;
      Current_Name_Length : RR_Type.WireStringTypeIndex;
   begin
      Qname_Locations := QNAME_PTR_RANGE_Array'(others => 0);
      Current_Byte := Start_Byte;
      -- accept Flow, 23, Replies, "it will fill in enough";
      DNS_Table_Pkg.DNS_Table.QueryMXRecords(
         DomainName      => Domainname,
         ReturnedRecords => Replies,
         HowMany         => Num_Found);
      -- end accept;
      if Num_Found>=1 then
         Response_Counter := 1;
         Current_Name_Length := RR_Type.WireNameLength(Replies(Response_Counter).mailExchanger);
         while Response_Counter <= Num_Found and then
            Integer(Current_Byte) < (DNS_Types.Packet_Size-(14+DNS_Types.Header_Bits/8))-
               (Current_Name_Length) loop
            --# assert Response_Counter >=1 and Response_Counter <= Num_Found
            --# and current_name_length >=1 and current_name_length<=rr_type.WireStringTypeIndex'last
            --# and Num_Found <= rr_type.MaxNumRecords
            --# and Integer(Start_Byte) <= DNS_Types.Packet_Size
            --# and Answer_Count = Answer_Count~
            --# and Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords)
            --# and Integer(Current_Byte) < (DNS_Types.Packet_Size-(14+DNS_Types.Header_Bits/8))-
            --#    (Current_Name_Length)
            --# and Current_Byte >= 0;
            -- PTR to character of message
            Set_Unsigned_16(Output_Packet.Bytes,Current_Byte+1,Unsigned_Types.Unsigned16(Qname_Location)+16#C000#);
            -- MX
            Output_Packet.Bytes(Current_Byte+3) := 16#00#;
            Output_Packet.Bytes(Current_Byte+4) := 16#0F#;
            -- IN
            Output_Packet.Bytes(Current_Byte+5) := 16#00#;
            Output_Packet.Bytes(Current_Byte+6) := 16#01#;
            Qname_Locations(Response_Counter) := DNS_Types.QNAME_PTR_RANGE(
               (Current_Byte+14)+ DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8));
            Set_TTL_Data_MX_Response(Output_Packet.Bytes,Current_Byte+7,
               Replies(Response_Counter),Current_Name_Length);
            Response_Counter := Response_Counter + 1;
            Current_Byte := (Current_Byte + 14) + DNS_Types.Packet_Bytes_Range(Current_Name_Length);
            if Response_Counter <= Num_Found then
               Current_Name_Length := RR_Type.WireNameLength(Replies(Response_Counter).mailExchanger);
            end if;
         end loop;
      end if;
      Output_Bytes := DNS_Types.Packet_Length_Range(Current_Byte + DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8));
      Answer_Count := Answer_Count + DNS_Types.Unsigned_Short(Num_Found);
      -- accept Flow, 602, Output_Packet, Replies,  "initialization is unneeded";
      -- accept Flow, 602, Output_Bytes, Replies,  "initialization is unneeded";
      -- accept Flow, 602, Replies, Replies,  "initialization is unneeded";
      -- accept Flow, 602, Qname_Locations, Replies,  "initialization is unneeded";
   end Create_Response_MX;

   procedure Create_Response_SRV(
         Start_Byte      : in DNS_Types.Packet_Bytes_Range;
         Domainname      : in RR_Type.WireStringType;
         Num_Found       : out RR_Type.NumberOfRecordsType;
         Qname_Location  : in DNS_Types.QNAME_PTR_RANGE;
         Qname_Locations : out QNAME_PTR_RANGE_Array;
         Replies         : out RR_Type.srv_record_type.SRVRecordBucketType;
         Output_Packet   : in out DNS_Types.DNS_Packet;
         Answer_Count    : in out DNS_Types.Unsigned_Short;
         Output_Bytes    : out DNS_Types.Packet_Length_Range) is
      Response_Counter : Natural;
      Current_Byte  : DNS_Types.Packet_Bytes_Range;
      Current_Name_Length : RR_Type.WireStringTypeIndex;
   begin
      Qname_Locations := QNAME_PTR_RANGE_Array'(others => 0);
      Current_Byte := Start_Byte;
      -- accept Flow, 23, Replies, "it will fill in enough";
      DNS_Table_Pkg.DNS_Table.QuerySRVRecords(
         DomainName      => Domainname,
         ReturnedRecords => Replies,
         HowMany         => Num_Found);
      -- end accept;
      if Num_Found>=1 then
         Response_Counter := 1;
         Current_Name_Length := RR_Type.WireNameLength(Replies(Response_Counter).ServerName);
         while Response_Counter <= Num_Found and then
            Integer(Current_Byte) < (DNS_Types.Packet_Size-(18+DNS_Types.Header_Bits/8))-
               (Current_Name_Length) loop
            --# assert Response_Counter >=1 and Response_Counter <= Num_Found
            --# and current_name_length >=1 and current_name_length<=rr_type.WireStringTypeIndex'last
            --# and Num_Found <= rr_type.MaxNumRecords
            --# and Integer(Start_Byte) <= DNS_Types.Packet_Size
            --# and Answer_Count = Answer_Count~
            --# and Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords)
            --# and Integer(Current_Byte) < (DNS_Types.Packet_Size-(18+DNS_Types.Header_Bits/8))-
            --#    (Current_Name_Length)
            --# and Current_Byte >= 0;
            -- PTR to character of message
            Set_Unsigned_16(Output_Packet.Bytes,Current_Byte+1,Unsigned_Types.Unsigned16(Qname_Location)+16#C000#);
            -- SRV
            Output_Packet.Bytes(Current_Byte+3) := 16#00#;
            Output_Packet.Bytes(Current_Byte+4) := 16#21#;
            -- IN
            Output_Packet.Bytes(Current_Byte+5) := 16#00#;
            Output_Packet.Bytes(Current_Byte+6) := 16#01#;
            Qname_Locations(Response_Counter) := DNS_Types.QNAME_PTR_RANGE(
               (Current_Byte+18)+ DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8)); -- offset = 18
            Set_TTL_Data_SRV_Response(Output_Packet.Bytes,Current_Byte+7,
               Replies(Response_Counter),Current_Name_Length);
            Response_Counter := Response_Counter + 1;
            Current_Byte := (Current_Byte + 18) + DNS_Types.Packet_Bytes_Range(Current_Name_Length); --  offset = 18
            if Response_Counter <= Num_Found then
               Current_Name_Length := RR_Type.WireNameLength(Replies(Response_Counter).serverName);
            end if;
         end loop;
      end if;
      Output_Bytes := DNS_Types.Packet_Length_Range(Current_Byte + DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8));
      Answer_Count := Answer_Count + DNS_Types.Unsigned_Short(Num_Found);
      -- accept Flow, 602, Output_Packet, Replies,  "initialization is unneeded";
      -- accept Flow, 602, Output_Bytes, Replies,  "initialization is unneeded";
      -- accept Flow, 602, Replies, Replies,  "initialization is unneeded";
      -- accept Flow, 602, Qname_Locations, Replies,  "initialization is unneeded";
   end Create_Response_SRV;

   procedure Create_Response_SOA(
         Start_Byte      : in DNS_Types.Packet_Bytes_Range;
         Domainname      : in RR_Type.WireStringType;
         Qname_Location  : in DNS_Types.QNAME_PTR_RANGE;
         Output_Packet   : in out DNS_Types.DNS_Packet;
         Answer_Count    : in out DNS_Types.Unsigned_Short;
         Output_Bytes    : out DNS_Types.Packet_Length_Range) is
      Response_Counter       : Natural;
      Current_Byte           : DNS_Types.Packet_Bytes_Range;
      Nameserver_Name_Length : RR_Type.WireStringTypeIndex;
      Mailbox_Name_Length    : RR_Type.WireStringTypeIndex;
      Num_Found              : RR_Type.NumberOfRecordsType;
      Replies                : RR_Type.SOA_record_type.SOARecordBucketType;
   begin
      Current_Byte := Start_Byte;
      -- accept Flow, 23, Replies, "it will fill in enough";
      DNS_Table_Pkg.DNS_Table.QuerySOARecords(
         DomainName      => Domainname,
         ReturnedRecords => Replies,
         HowMany         => Num_Found);
      -- end accept;
      if Num_Found>=1 then
         Response_Counter := 1;
         Nameserver_Name_Length := RR_Type.WireNameLength(Replies(Response_Counter).nameserver);
         Mailbox_Name_Length := RR_Type.WireNameLength(Replies(Response_Counter).email);
         if Integer(Current_Byte) < (DNS_Types.Packet_Size-(32+DNS_Types.Header_Bits/8))-
               (Nameserver_Name_Length+Mailbox_Name_Length) then
            -- PTR to character of message
            Set_Unsigned_16(Output_Packet.Bytes,Current_Byte+1,Unsigned_Types.Unsigned16(Qname_Location)+16#C000#);
            -- SOA
            Output_Packet.Bytes(Current_Byte+3) := 16#00#;
            Output_Packet.Bytes(Current_Byte+4) := 16#06#;
            -- IN
            Output_Packet.Bytes(Current_Byte+5) := 16#00#;
            Output_Packet.Bytes(Current_Byte+6) := 16#01#;
            Set_TTL_Data_SOA_Response(Output_Packet.Bytes,Current_Byte+7,
               Replies(Response_Counter),Nameserver_Name_Length,Mailbox_Name_Length);
            Current_Byte := (Current_Byte + 32) + DNS_Types.Packet_Bytes_Range(
               Nameserver_Name_Length+Mailbox_name_Length);
         end if;
      end if;
      Output_Bytes := DNS_Types.Packet_Length_Range(Current_Byte + DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8));
      Answer_Count := Answer_Count + DNS_Types.Unsigned_Short(Num_Found);
      -- accept Flow, 602, Output_Packet, Replies,  "initialization is unneeded";
      -- accept Flow, 602, Output_Bytes, Replies,  "initialization is unneeded";
   end Create_Response_SOA;


   procedure Process_Response_Cname(
         Start_Byte     : in DNS_Types.Packet_Bytes_Range;
         Cnames         : in RR_Type.cname_record_type.CNAMERecordBucketType;
         Domainname     : out RR_Type.WireStringType;
         Qname_Location : in out DNS_Types.QNAME_PTR_RANGE;
         Output_Packet  : in out DNS_Types.DNS_Packet;
         Output_Bytes   : out DNS_Types.Packet_Length_Range) is
      Current_Byte  : DNS_Types.Packet_Bytes_Range;
      Name_Length : RR_Type.WireStringTypeIndex;
      I : RR_Type.WireStringTypeIndex;
   begin
--      Cnames(Cnames'First).CanonicalDomainName := Character'Val(8) & "carlisle" & Character'Val(4) &
--         "dfcs" & Character'Val(5) & "usafa" & Character'Val(3) & "edu" & Character'Val(0) &
--         "       ";
      Current_Byte := Start_Byte;
      Domainname := Cnames(Cnames'First).CanonicalDomainName;
      Name_Length := RR_Type.WirenameLength(Cnames(Cnames'First).CanonicalDomainName);
      if Integer(Current_Byte) < DNS_Types.Packet_Size-(12+DNS_Types.Header_Bits/8) then
         -- PTR to character of message
         Set_Unsigned_16(Output_Packet.Bytes,Current_Byte+1,Unsigned_Types.Unsigned16(Qname_Location)+16#C000#);
         -- CNAME
         Output_Packet.Bytes(Current_Byte+3) := 16#00#;
         Output_Packet.Bytes(Current_Byte+4) := 16#05#;
         -- IN
         Output_Packet.Bytes(Current_Byte+5) := 16#00#;
         Output_Packet.Bytes(Current_Byte+6) := 16#01#;
            -- TTL
         Set_Unsigned_32(Output_Packet.Bytes,Current_Byte+7,Cnames(Cnames'First).TtlInSeconds);
         Set_Unsigned_16(Output_Packet.Bytes,Current_Byte+11,Unsigned_Types.Unsigned16(Name_Length));
         Current_Byte := Current_Byte + 12;
      end if;
      Qname_Location := DNS_Types.QNAME_PTR_RANGE(
         (Integer(Current_Byte)) + DNS_Types.Header_Bits/8);
      I := 1;
      while I<=Name_Length and I<RR_Type.WireStringTypeIndex'Last and
            Integer(Current_Byte)+DNS_Types.Header_Bits/8<DNS_Types.Packet_Size loop
         --# assert I<RR_Type.WireStringTypeIndex'Last and
         --#        I<=Name_Length and
         --#        Output_Packet.Header.ANCount = 0 and
         --#        Current_Byte >= Start_Byte and
         --#        Integer(Current_Byte)+DNS_Types.Header_Bits/8<DNS_Types.Packet_Size;
         Current_Byte := Current_Byte + 1;
         Output_Packet.Bytes(Current_Byte) := DNS_Types.Byte(Character'Pos(Cnames(Cnames'First).CanonicalDomainName(I)));
         I := I + 1;
      end loop;
      Output_Bytes := DNS_Types.Packet_Length_Range(Current_Byte + DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8));
      Output_Packet.Header.ANCount := Output_Packet.Header.ANCount + 1;
   end Process_Response_Cname;

   procedure Trim_Name(
         Domainname         : in RR_Type.WireStringType;
         Trimmed_name       : out RR_Type.WireStringType;
         Qname_Location     : in DNS_Types.QNAME_PTR_RANGE;
         New_Qname_Location : out DNS_Types.QNAME_PTR_RANGE) is
      Zone_Length : Natural;
   begin
      Zone_Length := natural(character'pos(domainname(domainname'first))+1);
      Trimmed_Name := RR_Type.WireStringType'(others => ' ');
      New_Qname_Location := Qname_Location;
      if Zone_Length > 0 and Zone_Length < Rr_Type.WireStringTypeIndex'Last then
         New_Qname_Location := New_Qname_Location + DNS_Types.QNAME_PTR_RANGE(Zone_Length);
         -- the assertion below is kind of interesting b/c we need to tell SPARK
         -- that zone_Length hasn't changed, and I don't really use it in the loop
         for I in RR_Type.WireStringTypeIndex range 1..RR_Type.WireStringTypeIndex'Last-natural(character'pos(domainname(domainname'first))+1) loop
            --# assert I+Zone_Length<=RR_Type.WireStringTypeIndex'Last and I>=1 and
            --# zone_length = natural(character'pos(domainname(domainname'first))+1);
            Trimmed_Name(I) := Domainname(I+natural(character'pos(domainname(domainname'first))+1));
         end loop;
      end if;
   end Trim_Name;

   procedure Create_NXDOMAIN_Response(
         Start_Byte      : in DNS_Types.Packet_Bytes_Range;
         Domainname      : in RR_Type.WireStringType;
         Qname_Location  : in DNS_Types.QNAME_PTR_RANGE;
         Output_Packet   : in out DNS_Types.DNS_Packet;
         Output_Bytes    : out DNS_Types.Packet_Length_Range) is
      Answer_Count    : DNS_Types.Unsigned_Short := 0;
      Amount_Trimmed  : Natural := 0;
      Trimmed_Name : RR_Type.WireStringType;
      Current_Name : RR_Type.WireStringType;
      Current_Qname_Location : DNS_Types.QNAME_PTR_RANGE;
      New_Qname_Location : DNS_Types.QNAME_PTR_RANGE;
   begin
      Current_Qname_Location := Qname_Location;
      Output_Bytes := DNS_Types.Packet_Length_Range(Start_Byte + DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8));
      Current_Name := Domainname;
      Output_Packet.Header.RCODE   := DNS_Types.Name_Error;
      Output_Packet.Header.ANCount := 0;

      -- Amount_Trimmed is used to guarantee we don't end up in an infinite loop
      while Answer_Count=0 and Amount_Trimmed<RR_Type.WireStringType'Last and
            Natural(Character'Pos(Current_Name(Current_Name'First)))/=0 and
            Current_Qname_Location <= DNS_Types.QNAME_PTR_RANGE(Output_Bytes) loop
         --# assert Answer_Count=0 and Amount_Trimmed>=0 and Amount_Trimmed<RR_Type.WireStringType'Last
         --# and Output_Bytes <= DNS_Types.Packet_Length_Range'Last
         --# and Current_Qname_Location <= DNS_Types.QNAME_PTR_RANGE(Output_Bytes);
         Trim_Name(
            Domainname         => Current_Name,
            Trimmed_Name       => Trimmed_Name,
            Qname_Location     => Current_Qname_Location,
            New_Qname_Location => New_Qname_Location);
         Create_Response_SOA(
            Start_Byte      => Start_Byte,
            Domainname      => Trimmed_name,
            Qname_Location  => New_Qname_Location,
            Output_Packet   => Output_Packet,
            Answer_Count    => Answer_Count,
            Output_Bytes    => Output_Bytes);
         Current_Name := Trimmed_Name;
         Current_Qname_Location := New_Qname_Location;
         Amount_Trimmed := Amount_Trimmed + Natural(Character'Pos(Domainname(Domainname'First))+1);
      end loop;
      if Answer_Count >= 1 then
         Output_Packet.Header.AA := True;
      end if;
      Output_Packet.Header.NSCount := Answer_Count;
   end Create_NXDOMAIN_Response;

   -- if we get in an EDNS option, we will add a response in kind
   procedure Create_Response_EDNS(
         Input_Packet       : in DNS_Types.DNS_Packet;
         Input_Bytes        : in DNS_Types.Packet_Length_Range;
         Query_End_Byte     : in DNS_Types.Packet_Bytes_Range;
         Start_Byte         : in DNS_Types.Packet_Bytes_Range;
         Output_Packet      : in out DNS_Types.DNS_Packet;
         Output_Bytes       : out DNS_Types.Packet_Length_Range;
         Additional_Count   : in out DNS_Types.Unsigned_Short;
         DNSSEC             : out Boolean;
         Max_Transmit       : out DNS_Types.Packet_Length_Range) is
      EDNS_Rec : DNS_Types.EDNS_Record;
      function To_Query_Type is new Ada.Unchecked_Conversion(DNS_Types.Unsigned_Short,DNS_Types.Query_Type);
      function From_Query_Type is new Ada.Unchecked_Conversion(DNS_Types.Query_Type,DNS_Types.Unsigned_Short);
   begin
      Max_Transmit := DNS_Types.UDP_Max_Size;
      Output_Bytes := DNS_Types.Packet_Length_Range(Start_Byte + DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8));
      DNSSEC := False;

      -- if there's more to the packet, check for the OPT code
      if (Integer(Query_End_Byte)+11)+(DNS_Types.Header_Bits/8)<=Integer(Input_Bytes) and
         (Integer(Start_Byte)+11)+(DNS_Types.Header_Bits/8)<DNS_Types.Packet_Size then
         EDNS_Rec.Root    := Character'Val(Input_Packet.Bytes(Query_End_Byte+1));
         --# accept Warning, 12, To_Query_Type, "unchecked conversions ok";
         EDNS_Rec.Code    := To_Query_Type(DNS_Types.Unsigned_Short(
            Input_Packet.Bytes(Query_End_Byte+2))*256+
            DNS_Types.Unsigned_Short(Input_Packet.Bytes(Query_End_Byte+3)));
         if EDNS_Rec.Root = Character'Val(0) and
            EDNS_Rec.Code = DNS_Types.OPT then
            EDNS_Rec.Payload_Size := DNS_Types.Unsigned_Short(Input_Packet.Bytes(
               Query_End_Byte+4))*256+
               DNS_Types.Unsigned_Short(Input_Packet.Bytes(Query_End_Byte+5));
            --EDNS_Rec.RCODE   := Input_Packet.Bytes(Query_End_Byte+6);
            --EDNS_Rec.Version := Input_Packet.Bytes(Query_End_Byte+7);
            EDNS_Rec.ZTop    := Input_Packet.Bytes(Query_End_Byte+8);
            --EDNS_Rec.ZBottom := Input_Packet.Bytes(Query_End_Byte+9);
            --EDNS_Rec.RDLEN    := DNS_Types.Unsigned_Short(
            --   Input_Packet.Bytes(Query_End_Byte+10))*256+
            --   DNS_Types.Unsigned_Short(Input_Packet.Bytes(Query_End_Byte+11));

            -- when we respond, we'll respond with AT LEAST UDP_Max_Size,
            -- but no bigger than our Packet_Size
            Max_Transmit := DNS_Types.Packet_Length_Range(
               DNS_Types.Unsigned_Short'Min(DNS_Types.Packet_Size,
               EDNS_Rec.Payload_Size));
            Max_Transmit := DNS_Types.Packet_Length_Range'Max(
               DNS_Types.UDP_Max_Size, Max_Transmit);

            Output_Packet.Bytes(Start_Byte+1) := 0;
            -- high order byte of OPT is 0
            Output_Packet.Bytes(Start_Byte+2) := 0;
            -- the mod here is superfluous as OPT = 41
            --# accept Warning, 12, From_Query_Type, "unchecked conversions ok";
            Output_Packet.Bytes(Start_Byte+3) := DNS_Types.Byte(
               From_Query_Type(DNS_Types.OPT) mod 256);

            -- split unsigned short into two bytes
            Output_Packet.Bytes(Start_Byte+4) := DNS_Types.Byte(
               Max_Transmit/256);
            Output_Packet.Bytes(Start_Byte+5) := DNS_Types.Byte(
               Max_Transmit mod 256);

            Output_Packet.Bytes(Start_Byte+6) := 0;
            Output_Packet.Bytes(Start_Byte+7) := 0;
            -- FLAGS (DNSSEC ONLY), see RFC 3225
            if (EDNS_Rec.ZTop and Dns_Types.DNSSECMASK) /= 0 then
               Output_Packet.Bytes(Start_Byte+8) := Dns_Types.DNSSECMASK;
               DNSSEC := True;
            else
               Output_Packet.Bytes(Start_Byte+8) := 0;
            end if;
            Output_Packet.Bytes(Start_Byte+9) := 0;
            -- RDLEN = 0
            Output_Packet.Bytes(Start_Byte+10) := 0;
            Output_Packet.Bytes(Start_Byte+11) := 0;

            Additional_Count := Additional_Count + 1;
            Output_Bytes := DNS_Types.Packet_Length_Range((Start_Byte + 11) +
               DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8));
         end if;
      end if;
   end Create_Response_EDNS;

   procedure Create_Response(
         Input_Packet  : in DNS_Types.DNS_Packet;
         Input_Bytes   : in DNS_Types.Packet_Length_Range;
         Output_Packet : in out DNS_Types.DNS_Packet;
         Output_Bytes  : out DNS_Types.Packet_Length_Range;
         Max_Transmit  : out DNS_Types.Packet_Length_Range) is
      Start_Byte    : DNS_Types.Packet_Bytes_Range;
      Query_End_Byte : DNS_Types.Packet_Bytes_Range;
      Domainname : RR_Type.WireStringType;
      Query_Type : DNS_Types.Query_Type;
      Query_Class : DNS_Types.Query_Class;
      NumFound : Natural;
      Counter  : Natural;
      Qname_Location : DNS_Types.QNAME_PTR_RANGE := 12;
      Qname_Locations : QNAME_PTR_RANGE_Array;
      ReturnedCNAMERecords : Rr_Type.CNAME_Record_Type.CNAMERecordBucketType;
      NS_Replies      : RR_Type.Ns_Record_Type.NSRecordBucketType;
      MX_Replies      : RR_Type.MX_Record_Type.MXRecordBucketType;
      SRV_Replies     : RR_Type.srv_record_type.SRVRecordBucketType;
      Answer_Count     : DNS_Types.Unsigned_Short;
      Additional_Count : DNS_Types.Unsigned_Short;
      DNSSEC           : Boolean;
   begin

      -- I would like to only copy the header here, but I get a flow error!!
      --# accept Flow, 10, Output_Packet.Header.QR,
      --#   "The rest of the header fields retain their newly assigned values";
      --# accept Flow, 10, Output_Packet.Header.ANCOUNT,
      --#   "The rest of the header fields retain their newly assigned values";
      --# accept Flow, 10, Output_Packet.Header.AA,
      --#   "The rest of the header fields retain their newly assigned values";
      -- accept Flow, 10, Output_Packet.Header.RCODE,
      --   "The rest of the header fields retain their newly assigned values";
      Output_Packet.Header := Input_Packet.Header;
      Output_Packet.Header.AA := False;
      --# end accept;
      --# end accept;
      --# end accept;
      -- end accept;
      Output_Packet.Header.QR := True;
      -- Keep # of queries and send the query back!! (i.e. don't do line below)
      -- Response_Header.QDCOUNT := 0;

      --# assert Integer(Input_Bytes) >=DNS_Types.Header_Bits/8+1
      --# and Qname_Location >=0 and Qname_Location < 16384
      --# and Integer(Input_Bytes) < 312;
      Get_Query_Name_Type_Class(Input_Packet, Input_Bytes, Domainname, Query_Type, Query_Class, Query_End_Byte);
      Start_Byte := Query_End_Byte;
      --Start_Byte := DNS_Types.Packet_Bytes_Range(Input_Bytes) -
      --   DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8);
      for I in DNS_Types.Packet_Bytes_Range range 1..Start_Byte loop
         --# assert Integer(Input_Bytes) >=DNS_Types.Header_Bits/8
         --# and Qname_Location >=0 and Qname_Location < 16384
         --# and Integer(Input_Bytes) < 312
         --# and Start_Byte <= DNS_Types.Packet_Bytes_Range(Input_Bytes) and Start_Byte >= 4;
         Output_Packet.Bytes(I) := Input_Packet.Bytes(I);
      end loop;

      -- we start out with no responses
      Output_Packet.Header.ANCount := 0;

      -- accept Flow, 23, ReturnedCNAMERecords, "it will fill in enough";
      DNS_Table_Pkg.DNS_Table.QueryCNAMERecords(DomainName => Domainname,
         ReturnedRecords => ReturnedCNAMERecords, HowMany => NumFound);
      -- end accept;
      if NumFound>1 then
         Protected_SPARK_IO_05.SPARK_IO_PO.Put_Line(Protected_SPARK_IO_05.SPARK_IO_PO.Standard_Output,"more than one cname?", 0);
      elsif NumFound=1 then
         Process_Response_Cname(
            Start_Byte     => Start_Byte,
            Cnames         => ReturnedCNAMERecords,
            Domainname     => Domainname,
            Qname_Location => Qname_Location,
            Output_Packet  => Output_Packet,
            Output_Bytes   => Output_Bytes);
         Start_Byte := DNS_Types.Packet_Bytes_Range(Integer(Output_Bytes) -
            DNS_Types.Header_Bits/8);
      end if;
      Answer_Count := Output_Packet.Header.ANCount;
      Additional_Count := 0;
      --ada.text_io.put_line("numfound: " & integer'image(numfound));
      if Query_Class /= DNS_Types.IN_CLASS then
         Protected_SPARK_IO_05.SPARK_IO_PO.Put_Line(Protected_SPARK_IO_05.SPARK_IO_PO.Standard_Output,"bad query class", 0);
--            ada.text_io.put_line("qc: " & dns_types.Query_Class'image(Query_Class));
         Create_Response_Error(
            Input_Bytes   => Input_Bytes,
            Output_Packet => Output_Packet,
            Output_Bytes  => Output_Bytes);
      elsif Query_Type = DNS_Types.ANY then
         Create_Response_A(
            Start_Byte     => Start_Byte,
            Domainname     => Domainname,
            Qname_Location => Qname_Location,
            Output_Packet  => Output_Packet,
            Answer_Count   => Answer_Count,
            Output_Bytes   => Output_Bytes);
         Start_Byte := DNS_Types.Packet_Bytes_Range(Integer(Output_Bytes) -
            DNS_Types.Header_Bits/8);
         Create_Response_AAAA(
            Start_Byte     => Start_Byte,
            Domainname     => Domainname,
            Qname_Location => Qname_Location,
            Output_Packet  => Output_Packet,
            Answer_Count   => Answer_Count,
            Output_Bytes   => Output_Bytes);
         Start_Byte := DNS_Types.Packet_Bytes_Range(Integer(Output_Bytes) -
            DNS_Types.Header_Bits/8);
--# accept Flow, 10, MX_Replies, "not needed for ANY query";
--# accept Flow, 10, Qname_Locations, "not needed for ANY query";
--# accept Flow, 10, NumFound, "not needed for any query";
         Create_Response_MX(
            Start_Byte      => Start_Byte,
            Domainname      => Domainname,
            Num_Found       => NumFound,
            Qname_Location  => Qname_Location,
            Qname_Locations => Qname_Locations,
            Replies         => MX_Replies,
            Output_Packet   => Output_Packet,
            Answer_Count    => Answer_Count,
            Output_Bytes    => Output_Bytes);
--# end accept;
--# end accept;
--# end accept;
         Start_Byte := DNS_Types.Packet_Bytes_Range(Integer(Output_Bytes) -
            DNS_Types.Header_Bits/8);
--# accept Flow, 10, NS_Replies, "not needed for ANY query";
--# accept Flow, 10, Qname_Locations, "not needed for ANY query";
--# accept Flow, 10, NumFound, "not needed for any query";
         Create_Response_NS(
            Start_Byte      => Start_Byte,
            Domainname      => Domainname,
            Num_Found       => NumFound,
            Qname_Location  => Qname_Location,
            Qname_Locations => Qname_Locations,
            Replies         => NS_Replies,
            Output_Packet   => Output_Packet,
            Answer_Count    => Answer_Count,
            Output_Bytes    => Output_Bytes);
--# end accept;
--# end accept;
--# end accept;
         Start_Byte := DNS_Types.Packet_Bytes_Range(Integer(Output_Bytes) -
            DNS_Types.Header_Bits/8);
--# accept Flow, 10, SRV_Replies, "not needed for ANY query";
--# accept Flow, 10, Qname_Locations, "not needed for ANY query";
--# accept Flow, 10, NumFound, "not needed for any query";
         Create_Response_SRV(
            Start_Byte      => Start_Byte,
            Domainname      => Domainname,
            Num_Found       => NumFound,
            Qname_Location  => Qname_Location,
            Qname_Locations => Qname_Locations,
            Replies         => SRV_Replies,
            Output_Packet   => Output_Packet,
            Answer_Count    => Answer_Count,
            Output_Bytes    => Output_Bytes);
--# end accept;
--# end accept;
--# end accept;
         Start_Byte := DNS_Types.Packet_Bytes_Range(Integer(Output_Bytes) -
            DNS_Types.Header_Bits/8);
         Create_Response_PTR(
            Start_Byte      => Start_Byte,
            Domainname      => Domainname,
            Qname_Location  => Qname_Location,
            Output_Packet   => Output_Packet,
            Answer_Count    => Answer_Count,
            Output_Bytes    => Output_Bytes);
         Start_Byte := DNS_Types.Packet_Bytes_Range(Integer(Output_Bytes) -
            DNS_Types.Header_Bits/8);
         Create_Response_SOA(
            Start_Byte      => Start_Byte,
            Domainname      => Domainname,
            Qname_Location  => Qname_Location,
            Output_Packet   => Output_Packet,
            Answer_Count    => Answer_Count,
            Output_Bytes    => Output_Bytes); --DNS_Types.ANY
      elsif Query_Type = DNS_Types.SOA then
         Create_Response_SOA(
            Start_Byte      => Start_Byte,
            Domainname      => Domainname,
            Qname_Location  => Qname_Location,
            Output_Packet   => Output_Packet,
            Answer_Count    => Answer_Count,
            Output_Bytes    => Output_Bytes);
      elsif Query_Type = DNS_Types.PTR then
         Create_Response_PTR(
            Start_Byte      => Start_Byte,
            Domainname      => Domainname,
            Qname_Location  => Qname_Location,
            Output_Packet   => Output_Packet,
            Answer_Count    => Answer_Count,
            Output_Bytes    => Output_Bytes);
      elsif Query_Type = DNS_Types.A then
         Create_Response_A(
            Start_Byte     => Start_Byte,
            Domainname     => Domainname,
            Qname_Location => Qname_Location,
            Output_Packet  => Output_Packet,
            Answer_Count   => Answer_Count,
            Output_Bytes   => Output_Bytes);
      elsif Query_Type = DNS_Types.AAAA then
         Create_Response_AAAA(
            Start_Byte     => Start_Byte,
            Domainname     => Domainname,
            Qname_Location => Qname_Location,
            Output_Packet  => Output_Packet,
            Answer_Count   => Answer_Count,
            Output_Bytes   => Output_Bytes);
      elsif Query_Type = DNS_Types.DNSKEY then   --BSF 24 Aug 2012
         Create_Response_DNSKEY(
            Start_Byte     => Start_Byte,
            Domainname     => Domainname,
            Qname_Location => Qname_Location,
            Output_Packet  => Output_Packet,
            Answer_Count   => Answer_Count,
            Output_Bytes   => Output_Bytes);
      elsif Query_Type = DNS_Types.NSEC then   --BSF 2 Oct 2012
         Create_Response_NSEC(
            Start_Byte     => Start_Byte,
            Domainname     => Domainname,
            Qname_Location => Qname_Location,
            Output_Packet  => Output_Packet,
            Answer_Count   => Answer_Count,
            Output_Bytes   => Output_Bytes);
      elsif Query_Type = DNS_Types.RRSIG then   --BSF 11 Sep 2012
         Create_Response_RRSIG(
            Start_Byte     => Start_Byte,
            Domainname     => Domainname,
            Qname_Location => Qname_Location,
            Output_Packet  => Output_Packet,
            Answer_Count   => Answer_Count,
            Output_Bytes   => Output_Bytes);
      elsif Query_Type = DNS_Types.MX then
         Create_Response_MX(
            Start_Byte      => Start_Byte,
            Domainname      => Domainname,
            Num_Found       => NumFound,
            Qname_Location  => Qname_Location,
            Qname_Locations => Qname_Locations,
            Replies         => MX_Replies,
            Output_Packet   => Output_Packet,
            Answer_Count    => Answer_Count,
            Output_Bytes    => Output_Bytes);
         Counter := 1;
         Additional_Count := 0;
         while Counter <= NumFound and Additional_Count < DNS_Types.Unsigned_Short'Last-DNS_Types.Unsigned_Short(
               2*Rr_Type.MaxNumRecords) loop
            --# assert Counter >= 1 and Counter<=NumFound and
            --#    Answer_Count >=0 and Answer_Count <= 65535 and
            --#    Additional_Count >= 0 and
            --#    (for all Z in RR_Type.ReturnedRecordsIndexType =>
            --#       (Qname_Locations(Z) >= 0 and Qname_Locations(Z) < 16384)) and
            --#    Qname_Location >=0 and Qname_Location <= 16383 and
            --#    Additional_Count < DNS_Types.Unsigned_Short'Last-DNS_Types.Unsigned_Short(
            --#    2*Rr_Type.MaxNumRecords) and
            --#    NumFound >= 0 and NumFound <= rr_type.MaxNumRecords and
            --#    Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and
            --#    Integer(Output_Bytes) <= DNS_Types.Packet_Size;
            Start_Byte := DNS_Types.Packet_Bytes_Range(Integer(Output_Bytes) -
               DNS_Types.Header_Bits/8);
            Create_Response_A(
               Start_Byte     => Start_Byte,
               Domainname     => MX_Replies(Counter).mailExchanger,
               Qname_Location => Qname_Locations(Counter),
               Output_Packet  => Output_Packet,
               Answer_Count   => Additional_Count,
               Output_Bytes   => Output_Bytes);
            Start_Byte := DNS_Types.Packet_Bytes_Range(Integer(Output_Bytes) -
               DNS_Types.Header_Bits/8);
            Create_Response_AAAA(
               Start_Byte     => Start_Byte,
               Domainname     => MX_Replies(Counter).mailExchanger,
               Qname_Location => Qname_Locations(Counter),
               Output_Packet  => Output_Packet,
               Answer_Count   => Additional_Count,
               Output_Bytes   => Output_Bytes);
            Counter := Counter + 1;
         end loop;
      elsif Query_Type = DNS_Types.SRV then
         Create_Response_SRV(
            Start_Byte      => Start_Byte,
            Domainname      => Domainname,
            Num_Found       => NumFound,
            Qname_Location  => Qname_Location,
            Qname_Locations => Qname_Locations,
            Replies         => SRV_Replies,
            Output_Packet   => Output_Packet,
            Answer_Count    => Answer_Count,
            Output_Bytes    => Output_Bytes);
         Counter := 1;
         Additional_Count := 0;
         while Counter <= NumFound and Additional_Count < DNS_Types.Unsigned_Short'Last-DNS_Types.Unsigned_Short(
               2*Rr_Type.MaxNumRecords) loop
            --# assert Counter >= 1 and Counter<=NumFound and
            --#    Answer_Count >=0 and Answer_Count <= 65535 and
            --#    Additional_Count >= 0 and
            --#    (for all Z in RR_Type.ReturnedRecordsIndexType =>
            --#       (Qname_Locations(Z) >= 0 and Qname_Locations(Z) < 16384)) and
            --#    Qname_Location >=0 and Qname_Location <= 16383 and
            --#    Additional_Count < DNS_Types.Unsigned_Short'Last-DNS_Types.Unsigned_Short(
            --#    2*Rr_Type.MaxNumRecords) and
            --#    NumFound >= 0 and NumFound <= rr_type.MaxNumRecords and
            --#    Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and
            --#    Integer(Output_Bytes) <= DNS_Types.Packet_Size;
            Start_Byte := DNS_Types.Packet_Bytes_Range(Integer(Output_Bytes) -
               DNS_Types.Header_Bits/8);
            Create_Response_A(
               Start_Byte     => Start_Byte,
               Domainname     => SRV_Replies(Counter).servername,
               Qname_Location => Qname_Locations(Counter),
               Output_Packet  => Output_Packet,
               Answer_Count   => Additional_Count,
               Output_Bytes   => Output_Bytes);
            Start_Byte := DNS_Types.Packet_Bytes_Range(Integer(Output_Bytes) -
               DNS_Types.Header_Bits/8);
            Create_Response_AAAA(
               Start_Byte     => Start_Byte,
               Domainname     => SRV_Replies(Counter).servername,
               Qname_Location => Qname_Locations(Counter),
               Output_Packet  => Output_Packet,
               Answer_Count   => Additional_Count,
               Output_Bytes   => Output_Bytes);
            Counter := Counter + 1;
         end loop;
      elsif Query_Type = DNS_Types.NS then
         Create_Response_NS(
            Start_Byte      => Start_Byte,
            Domainname      => Domainname,
            Num_Found       => NumFound,
            Qname_Location  => Qname_Location,
            Qname_Locations => Qname_Locations,
            Replies         => NS_Replies,
            Output_Packet   => Output_Packet,
            Answer_Count    => Answer_Count,
            Output_Bytes    => Output_Bytes);
         Counter := 1;
         Additional_Count := 0;
         while Counter <= NumFound and Additional_Count < DNS_Types.Unsigned_Short'Last-DNS_Types.Unsigned_Short(
               2*Rr_Type.MaxNumRecords) loop
            --# assert Counter >= 1 and Counter<=NumFound and
            --#    (for all Z in RR_Type.ReturnedRecordsIndexType =>
            --#       (Qname_Locations(Z) >= 0 and Qname_Locations(Z) < 16384)) and
            --#    Qname_Location >=0 and Qname_Location <= 16383 and
            --#    Answer_Count >=0 and Answer_Count <= 65535 and
            --#    Additional_Count >= 0 and
            --#    Additional_Count < DNS_Types.Unsigned_Short'Last-DNS_Types.Unsigned_Short(
            --#    2*Rr_Type.MaxNumRecords) and
            --#    NumFound >= 0 and NumFound <= rr_type.MaxNumRecords and
            --#    Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and
            --#    Integer(Output_Bytes) <= DNS_Types.Packet_Size;
            Start_Byte := DNS_Types.Packet_Bytes_Range(Integer(Output_Bytes) -
               DNS_Types.Header_Bits/8);
            Create_Response_A(
               Start_Byte     => Start_Byte,
               Domainname     => NS_Replies(Counter).nameserver,
               Qname_Location => Qname_Locations(Counter),
               Output_Packet  => Output_Packet,
               Answer_Count   => Additional_Count,
               Output_Bytes   => Output_Bytes);
            Start_Byte := DNS_Types.Packet_Bytes_Range(Integer(Output_Bytes) -
               DNS_Types.Header_Bits/8);
            Create_Response_AAAA(
               Start_Byte     => Start_Byte,
               Domainname     => NS_Replies(Counter).nameserver,
               Qname_Location => Qname_Locations(Counter),
               Output_Packet  => Output_Packet,
               Answer_Count   => Additional_Count,
               Output_Bytes   => Output_Bytes);
            Counter := Counter + 1;
         end loop;
      else
         Protected_SPARK_IO_05.SPARK_IO_PO.Put_Line(Protected_SPARK_IO_05.SPARK_IO_PO.Standard_Output,"bad query type", 0);
--            ada.text_io.put_line("qc: " & dns_types.Query_Type'image(Query_Type));
         Create_Response_Error(
            Input_Bytes   => Input_Bytes,
            Output_Packet => Output_Packet,
            Output_Bytes  => Output_Bytes);
      end if;

      -- this assert helps with the VCG Heap overflow
      --# assert
      --#    Answer_Count >=0 and Answer_Count <= 65535 and
      --#    Qname_Location >=0 and Qname_Location < 16384 and
      --#    Additional_Count >= 0 and
      --#    NumFound >= 0 and NumFound <= rr_type.MaxNumRecords and
      --#    Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and
      --#    Integer(Output_Bytes) <= DNS_Types.Packet_Size;

      DNSSEC := False;
      Max_Transmit := DNS_Types.UDP_Max_Size;
      -- Handle EDNS additional OPT record here!
      if Input_Packet.Header.QDCount = 1 and
         Input_Packet.Header.ARCount = 1 and
         Additional_Count < DNS_Types.Unsigned_Short'Last then
         Start_Byte := DNS_Types.Packet_Bytes_Range(Integer(Output_Bytes) -
            DNS_Types.Header_Bits/8);
         Create_Response_EDNS(
            Input_Packet     => Input_Packet,
            Input_Bytes      => Input_Bytes,
            Query_End_Byte   => Query_End_Byte,
            Start_Byte       => Start_Byte,
            Output_Packet    => Output_Packet,
            Output_Bytes     => Output_Bytes,
            Additional_Count => Additional_Count,
            DNSSEC           => DNSSEC,
            Max_Transmit     => Max_Transmit);
      elsif Input_Packet.Header.QDCount /= 1 then
         Protected_SPARK_IO_05.SPARK_IO_PO.Put_Line(Protected_SPARK_IO_05.SPARK_IO_PO.Standard_Output,"query count > 1", 0);
      elsif Input_Packet.Header.ARCount > 1 then
         Protected_SPARK_IO_05.SPARK_IO_PO.Put_Line(Protected_SPARK_IO_05.SPARK_IO_PO.Standard_Output,"ar count > 1", 0);
      end if;

      -- this assert helps with the VCG Heap overflow
      --# assert
      --#    Answer_Count >=0 and Answer_Count <= 65535 and
      --#    Qname_Location >=0 and Qname_Location < 16384 and
      --#    Additional_Count >= 0 and
      --#    NumFound >= 0 and NumFound <= rr_type.MaxNumRecords and
      --#    Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and
      --#    Integer(Max_Transmit) <= DNS_Types.Packet_Size and Max_Transmit >= DNS_Types.UDP_Max_Size and
      --#    Integer(Output_Bytes) <= DNS_Types.Packet_Size;


      if DNSSEC and Answer_Count > 0 then
         Output_Bytes := (Output_Bytes-1)+1;
      end if;

      Output_Packet.Header.ANCount := Answer_Count;
      Output_Packet.Header.ARCount := Additional_Count;
      if Answer_Count > 0 then
         -- our answer is authoritative
         Output_Packet.Header.AA := True;
         Output_Packet.Header.RCODE := DNS_Types.No_Error;
      elsif Output_Packet.Header.AA = False then
         Create_NXDOMAIN_Response(
            Start_Byte     => DNS_Types.Packet_Bytes_Range(Input_Bytes) -
               DNS_Types.Packet_Bytes_Range(DNS_Types.Header_Bits/8),
            Domainname     => Domainname,
            Qname_Location => Qname_Location,
            Output_Packet  => Output_Packet,
            Output_Bytes   => Output_Bytes);
      end if;
      -- accept Flow, 602, Output_Packet, ReturnedCNAMERecords, "initialization is unneeded";
      -- accept Flow, 602, Output_Bytes, ReturnedCNAMERecords, "initialization is unneeded";
   end Create_Response;


   procedure Process_Request_Tcp(
      Reply_Socket : in DNS_Network.DNS_Socket)
   is
      Input_Packet  : DNS_Types.DNS_Tcp_Packet;
      Input_Bytes   : DNS_Types.Packet_Length_Range;
      Output_Packet : DNS_Types.DNS_Tcp_Packet;
      Output_Bytes  : DNS_Types.Packet_Length_Range;
      Max_Transmit  : DNS_Types.Packet_Length_Range;
      Failure       : Boolean;
   begin
      --Output_Packet.Rest.Bytes := DNS_Types.Bytes_Array_Type'(others => 0);

      DNS_Network_Receive.Receive_DNS_Packet_Tcp(
         Packet        => Input_Packet,
         Number_Bytes  => Input_Bytes,
         Socket        => Reply_Socket,
         Failure       => Failure);
--      SPARK_IO_05.Put_Line(SPARK_IO_05.Standard_Output,"Input ID", 0);
--      SPARK_IO_05.Put_Integer(SPARK_IO_05.Standard_Output,
--         Integer(Input_Packet.Rest.Header.MessageID), 0, 16);
--      SPARK_IO_05.New_Line(SPARK_IO_05.Standard_Output,1);
      if Failure then
         --Protected_SPARK_IO_05.SPARK_IO_PO.Put_Line(Protected_SPARK_IO_05.SPARK_IO_PO.Standard_Output,"Receive failed", 0);
         null;
      else
         --Protected_SPARK_IO_05.SPARK_IO_PO.Put_Line(Protected_SPARK_IO_05.SPARK_IO_PO.Standard_Output,"got packet", 0);
         --# accept Flow, 23, Output_Packet.Rest, "init not needed";
         --# accept Flow, 10, Max_Transmit, "only needed for UDP";
         Create_Response(
            Input_Packet  => Input_Packet.Rest,
            Input_Bytes   => Input_Bytes,
            Output_Packet => Output_Packet.Rest,
            Output_Bytes  => Output_Bytes,
            Max_Transmit  => Max_Transmit);
         --# end accept;
         --# end accept;
         --Protected_SPARK_IO_05.SPARK_IO_PO.Put_Line(Protected_SPARK_IO_05.SPARK_IO_PO.Standard_Output,"Reply created", 0);
         --# accept Flow, 22,
         --#   "allow use of static expression for portability across platforms";
         if System.Default_Bit_Order=System.Low_Order_First then
         --# end accept;
            Output_Packet.Length := DNS_Types.Byte_Swap_US(DNS_Types.Unsigned_Short(Output_Bytes));
         else
            Output_Packet.Length := DNS_Types.Unsigned_Short(Output_Bytes);
         end if;
--         SPARK_IO_05.Put_Line(SPARK_IO_05.Standard_Output,"Output ID", 0);
--         SPARK_IO_05.Put_Integer(SPARK_IO_05.Standard_Output,
--            Integer(Output_Packet.Rest.Header.MessageID), 0, 16);
--         SPARK_IO_05.New_Line(SPARK_IO_05.Standard_Output,1);
--         Protected_SPARK_IO_05.SPARK_IO_PO.Put_Line(Protected_SPARK_IO_05.SPARK_IO_PO.Standard_Output,"sending", 0);

         DNS_Network.Send_DNS_Packet_Tcp(
            Packet       => Output_Packet,
            Number_Bytes => Output_Bytes,
            Socket       => Reply_Socket,
            Failure      => Failure);
         if Failure then
            Protected_SPARK_IO_05.SPARK_IO_PO.Put_Integer(Protected_SPARK_IO_05.SPARK_IO_PO.Standard_Output,
               Integer(Output_Packet.Rest.Header.MessageID), 0, 16);
            Protected_SPARK_IO_05.SPARK_IO_PO.Put_Line(Protected_SPARK_IO_05.SPARK_IO_PO.Standard_Output,"Respond failed", 0);
         end if;
      end if;
      --# accept Flow, 602, DNS_Network.Network, Output_Packet.Rest,  "initialization is unneeded";
      --# accept Flow, 602, Protected_SPARK_IO_05.SPARK_IO_PO, Output_Packet.Rest,  "initialization is unneeded";
      --# accept Flow, 33, Max_Transmit, "Max_Transmit only for UDP";
   end Process_Request_Tcp;



end Process_Dns_Request;

