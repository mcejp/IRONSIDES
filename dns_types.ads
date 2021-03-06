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

--# inherit System;
package DNS_Types is
   Packet_Size : constant := 8192;
   Header_Bits : constant := 96;

   type QNAME_PTR_RANGE is range 0..2**14-1;

   type Packet_Length_Range is range 0..Packet_Size;
   --# assert Packet_Length_Range'Base is Integer;
   UDP_Max_Size : constant Packet_Length_Range := 512;

   type Packet_Bytes_Range is range 1..(Packet_Size - Header_Bits/8);
   --# assert Packet_Bytes_Range'Base is Integer;

   type Byte is mod 256;
   --# accept Warning, 2, "representation clause ok";
   for Byte'Size use 8;
   --# end accept;


   type Unsigned_Short is range 0 .. 2**16 - 1;
   --# assert Unsigned_Short'Base is Integer;
   --# accept Warning, 2, "representation clause ok";
   for Unsigned_Short'Size use 16;
   --# end accept;

   -- used in OPCODE field below
   type Opcode_Type is (Query, IQuery, Status);
   --# accept Warning, 2, "representation clause ok";
   for Opcode_Type'Size use 4;
   --# end accept;

   -- used in RCODE field below
   type Response_Code is
         (No_Error,
          Format_Error,
          Server_Failure,
          Name_Error,
          Not_Implemented,
          Refused);
   --# accept Warning, 2, "representation clause ok";
   for Response_Code'Size use 4;
   --# end accept;


   -- See http://www.zytrax.com/books/dns/ch15/ for a description
   -- of these fields.
   type Header_Type is
      record
         -- 16 bit message ID supplied by requester and mirrored by responder
         MessageID : Unsigned_Short;
         -- False for query, true for response
         QR : Boolean;
         -- 0 for query, 1 for inverse query, 2 for status request
         Opcode : Opcode_Type;
         -- Authoritative Answer (response only)
         AA : Boolean;
         -- Truncated (partial message, true until last portion)
         TC : Boolean;
         -- recursion desired (query)
         RD : Boolean;
         -- recursion available (response)
         RA : Boolean;
         -- Reserved for future use (zone transfers??)
         Res1 : Boolean;
         Res2 : Boolean;
         Res3 : Boolean;
         -- response code.
         RCODE : Response_Code;
         -- number of queries (echo in answer!)
         QDCOUNT : Unsigned_Short;
         -- number of answers
         ANCOUNT : Unsigned_Short;
         -- number of name server resource records
         NSCOUNT : Unsigned_Short;
         -- number of additional records
         ARCOUNT : Unsigned_Short;
      end record;
   --   for Header use record
   --      MessageID at 0 range 0..15;
   --      QR at 0 range 23..23;
   --      Opcode at 0 range 19..22;
   --      AA at 0 range 18..18;
   --      TC at 0 range 17..17;
   --      RD at 0 range 16..16;
   --      RA at 0 range 31..31;
   --      Res1 at 0 range 30..30;
   --      Res2 at 0 range 29..29;
   --      Res3 at 0 range 28..28;
   --      RCODE at 0 range 24..27;
   --      QDCOUNT at 4 range 0..15;
   --      ANCOUNT at 4 range 16..31;
   --      NSCOUNT at 8 range 0..15;
   --      ARCOUNT at 8 range 16..31;
   --   end record;
   --   for Header'Bit_Order use System.Low_Order_First;
   --# accept Warning, 2, "representation clause ok";
   for Header_Type use record
      MessageID at 0 range 16..31;
      QR at 0 range 8..8;
      Opcode at 0 range 9..12;
      AA at 0 range 13..13;
      TC at 0 range 14..14;
      RD at 0 range 15..15;
      RA at 0 range 0..0;
      Res1 at 0 range 1..1;
      Res2 at 0 range 2..2;
      Res3 at 0 range 3..3;
      RCODE at 0 range 4..7;
      QDCOUNT at 4 range 16..31;
      ANCOUNT at 4 range 0..15;
      NSCOUNT at 8 range 16..31;
      ARCOUNT at 8 range 0..15;
   end record;
   for Header_Type'Size use Header_Bits;
   for Header_Type'Bit_Order use System.High_Order_First;
   --# end accept;

   Empty_Header : constant Header_Type := Header_Type'(
      MessageID => 0,
      QR => False,
      Opcode => Query,
      Rcode => No_Error,
      AA => False,
      TC => False,
      RD => False,
      RA => False,
      Res1 => False,
      Res2 => False,
      Res3 => False,
      QDCOUNT => 0,
      ANCOUNT => 0,
      NSCOUNT => 0,
      ARCOUNT => 0);

   function Byte_Swap_US(U : Unsigned_Short) return Unsigned_Short;
   --# accept Warning, 3, "Inline ok";
   pragma Inline(Byte_Swap_US);
   --# end accept;

   -- swap bytes in Unsigned_Short fields
   -- to switch between network and host order for little endian machines
   procedure Byte_Swap (
         H : in out Header_Type);
   --# derives H from H;
   --# post H = H~[MessageID => Byte_Swap_US(H~.MessageID);
   --#   QDCount => Byte_Swap_US(H~.QDCount);
   --#   ANCount => Byte_Swap_US(H~.ANCount);
   --#   NSCount => Byte_Swap_US(H~.NSCount);
   --#   ARCount => Byte_Swap_US(H~.ARCount)];
   type Query_Class is
        (IN_CLASS,
         CH_CLASS,
         HS_CLASS,
         NONE_CLASS,
         ANY_CLASS);
   --# accept Warning, 2, "representation clause ok";
   for Query_Class use
      (
      IN_CLASS   => 1,
      CH_CLASS   => 3,
      HS_CLASS   => 4,
      NONE_CLASS => 254,
      ANY_CLASS  => 255);
   for Query_Class'Size use 16;
   --# end accept;

   type Query_Type is
         (A,
          NS,
          CNAME,
          SOA,
          WKS,
          PTR,
          MX,
          AAAA,
          SRV,
          A6,
          OPT,
          --DNSSEC
          DS,
          RRSIG,
          NSEC,
          DNSKEY,
          --
          ANY,
          CAA,
          ERROR,
          UNIMPLEMENTED);
   --# accept Warning, 2, "representation clause ok";
   for Query_Type use
      (
      A     => 1,
      NS    => 2,
      CNAME => 5,
      SOA   => 6,
      WKS   => 11,
      PTR   => 12,
      MX    => 15,
      AAAA  => 28,
      SRV   => 33,
      A6    => 38,
      OPT   => 41,
      DS    => 43,
      RRSIG => 46,
      NSEC  => 47,
      DNSKEY => 48,
      ANY   => 255,
      CAA   => 257,
      ERROR => 65280,
      UNIMPLEMENTED => 65281);
   for Query_Type'Size use 16;
   --# end accept;

   type EDNS_Record is record
      Root         : Character;
      Code         : Query_Type;
      Payload_Size : Unsigned_Short;
      RCode        : Byte;
      Version      : Byte;
      ZTop         : Byte;
      ZBottom      : Byte;
      RDLen        : Unsigned_Short;
   end record;
   --this record won't pack b/c payload_size isn't aligned correctly.
   --for EDNS_Record'Size use 9*8;
   --for EDNS_Record'Bit_Order use System.High_Order_First;
   DNSSECMASK : constant := 128;

   type Bytes_Array_Type is array(Packet_Bytes_Range) of Byte;

   type DNS_Packet is record
      Header : Header_Type;
      Bytes  : Bytes_Array_Type;
   end record;
   type DNS_Tcp_Packet is record
      Length : Unsigned_Short;
      Rest   : DNS_Packet;
   END RECORD;
end Dns_Types;

