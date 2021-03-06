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

with DNS_Types;
WITH Gnat.Sockets;
--# inherit DNS_Types,System;
package DNS_Network
--# own protected Network : Network_Type;
is
   --# type Network_Type is abstract;
   -- how long do we allow a receive/send to occur before we timeout
   Socket_Timeout_Milliseconds : CONSTANT := 2_000;
   Max_Query_Size : CONSTANT := 311;

   type Network_Address_and_Port is limited private;
   type DNS_Socket is private;

   procedure Initialize_TCP;
   --# global in out Network;
   --# derives Network from Network;

   procedure Initialize_UDP;
   --# global in out Network;
   --# derives Network from Network;

   procedure Get_Connection_TCP(
      Socket : out DNS_Socket);
   --# global in out Network;
   --# derives Network from * & Socket from Network;

   -- post condition comes from DNS_Network_Receive
   procedure Receive_DNS_Packet_TCP
     (Packet : out DNS_Types.DNS_Tcp_Packet;
      Number_Bytes   : out DNS_Types.Packet_Length_Range;
      Socket : in DNS_Socket;
      Failure : out Boolean);
   --# global in out Network;
   --# derives Network, Packet, Number_Bytes, Failure from Network, Socket;

   procedure Send_DNS_Packet_Tcp
     (Packet : in out DNS_Types.DNS_Tcp_Packet;
      Number_Bytes : in DNS_Types.Packet_Length_Range;
      Socket : in DNS_Socket;
      Failure : out Boolean);
   --# global in out Network;
   --# derives Failure,Network from Network, Packet, Number_Bytes, Socket &
   --#         Packet from Network;
   --# pre Integer(Number_Bytes) > DNS_Types.Header_Bits/8;
   --# post System.Default_Bit_Order=System.High_Order_First -> Packet = Packet~;

   -- Reads a single UDP packet from network on port 53
   -- Last is the number of bytes read (assuming no failure)
   -- post condition comes from DNS_Network_Receive
   procedure Receive_DNS_Packet(
      Packet : out DNS_Types.DNS_Packet;
      Number_Bytes  : out DNS_Types.Packet_Length_Range;
      Reply_Address : out Network_Address_and_Port;
      Failure : out Boolean);
   --# global in out Network;
   --# derives Network, Packet, Number_Bytes, Reply_Address, Failure from Network;

   -- send a single UDP DNS reply packet to the given address
   -- Last is number of bytes to send
   procedure Send_DNS_Packet(Packet : in out DNS_Types.DNS_Packet;
      Number_Bytes : in DNS_Types.Packet_Length_Range;
      To_Address : in Network_Address_and_Port;
      Failure : out Boolean);
   --# global in out Network;
   --# derives Failure,Network from Network, Packet, Number_Bytes, To_Address &
   --#         Packet from Network;
   --# pre Integer(Number_Bytes) > DNS_Types.Header_Bits/8;
   --# post System.Default_Bit_Order=System.High_Order_First -> Packet = Packet~;

   procedure Discard_Socket(Socket : in DNS_Socket);
   --# global in out Network;
   --# derives Network from *, Socket;
PRIVATE
   --# hide DNS_Network
   type Network_Address_And_Port is new Gnat.Sockets.Sock_Addr_Type;
   type DNS_Socket is new Gnat.Sockets.Socket_Type;
end DNS_Network;

