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
WITH DNS_Network;
with DNS_Network_Receive;
with DNS_Table_Pkg;
with RR_Type;
with RR_Type.a_record_type;
with RR_Type.Aaaa_Record_Type;
WITH RR_Type.Cname_Record_Type;
with RR_Type.DNSKEY_Record_Type;
with RR_Type.ns_record_type;
with RR_Type.nsec_record_type;
with RR_Type.Mx_Record_Type;
with RR_Type.Rrsig_Record_Type;
with RR_Type.srv_record_type;
with RR_Type.Ptr_Record_Type;
with RR_Type.Soa_Record_Type;
with Unsigned_Types;
--# inherit DNS_types, DNS_Network, DNS_Network_Receive, System, Protected_SPARK_IO_05,
--#          RR_Type, RR_Type.a_record_type, RR_Type.aaaa_record_type,
--#          RR_Type.cname_record_type,RR_Type.dnskey_record_type,
--#          RR_Type.ns_record_type,RR_Type.nsec_record_type,
--#          RR_type.mx_record_type, RR_Type.ptr_record_type,
--#          RR_type.rrsig_record_type, 
--#          RR_type.soa_record_type, RR_type.srv_record_type,
--#          DNS_Table_Pkg, Unsigned_Types, ada.Unchecked_Conversion;
package Process_Dns_Request is
   procedure Process_Request_Tcp(
      Reply_Socket : in DNS_Network.DNS_Socket);
      --# global in out Protected_SPARK_IO_05.SPARK_IO_PO;
      --#        in out DNS_Network.Network;
      --#        in DNS_Table_Pkg.DNS_Table;
      --# derives DNS_Network.Network from DNS_Table_Pkg.DNS_Table, DNS_Network.Network, Reply_Socket &
      --#         Protected_SPARK_IO_05.SPARK_IO_PO from *, DNS_Table_Pkg.DNS_Table, DNS_Network.Network, Reply_Socket;
   procedure Create_Response(
         Input_Packet  : in DNS_Types.DNS_Packet;
         Input_Bytes   : in DNS_Types.Packet_Length_Range;
         Output_Packet : in out DNS_Types.DNS_Packet;
         Output_Bytes  : out DNS_Types.Packet_Length_Range;
         Max_Transmit  : out DNS_Types.Packet_Length_Range);
   --# global in DNS_Table_Pkg.DNS_Table;
   --#        in out Protected_SPARK_IO_05.SPARK_IO_PO;
   --# derives Output_Packet from *, DNS_Table_Pkg.DNS_Table, Input_Packet, Input_Bytes &
   --#         Output_Bytes from  Output_Packet, Input_Bytes, Input_Packet, DNS_Table_Pkg.DNS_Table &
   --#         Protected_SPARK_IO_05.SPARK_IO_PO from *, DNS_Table_Pkg.DNS_Table, Input_Packet, Input_Bytes &
   --#         Max_Transmit from DNS_Table_Pkg.DNS_Table, Input_Packet, Input_Bytes;
   --# pre Integer(Input_Bytes) >=DNS_Types.Header_Bits/8+1
   --#     and Integer(Input_Bytes) < 312;
   --# post Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and Integer(Output_Bytes) <= DNS_Types.Packet_Size and
   --#      Integer(Max_Transmit) <= DNS_Types.Packet_Size and Max_Transmit >= DNS_Types.UDP_Max_Size;
private
   procedure Set_Unsigned_32(
         Bytes : in out DNS_Types.Bytes_Array_Type;
         Start_Byte : in DNS_Types.Packet_Bytes_Range;
         Value : in Unsigned_Types.Unsigned32);
   --# derives Bytes from *, Start_Byte, Value;
   --# pre Start_Byte <= DNS_Types.Packet_Bytes_Range'Last-3;

   procedure Set_Unsigned_16(
         Bytes : in out DNS_Types.Bytes_Array_Type;
         Start_Byte : in DNS_Types.Packet_Bytes_Range;
         Value : in Unsigned_Types.Unsigned16);
   --# derives Bytes from *, Start_Byte, Value;
   --# pre Start_Byte <= DNS_Types.Packet_Bytes_Range'Last-1;

   procedure Get_Query_Name_Type_Class(
      Input_Packet  : in DNS_Types.DNS_Packet;
      Input_Bytes   : in DNS_Types.Packet_Length_Range;
      Domainname    : out RR_Type.WireStringType;
      Query_Type    : out DNS_Types.Query_Type;
      Query_Class   : out DNS_Types.Query_Class;
      End_Byte      : out Dns_types.Packet_Bytes_Range);
   --# derives Domainname from Input_Packet,Input_Bytes &
   --#         Query_Type from Input_Packet,Input_Bytes &
   --#         Query_Class from Input_Packet,Input_Bytes &
   --#         End_Byte from Input_Packet,Input_Bytes;
   --# pre Input_Bytes >=DNS_Types.Header_Bits/8+1 and Input_Bytes < 1000;
   --# post Integer(End_Byte) <= Integer(Input_Bytes) and End_Byte >= 4;

   procedure Set_TTL_Data_IP(
      Bytes      : in out DNS_Types.Bytes_Array_Type;
      Start_Byte : in DNS_Types.Packet_Bytes_Range;
      A_Record   : in Rr_Type.A_Record_Type.ARecordType);
   --# derives Bytes from *, Start_Byte, A_Record;
   --# pre Start_Byte <= DNS_Types.Packet_Bytes_Range'Last-10;

   procedure Set_TTL_Data_DNSKEY( --BSF
         Bytes : in out DNS_Types.Bytes_Array_Type;
         Start_Byte : in DNS_Types.Packet_Bytes_Range;
         DNSKEY_Record : IN Rr_Type.DNSKEY_Record_Type.DNSKEYRecordType;
         dstBytes : out rr_type.dnskey_record_type.keyLengthValueType);
   --# derives Bytes from *, Start_Byte, DNSKEY_Record &
   --#	dstBytes from DNSKEY_Record;
   --# pre Start_Byte <= DNS_Types.Packet_Bytes_Range'Last-10-DNS_Types.Packet_Bytes_Range(DNSKEY_Record.keyLength);

   procedure Set_TTL_Data_NSEC( --BSF
         Bytes : in out DNS_Types.Bytes_Array_Type;
         Start_Byte : in DNS_Types.Packet_Bytes_Range;
         NSEC_Record : IN Rr_Type.NSEC_Record_Type.NSECRecordType;
         dstbytes : OUT DNS_Types.Packet_Length_Range);
   --# derives Bytes from *, Start_Byte, NSEC_Record & dstBytes from NSEC_Record;
   --# pre Start_Byte <= DNS_Types.Packet_Bytes_Range'Last-6-DNS_Types.Packet_Bytes_Range(rr_type.maxDomainNameLength+1)
   --# - DNS_Types.Packet_Bytes_Range(rr_type.nsec_record_type.maxRRDataLength);
   --# post dstBytes <= DNS_Types.Packet_Length_Range(Rr_Type.NSEC_Record_Type.MaxRRDataLength);

   procedure Set_TTL_Data_RRSIG( --BSF
         Bytes : in out DNS_Types.Bytes_Array_Type;
         Start_Byte : in DNS_Types.Packet_Bytes_Range;
         RRSIG_Record : IN Rr_Type.RRSIG_Record_Type.RRSIGRecordType;
         dstbytes : OUT DNS_Types.Packet_Bytes_Range);
   --# derives Bytes from *, Start_Byte, RRSIG_Record &
   --#	dstBytes from RRSIG_Record;
   --# pre Start_Byte <= DNS_Types.Packet_Bytes_Range'Last-24-DNS_Types.Packet_Bytes_Range(Rr_Type.MaxDomainNameLength) -
   --#	DNS_Types.Packet_Bytes_Range(Rr_Type.Rrsig_Record_Type.maxrrsigLength);
   --# post dstBytes <= DNS_Types.Packet_Bytes_Range(24 + Rr_Type.MaxDomainnameLength + Rr_Type.RRSIG_Record_Type.maxrrsigLength);

   procedure Set_TTL_Data_AAAA_IP(
      Bytes      : in out DNS_Types.Bytes_Array_Type;
      Start_Byte : in DNS_Types.Packet_Bytes_Range;
      AAAA_Record   : in Rr_Type.AAAA_Record_Type.AAAARecordType);
   --# derives Bytes from *, Start_Byte, AAAA_Record;
   --# pre Start_Byte <= DNS_Types.Packet_Bytes_Range'Last-22;


   procedure Set_TTL_Data_NS_Response(
         Bytes               : in out DNS_Types.Bytes_Array_Type;
         Start_Byte          : in DNS_Types.Packet_Bytes_Range;
         NS_Record           : in Rr_Type.ns_record_type.NSRecordType;
         Current_Name_Length : in RR_Type.WireStringTypeIndex);
   --# derives Bytes from *, Start_Byte, NS_Record, Current_Name_Length;
   --# pre Current_Name_Length >= 0 and Current_Name_Length<=RR_Type.WireStringTypeIndex'Last and
   --#     Start_Byte <= (DNS_Types.Packet_Bytes_Range'Last-6)-DNS_Types.Packet_Bytes_Range(Current_Name_Length);

   procedure Set_TTL_Data_PTR_Response(
         Bytes                : in out DNS_Types.Bytes_Array_Type;
         Start_Byte           : in DNS_Types.Packet_Bytes_Range;
         PTR_Record           : in Rr_Type.ptr_record_type.PTRRecordType;
         Current_Name_Length  : in RR_Type.WireStringTypeIndex);
   --# derives Bytes from *, Start_Byte, PTR_Record, Current_Name_Length;
   --# pre Current_Name_Length >= 0 and Current_Name_Length<=RR_Type.WireStringTypeIndex'Last and
   --#     Start_Byte <= (DNS_Types.Packet_Bytes_Range'Last-6)-DNS_Types.Packet_Bytes_Range(Current_Name_Length);

   procedure Set_TTL_Data_MX_Response(
         Bytes               : in out DNS_Types.Bytes_Array_Type;
         Start_Byte          : in DNS_Types.Packet_Bytes_Range;
         MX_Record           : in Rr_Type.MX_record_type.MXRecordType;
         Current_Name_Length : in RR_Type.WireStringTypeIndex);
   --# derives Bytes from *, Start_Byte, MX_Record, Current_Name_Length;
   --# pre Current_Name_Length >= 0 and Current_Name_Length<=RR_Type.WireStringTypeIndex'Last and
   --#     Start_Byte <= (DNS_Types.Packet_Bytes_Range'Last-8)-DNS_Types.Packet_Bytes_Range(Current_Name_Length);

   procedure Set_TTL_Data_SOA_Response(
         Bytes                  : in out DNS_Types.Bytes_Array_Type;
         Start_Byte             : in DNS_Types.Packet_Bytes_Range;
         SOA_Record             : in Rr_Type.SOA_record_type.SOARecordType;
         Nameserver_Name_Length : in RR_Type.WireStringTypeIndex;
         Mailbox_Name_Length    : in RR_Type.WireStringTypeIndex);
   --# derives Bytes from *, Start_Byte, SOA_Record, Nameserver_Name_Length, Mailbox_Name_Length;
   --# pre Nameserver_Name_Length >= 0 and Nameserver_Name_Length<=RR_Type.WireStringTypeIndex'Last and
   --#     Mailbox_Name_Length >= 0 and Mailbox_Name_Length<=RR_Type.WireStringTypeIndex'Last and
   --#     Start_Byte <= (DNS_Types.Packet_Bytes_Range'Last-26)-
   --#        DNS_Types.Packet_Bytes_Range(Nameserver_Name_Length+Mailbox_Name_Length);


   procedure Set_TTL_Data_SRV_Response(
         Bytes               : in out DNS_Types.Bytes_Array_Type;
         Start_Byte          : in DNS_Types.Packet_Bytes_Range;
         SRV_Record           : in Rr_Type.SRV_record_type.SRVRecordType;
         Current_Name_Length : in RR_Type.WireStringTypeIndex);
   --# derives Bytes from *, Start_Byte, SRV_Record, Current_Name_Length;
   --# pre Current_Name_Length >= 0 and Current_Name_Length<=RR_Type.WireStringTypeIndex'Last and
   --#     Start_Byte <= (DNS_Types.Packet_Bytes_Range'Last-12)-DNS_Types.Packet_Bytes_Range(Current_Name_Length);

   procedure Create_Response_EDNS(
         Input_Packet       : in DNS_Types.DNS_Packet;
         Input_Bytes        : in DNS_Types.Packet_Length_Range;
         Query_End_Byte     : in DNS_Types.Packet_Bytes_Range;
         Start_Byte         : in DNS_Types.Packet_Bytes_Range;
         Output_Packet      : in out DNS_Types.DNS_Packet;
         Output_Bytes       : out DNS_Types.Packet_Length_Range;
         Additional_Count   : in out DNS_Types.Unsigned_Short;
         DNSSEC             : out Boolean;
         Max_Transmit       : out DNS_Types.Packet_Length_Range);
   --# derives Output_Packet from *, Start_Byte, Input_Packet, Input_Bytes, Query_End_Byte &
   --#         Output_Bytes from Start_Byte, Input_Packet, Input_Bytes, Query_End_Byte &
   --#         Max_Transmit from Start_Byte, Input_Bytes, Input_Packet, Query_End_Byte &
   --#         DNSSEC from Start_Byte, Input_Bytes, Input_Packet, Query_End_Byte &
   --#         Additional_Count from *, Input_Packet, Start_Byte, Input_Bytes, Query_End_Byte;
   --# pre Additional_Count < DNS_Types.Unsigned_Short'Last;
   --# post Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and Output_Bytes <= DNS_Types.Packet_Size and
   --#      Additional_Count >= Additional_Count~ and Additional_Count <= Additional_Count~+1 and
   --#      Max_Transmit >= DNS_Types.UDP_Max_Size and Max_Transmit <= DNS_Types.Packet_Size;

   procedure Create_Response_A(
         Start_Byte     : in DNS_Types.Packet_Bytes_Range;
         Domainname     : in RR_Type.WireStringType;
         Qname_Location : in DNS_Types.QNAME_PTR_RANGE;
         Output_Packet  : in out DNS_Types.DNS_Packet;
         Answer_Count   : in out DNS_Types.Unsigned_Short;
         Output_Bytes   : out DNS_Types.Packet_Length_Range);
   --# global in DNS_Table_Pkg.DNS_Table;
   --# derives Output_Packet from *, Qname_Location, Start_Byte, Domainname, DNS_Table_Pkg.DNS_Table &
   --#         Output_Bytes from Domainname, Start_Byte, DNS_Table_Pkg.DNS_Table &
   --#         Answer_Count from *, Domainname, DNS_Table_Pkg.DNS_Table;
   --# pre Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords)
   --#     and Integer(Start_Byte) <= DNS_Types.Packet_Size;
   --# post Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and Integer(Output_Bytes) <= DNS_Types.Packet_Size and
   --#      Answer_Count <= Answer_Count~+DNS_Types.Unsigned_Short(rr_type.MaxNumRecords);

   procedure Create_Response_DNSKEY(
         Start_Byte     : in DNS_Types.Packet_Bytes_Range;
         Domainname     : in RR_Type.WireStringType;
         Qname_Location : in DNS_Types.QNAME_PTR_RANGE;
         Output_Packet  : in out DNS_Types.DNS_Packet;
         Answer_Count   : in out DNS_Types.Unsigned_Short;
         Output_Bytes   : out DNS_Types.Packet_Length_Range);
   --# global in DNS_Table_Pkg.DNS_Table;
   --# derives Output_Packet from *, Qname_Location, Start_Byte, Domainname, DNS_Table_Pkg.DNS_Table &
   --#         Output_Bytes from Domainname, Start_Byte, DNS_Table_Pkg.DNS_Table &
   --#         Answer_Count from *, Domainname, DNS_Table_Pkg.DNS_Table;
   --# pre Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords)
   --#     and Integer(Start_Byte) <= DNS_Types.Packet_Size;
   --# post Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and Integer(Output_Bytes) <= DNS_Types.Packet_Size and
   --#      Answer_Count <= Answer_Count~+DNS_Types.Unsigned_Short(rr_type.MaxNumRecords);

   procedure Create_Response_NSEC(
         Start_Byte     : in DNS_Types.Packet_Bytes_Range;
         Domainname     : in RR_Type.WireStringType;
         Qname_Location : in DNS_Types.QNAME_PTR_RANGE;
         Output_Packet  : in out DNS_Types.DNS_Packet;
         Answer_Count   : in out DNS_Types.Unsigned_Short;
         Output_Bytes   : out DNS_Types.Packet_Length_Range);
   --# global in DNS_Table_Pkg.DNS_Table;
   --# derives Output_Packet from *, Qname_Location, Start_Byte, Domainname, DNS_Table_Pkg.DNS_Table &
   --#         Output_Bytes from Domainname, Start_Byte, DNS_Table_Pkg.DNS_Table &
   --#         Answer_Count from *, Domainname, DNS_Table_Pkg.DNS_Table;
   --# pre Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords);
   --# post Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and Integer(Output_Bytes) <= DNS_Types.Packet_Size and
   --#      Answer_Count <= Answer_Count~+DNS_Types.Unsigned_Short(rr_type.MaxNumRecords);

   procedure Create_Response_RRSIG(
         Start_Byte     : in DNS_Types.Packet_Bytes_Range;
         Domainname     : in RR_Type.WireStringType;
         Qname_Location : in DNS_Types.QNAME_PTR_RANGE;
         Output_Packet  : in out DNS_Types.DNS_Packet;
         Answer_Count   : in out DNS_Types.Unsigned_Short;
         Output_Bytes   : out DNS_Types.Packet_Length_Range);
   --# global in DNS_Table_Pkg.DNS_Table;
   --# derives Output_Packet from *, Qname_Location, Start_Byte, Domainname, DNS_Table_Pkg.DNS_Table &
   --#         Output_Bytes from Domainname, Start_Byte, DNS_Table_Pkg.DNS_Table &
   --#         Answer_Count from *, Domainname, DNS_Table_Pkg.DNS_Table;
   --# pre Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords)
   --#     and Integer(Start_Byte) <= DNS_Types.Packet_Size;
   --# post Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and Integer(Output_Bytes) <= DNS_Types.Packet_Size and
   --#      Answer_Count <= Answer_Count~+DNS_Types.Unsigned_Short(rr_type.MaxNumRecords);

   procedure Create_NXDOMAIN_Response(
         Start_Byte      : in DNS_Types.Packet_Bytes_Range;
         Domainname      : in RR_Type.WireStringType;
         Qname_Location  : in DNS_Types.QNAME_PTR_RANGE;
         Output_Packet   : in out DNS_Types.DNS_Packet;
         Output_Bytes    : out DNS_Types.Packet_Length_Range);
   --# global in DNS_Table_Pkg.DNS_Table;
   --# derives Output_Packet from *, Qname_Location, Start_Byte, Domainname, DNS_Table_Pkg.DNS_Table &
   --#         Output_Bytes from Domainname, Qname_Location, Start_Byte, DNS_Table_Pkg.DNS_Table;
   --# pre Integer(Start_Byte) <= DNS_Types.Packet_Size;
   --# post Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and Integer(Output_Bytes) <= DNS_Types.Packet_Size;


   procedure Create_Response_AAAA(
         Start_Byte     : in DNS_Types.Packet_Bytes_Range;
         Domainname     : in RR_Type.WireStringType;
         Qname_Location : in DNS_Types.QNAME_PTR_RANGE;
         Output_Packet  : in out DNS_Types.DNS_Packet;
         Answer_Count   : in out DNS_Types.Unsigned_Short;
         Output_Bytes   : out DNS_Types.Packet_Length_Range);
   --# global in DNS_Table_Pkg.DNS_Table;
   --# derives Output_Packet from *, Start_Byte, Qname_Location, Domainname, DNS_Table_Pkg.DNS_Table &
   --#         Output_Bytes from Domainname, Start_Byte, DNS_Table_Pkg.DNS_Table &
   --#         Answer_Count from *, Domainname, DNS_Table_Pkg.DNS_Table;
   --# pre Integer(Start_Byte) <= DNS_Types.Packet_Size and
   --#     Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords);
   --# post Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and Integer(Output_Bytes) <= DNS_Types.Packet_Size and
   --#      Answer_Count <= Answer_Count~ + DNS_Types.Unsigned_Short(rr_type.MaxNumRecords);


   procedure Process_Response_Cname(
         Start_Byte     : in DNS_Types.Packet_Bytes_Range;
         Cnames         : in RR_Type.cname_record_type.CNAMERecordBucketType;
         Domainname     : out RR_Type.WireStringType;
         Qname_Location : in out DNS_Types.QNAME_PTR_RANGE;
         Output_Packet  : in out DNS_Types.DNS_Packet;
         Output_Bytes   : out DNS_Types.Packet_Length_Range);
   --# derives Domainname from Cnames &
   --#         Qname_Location from Start_Byte &
   --#         Output_Packet from *, Qname_Location, Start_Byte, Cnames &
   --#         Output_Bytes from Cnames, Start_Byte;
   --# pre Integer(Start_Byte) <= DNS_Types.Packet_Size and
   --#      Output_Packet.Header.ANCount = 0;
   --# post Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and Integer(Output_Bytes) <= DNS_Types.Packet_Size and
   --#      Output_Packet.Header.ANCount <= 1;

   procedure Create_Response_Error(
         Input_Bytes   : in DNS_Types.Packet_Length_Range;
         Output_Packet : in out DNS_Types.DNS_Packet;
         Output_Bytes  : out DNS_Types.Packet_Length_Range);
   --# derives Output_Packet from * &
   --#         Output_Bytes from Input_Bytes;
   --# post Output_Bytes = Input_Bytes;

   type QNAME_PTR_RANGE_Array is array(RR_Type.ReturnedRecordsIndexType) of DNS_Types.QNAME_PTR_RANGE;

   procedure Create_Response_NS(
         Start_Byte      : in DNS_Types.Packet_Bytes_Range;
         Domainname      : in RR_Type.WireStringType;
         Num_Found       : out RR_Type.NumberOfRecordsType;
         Qname_Location  : in DNS_Types.QNAME_PTR_RANGE;
         Qname_Locations : out QNAME_PTR_RANGE_Array;
         Replies         : out RR_Type.ns_record_type.NSRecordBucketType;
         Output_Packet   : in out DNS_Types.DNS_Packet;
         Answer_Count    : in out DNS_Types.Unsigned_Short;
         Output_Bytes    : out DNS_Types.Packet_Length_Range);
   --# global in DNS_Table_Pkg.DNS_Table;
   --# derives Output_Packet from *, Start_Byte, Qname_Location, Domainname, DNS_Table_Pkg.DNS_Table &
   --#         Output_Bytes from Domainname, Start_Byte, DNS_Table_Pkg.DNS_Table &
   --#         Num_Found from DNS_Table_Pkg.DNS_Table, Domainname &
   --#         Replies from DNS_Table_Pkg.DNS_Table, Domainname &
   --#         Answer_Count from *, Domainname, DNS_Table_Pkg.DNS_Table &
   --#         Qname_Locations from Start_Byte, DNS_Table_Pkg.DNS_Table, Domainname ;
   --# pre Integer(Start_Byte) <= DNS_Types.Packet_Size and
   --#     Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords);
   --# post Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and Integer(Output_Bytes) <= DNS_Types.Packet_Size and
   --#     Answer_Count <= Answer_Count~+DNS_Types.Unsigned_Short(rr_type.MaxNumRecords);

   procedure Create_Response_PTR(
         Start_Byte      : in DNS_Types.Packet_Bytes_Range;
         Domainname      : in RR_Type.WireStringType;
         Qname_Location  : in DNS_Types.QNAME_PTR_RANGE;
         Output_Packet   : in out DNS_Types.DNS_Packet;
         Answer_Count    : in out DNS_Types.Unsigned_Short;
         Output_Bytes    : out DNS_Types.Packet_Length_Range);
   --# global in DNS_Table_Pkg.DNS_Table;
   --# derives Output_Packet from *, Start_Byte, Qname_Location, Domainname, DNS_Table_Pkg.DNS_Table &
   --#         Output_Bytes from Domainname, Start_Byte, DNS_Table_Pkg.DNS_Table &
   --#         Answer_Count from *, Domainname, DNS_Table_Pkg.DNS_Table;
   --# pre Integer(Start_Byte) <= DNS_Types.Packet_Size and
   --#     Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords);
   --# post Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and Integer(Output_Bytes) <= DNS_Types.Packet_Size and
   --#     Answer_Count <= Answer_Count~+DNS_Types.Unsigned_Short(rr_type.MaxNumRecords);

   procedure Create_Response_MX(
         Start_Byte      : in DNS_Types.Packet_Bytes_Range;
         Domainname      : in RR_Type.WireStringType;
         Num_Found       : out RR_Type.NumberOfRecordsType;
         Qname_Location  : in DNS_Types.QNAME_PTR_RANGE;
         Qname_Locations : out QNAME_PTR_RANGE_Array;
         Replies         : out RR_Type.mx_record_type.MXRecordBucketType;
         Output_Packet   : in out DNS_Types.DNS_Packet;
         Answer_Count    : in out DNS_Types.Unsigned_Short;
         Output_Bytes    : out DNS_Types.Packet_Length_Range);
   --# global in DNS_Table_Pkg.DNS_Table;
   --# derives Output_Packet from *, Start_Byte, Qname_Location, Domainname, DNS_Table_Pkg.DNS_Table &
   --#         Output_Bytes from Domainname, Start_Byte, DNS_Table_Pkg.DNS_Table &
   --#         Num_Found from DNS_Table_Pkg.DNS_Table, Domainname &
   --#         Replies from DNS_Table_Pkg.DNS_Table, Domainname &
   --#         Answer_Count from *, Domainname, DNS_Table_Pkg.DNS_Table &
   --#         Qname_Locations from Start_Byte, DNS_Table_Pkg.DNS_Table, Domainname ;
   --# pre Integer(Start_Byte) <= DNS_Types.Packet_Size and
   --#     Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords);
   --# post Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and Integer(Output_Bytes) <= DNS_Types.Packet_Size and
   --#     Answer_Count <= Answer_Count~+DNS_Types.Unsigned_Short(rr_type.MaxNumRecords);


   procedure Create_Response_SRV(
         Start_Byte      : in DNS_Types.Packet_Bytes_Range;
         Domainname      : in RR_Type.WireStringType;
         Num_Found       : out RR_Type.NumberOfRecordsType;
         Qname_Location  : in DNS_Types.QNAME_PTR_RANGE;
         Qname_Locations : out QNAME_PTR_RANGE_Array;
         Replies         : out RR_Type.srv_record_type.SRVRecordBucketType;
         Output_Packet   : in out DNS_Types.DNS_Packet;
         Answer_Count    : in out DNS_Types.Unsigned_Short;
         Output_Bytes    : out DNS_Types.Packet_Length_Range);
   --# global in DNS_Table_Pkg.DNS_Table;
   --# derives Output_Packet from *, Start_Byte, Qname_Location, Domainname, DNS_Table_Pkg.DNS_Table &
   --#         Output_Bytes from Domainname, Start_Byte, DNS_Table_Pkg.DNS_Table &
   --#         Num_Found from DNS_Table_Pkg.DNS_Table, Domainname &
   --#         Replies from DNS_Table_Pkg.DNS_Table, Domainname &
   --#         Answer_Count from *, Domainname, DNS_Table_Pkg.DNS_Table &
   --#         Qname_Locations from Start_Byte, DNS_Table_Pkg.DNS_Table, Domainname ;
   --# pre Integer(Start_Byte) <= DNS_Types.Packet_Size and
   --#     Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords);
   --# post Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and Integer(Output_Bytes) <= DNS_Types.Packet_Size and
   --#     Answer_Count <= Answer_Count~+DNS_Types.Unsigned_Short(rr_type.MaxNumRecords);

   procedure Create_Response_SOA(
         Start_Byte      : in DNS_Types.Packet_Bytes_Range;
         Domainname      : in RR_Type.WireStringType;
         Qname_Location  : in DNS_Types.QNAME_PTR_RANGE;
         Output_Packet   : in out DNS_Types.DNS_Packet;
         Answer_Count    : in out DNS_Types.Unsigned_Short;
         Output_Bytes    : out DNS_Types.Packet_Length_Range);
   --# global in DNS_Table_Pkg.DNS_Table;
   --# derives Output_Packet from *, Start_Byte, Qname_Location, Domainname, DNS_Table_Pkg.DNS_Table &
   --#         Output_Bytes from Domainname, Start_Byte, DNS_Table_Pkg.DNS_Table &
   --#         Answer_Count from *, Domainname, DNS_Table_Pkg.DNS_Table;
   --# pre Integer(Start_Byte) <= DNS_Types.Packet_Size and
   --#     Answer_Count <= DNS_Types.Unsigned_Short'Last-DNS_types.Unsigned_Short(rr_type.MaxNumRecords);
   --# post Integer(Output_Bytes) >= DNS_Types.Header_Bits/8+1 and Integer(Output_Bytes) <= DNS_Types.Packet_Size and
   --#     Answer_Count <= Answer_Count~+DNS_Types.Unsigned_Short(rr_type.MaxNumRecords);

   procedure Trim_Name(
      Domainname         : in RR_Type.WireStringType;
      Trimmed_name       : out RR_Type.WireStringType;
      Qname_Location     : in DNS_Types.QNAME_PTR_RANGE;
      New_Qname_Location : out DNS_Types.QNAME_PTR_RANGE);
   --# derives Trimmed_Name from Domainname &
   --#         New_Qname_Location from Domainname, Qname_Location;
   --# pre Qname_Location <= DNS_Types.QNAME_PTR_RANGE(DNS_Types.Packet_Length_Range'Last);
end Process_Dns_Request;

