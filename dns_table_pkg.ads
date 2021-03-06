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

with unsigned_types, rr_type, rr_type.a_record_type, rr_type.aaaa_record_type,
   Rr_Type.Cname_Record_Type, Rr_Type.Dnskey_Record_Type, Rr_Type.Mx_Record_Type,
   Rr_Type.Ns_Record_Type, Rr_Type.Nsec_Record_Type, Rr_Type.Ptr_Record_Type,
   Rr_Type.rrsig_record_type, Rr_Type.Soa_Record_Type, Rr_Type.srv_record_type;

USE TYPE Unsigned_Types.Unsigned32;

--need these for equality operator in package body
use type Rr_Type.a_Record_Type.ARecordType;
use type rr_type.aaaa_record_type.AAAARecordType;
USE TYPE Rr_Type.Cname_Record_Type.CNAMERecordType;
USE TYPE Rr_Type.Dnskey_Record_Type.DNSKEYRecordType;
USE TYPE Rr_Type.Mx_Record_Type.MXRecordType;
USE TYPE Rr_Type.srv_record_type.SRVRecordType;
use type Rr_Type.Ns_Record_Type.NSRecordType;
USE TYPE Rr_Type.NSEC_Record_Type.NSECRecordType;
use type Rr_Type.Ptr_Record_Type.PTRRecordType;
use type Rr_Type.rrsig_record_type.RRSIGRecordType;
use type rr_type.soa_record_type.SOARecordType;

--in case debugging IO needed
--WITH Ada.Text_IO, Ada.Integer_Text_Io;

--# inherit System, Ada.Characters.Handling, unsigned_types, dns_types, rr_type, rr_type.a_record_type, rr_type.aaaa_record_type,
--#    rr_type.cname_record_type, rr_type.dnskey_record_type, rr_type.mx_record_type, rr_type.srv_record_type,
--#    rr_type.ns_record_type, rr_type.nsec_record_type, rr_type.ptr_record_type,
--#    rr_type.rrsig_record_type, rr_type.soa_record_type;


package dns_table_pkg
--# own protected DNS_Table : DNS_Table_Type (priority => 0);
is

protected type Dns_Table_Type is

   pragma priority(0);

   procedure insertARecord(Key : in Rr_Type.WireStringType;
                           theRecord : in rr_type.a_record_type.ARecordType;
                           success : out boolean);
   --# global in out DNS_Table_Type;
   --# derives DNS_Table_Type from *, theRecord, Key &
   --#         success from DNS_Table_Type, key;

   procedure insertAAAARecord(Key : in Rr_Type.WireStringType;
                           theRecord : in rr_type.aaaa_record_type.AAAARecordType;
                           success : out boolean);
   --# global in out DNS_Table_Type;
   --# derives DNS_Table_Type from *, theRecord, Key &
   --#         success from DNS_Table_Type, key;

   procedure insertCNAMERecord(Key : in Rr_Type.WireStringType;
                           theRecord : in rr_type.cname_record_type.CNAMERecordType;
                           success : out boolean);
   --# global in out DNS_Table_Type;
   --# derives DNS_Table_Type from *, theRecord, Key &
   --#         success from DNS_Table_Type, key;

   procedure InsertDNSKEYRecord(Key : in Rr_Type.WireStringType;
                          theRecord : in rr_type.DNSKEY_record_type.DNSKEYRecordType;
                          success : out boolean);
   --# global in out DNS_Table_Type;
   --# derives DNS_Table_Type from *, theRecord, Key &
   --#         success from DNS_Table_Type, key;

   procedure insertMXRecord(Key : in Rr_Type.WireStringType;
                           theRecord : in rr_type.mx_record_type.MXRecordType;
                           success : out boolean);
   --# global in out DNS_Table_Type;
   --# derives DNS_Table_Type from *, theRecord, Key &
   --#         success from DNS_Table_Type, key;

procedure insertSRVRecord(Key : in Rr_Type.WireStringType;
                           theRecord : in rr_type.srv_record_type.SRVRecordType;
                           success : out boolean);
   --# global in out DNS_Table_Type;
   --# derives DNS_Table_Type from *, theRecord, Key &
   --#         success from DNS_Table_Type, key;

   procedure insertNSRecord(Key : in Rr_Type.WireStringType;
                           theRecord : in rr_type.ns_record_type.NSRecordType;
                           success : out boolean);
   --# global in out DNS_Table_Type;
   --# derives DNS_Table_Type from *, theRecord, Key &
   --#         success from DNS_Table_Type, key;

   procedure insertNSECRecord(Key : in Rr_Type.WireStringType;
                           theRecord : in rr_type.nsec_record_type.NSECRecordType;
                           success : out boolean);
   --# global in out DNS_Table_Type;
   --# derives DNS_Table_Type from *, theRecord, Key &
   --#         success from DNS_Table_Type, key;

   procedure insertPTRRecord(Key : in Rr_Type.WireStringType;
                           theRecord : in rr_type.ptr_record_type.PTRRecordType;
                           success : out boolean);
   --# global in out DNS_Table_Type;
   --# derives DNS_Table_Type from *, theRecord, Key &
   --#         success from DNS_Table_Type, key;

   procedure InsertRRSIGRecord(Key : in Rr_Type.WireStringType;
                          theRecord : in rr_type.RRSIG_record_type.RRSIGRecordType;
                          success : out boolean);
   --# global in out DNS_Table_Type;
   --# derives DNS_Table_Type from *, theRecord, Key &
   --#         success from DNS_Table_Type, key;

   procedure InsertSOARecord(Key : in Rr_Type.WireStringType;
                           theRecord : in rr_type.soa_record_type.SOARecordType;
                           success : out boolean);
   --# global in out DNS_Table_Type;
   --# derives DNS_Table_Type from *, theRecord, Key &
   --#         success from DNS_Table_Type, key;

   procedure queryARecords(
   	domainName : in rr_type.WireStringType;
        returnedRecords : out rr_type.a_record_type.ARecordBucketType;
        howMany : out rr_type.NumberOfRecordsType);
   --# global in DNS_Table_Type;
   --# derives returnedRecords from DNS_Table_Type, domainName &
   --#         howMany from DNS_Table_Type, domainName;

   -- to support RFC 4074
   procedure countARecords(
   	domainName : in rr_type.WireStringType;
      howMany : out rr_type.NumberOfRecordsType);
   --# global in DNS_Table_Type;
   --# derives howMany from DNS_Table_Type, domainName;
   procedure countAAAARecords(
   	domainName : in rr_type.WireStringType;
      howMany : out rr_type.NumberOfRecordsType);
   --# global in DNS_Table_Type;
   --# derives howMany from DNS_Table_Type, domainName;

   procedure queryAAAARecords(
   	domainName : in rr_type.WireStringType;
        returnedRecords : out rr_type.aaaa_record_type.AAAARecordBucketType;
        howMany : out rr_type.NumberOfRecordsType);
   --# global in DNS_Table_Type;
   --# derives returnedRecords from DNS_Table_Type, domainName &
   --#         howMany from DNS_Table_Type, domainName;

   procedure queryCNAMERecords(
      domainName : in rr_type.WireStringType;
      returnedRecords : out rr_type.cname_record_type.CNAMERecordBucketType;
      howMany : out rr_type.NumberOfRecordsType);
   --# global in DNS_Table_Type;
   --# derives returnedRecords from DNS_Table_Type, domainName &
   --#         howMany from DNS_Table_Type, domainName;

   procedure queryDNSKEYRecords(
      domainName : in rr_type.WireStringType;
      returnedRecords : out rr_type.DNSKEY_record_type.DNSKEYRecordBucketType;
      HowMany : out Rr_Type.NumberOfRecordsType);
   --# global in DNS_Table_Type;
   --# derives  returnedRecords, howMany from DNS_Table_Type, domainName;

   procedure queryMXRecords(
      domainName : in rr_type.WireStringType;
      returnedRecords : out rr_type.mx_record_type.mxRecordBucketType;
      howMany : out rr_type.NumberOfRecordsType);
   --# global in DNS_Table_Type;
   --# derives returnedRecords from DNS_Table_Type, domainName &
   --#         howMany from DNS_Table_Type, domainName;

procedure querySRVRecords(
      domainName : in rr_type.WireStringType;
      returnedRecords : out rr_type.srv_record_type.srvRecordBucketType;
      howMany : out rr_type.NumberOfRecordsType);
   --# global in DNS_Table_Type;
   --# derives returnedRecords from DNS_Table_Type, domainName &
   --#         howMany from DNS_Table_Type, domainName;

   procedure queryNSRecords(
      domainName : in rr_type.WireStringType;
      returnedRecords : out rr_type.ns_record_type.NSRecordBucketType;
      howMany : out rr_type.NumberOfRecordsType);
   --# global in DNS_Table_Type;
   --# derives returnedRecords from DNS_Table_Type, domainName &
   --#         howMany from DNS_Table_Type, domainName;

   procedure queryNSECRecords(
      domainName : in rr_type.WireStringType;
      returnedRecords : out rr_type.nsec_record_type.NSECRecordBucketType;
      howMany : out rr_type.NumberOfRecordsType);
   --# global in DNS_Table_Type;
   --# derives returnedRecords from DNS_Table_Type, domainName &
   --#         howMany from DNS_Table_Type, domainName;

   procedure queryPTRRecords(
      domainName : in rr_type.WireStringType;
      returnedRecords : out rr_type.ptr_record_type.PTRRecordBucketType;
      howMany : out rr_type.NumberOfRecordsType);
   --# global in DNS_Table_Type;
   --# derives returnedRecords from DNS_Table_Type, domainName &
   --#         howMany from DNS_Table_Type, domainName;

   procedure queryRRSIGRecords(
      domainName : in rr_type.WireStringType;
      returnedRecords : out rr_type.RRSIG_record_type.RRSIGRecordBucketType;
      HowMany : out Rr_Type.NumberOfRecordsType);
   --# global in DNS_Table_Type;
   --# derives  returnedRecords, howMany from DNS_Table_Type, domainName;

   procedure querySOARecords(
      domainName : in rr_type.WireStringType;
      returnedRecords : out rr_type.soa_record_type.SOARecordBucketType;
      howMany : out rr_type.NumberOfRecordsType);
   --# global in DNS_Table_Type;
   --# derives returnedRecords from DNS_Table_Type, domainName &
   --#         howMany from DNS_Table_Type, domainName;


   private
      ARecordKeys : RR_Type.OwnerHashTableType := RR_Type.OwnerHashTableType'(
         others => RR_Type.OwnerRecordBucketType'(
            others => RR_Type.BlankOwner));
      ARecordTable : Rr_Type.A_Record_Type.ARecordHashTableType := rr_type.a_record_type.ARecordHashTableType'(
         others => rr_type.a_record_type.ARecordBucketType'(
         others => rr_type.a_record_type.blankARecord));
      AAAARecordKeys : RR_Type.OwnerHashTableType := RR_Type.OwnerHashTableType'(
         others => RR_Type.OwnerRecordBucketType'(
            others => RR_Type.BlankOwner));
      AAAARecordTable : Rr_Type.AAAA_Record_Type.AAAARecordHashTableType := rr_type.aaaa_record_type.AAAARecordHashTableType'(
         others => rr_type.aaaa_record_type.AAAARecordBucketType'(
         others => rr_type.aaaa_record_type.blankAAAARecord));
      CNAMERecordKeys : RR_Type.OwnerHashTableType := RR_Type.OwnerHashTableType'(
         others => RR_Type.OwnerRecordBucketType'(
            others => RR_Type.BlankOwner));
      CNAMERecordTable : Rr_Type.Cname_Record_Type.CNAMERecordHashTableType := rr_type.cname_record_type.CNAMERecordHashTableType'(
         others => rr_type.cname_record_type.CNAMERecordBucketType'(
         others => Rr_Type.Cname_Record_Type.BlankCNAMERecord));
      DNSKEYRecordKeys : RR_Type.OwnerHashTableType := RR_Type.OwnerHashTableType'(
         others => RR_Type.OwnerRecordBucketType'(
            others => RR_Type.BlankOwner));
      DNSKEYRecordTable : Rr_Type.dnskey_Record_Type.DNSKEYRecordHashTableType := rr_type.dnskey_record_type.DNSKEYRecordHashTableType'(
         others => rr_type.dnskey_record_type.DNSKEYRecordBucketType'(
         others => rr_type.dnskey_record_type.blankDNSKEYRecord));
      MXRecordKeys : RR_Type.OwnerHashTableType := RR_Type.OwnerHashTableType'(
         others => RR_Type.OwnerRecordBucketType'(
            others => RR_Type.BlankOwner));
      MXRecordTable : Rr_Type.Mx_Record_Type.MXRecordHashTableType := rr_type.mx_record_type.MXRecordHashTableType'(
         others => rr_type.mx_record_type.MXRecordBucketType'(
         others => rr_type.mx_record_type.blankMXRecord));
      SRVRecordKeys : RR_Type.OwnerHashTableType := RR_Type.OwnerHashTableType'(
         others => RR_Type.OwnerRecordBucketType'(
            others => RR_Type.BlankOwner));
      SRVRecordTable : Rr_Type.SRV_Record_Type.SRVRecordHashTableType := rr_type.srv_record_type.SRVRecordHashTableType'(
         others => rr_type.srv_record_type.SRVRecordBucketType'(
         others => rr_type.srv_record_type.blankSRVRecord));
      NSRecordKeys : RR_Type.OwnerHashTableType := RR_Type.OwnerHashTableType'(
         others => RR_Type.OwnerRecordBucketType'(
            others => RR_Type.BlankOwner));
      NSRecordTable : rr_type.ns_record_type.NSRecordHashTableType := rr_type.ns_record_type.NSRecordHashTableType'(
         others => rr_type.ns_record_type.NSRecordBucketType'(
         others => Rr_Type.Ns_Record_Type.BlankNSRecord));
      NSECRecordKeys : RR_Type.OwnerHashTableType := RR_Type.OwnerHashTableType'(
         others => RR_Type.OwnerRecordBucketType'(
         others => RR_Type.BlankOwner));
      NSECRecordTable : rr_type.nsec_record_type.NSECRecordHashTableType := rr_type.nsec_record_type.NSECRecordHashTableType'(
         others => rr_type.nsec_record_type.NSECRecordBucketType'(
         others => Rr_Type.Nsec_Record_Type.BlankNSECRecord));
      PTRRecordKeys : RR_Type.OwnerHashTableType := RR_Type.OwnerHashTableType'(
         others => RR_Type.OwnerRecordBucketType'(
            others => RR_Type.BlankOwner));
      PTRRecordTable : rr_type.ptr_record_type.PTRRecordHashTableType := rr_type.ptr_record_type.PTRRecordHashTableType'(
         others => rr_type.ptr_record_type.PTRRecordBucketType'(
         others => Rr_Type.Ptr_Record_Type.BlankPTRRecord));
      RRSIGRecordKeys : RR_Type.OwnerHashTableType := RR_Type.OwnerHashTableType'(
         others => RR_Type.OwnerRecordBucketType'(
            others => RR_Type.BlankOwner));
      RRSIGRecordTable : Rr_Type.rrsig_Record_Type.rrsigRecordHashTableType := rr_type.rrsig_record_type.rrsigRecordHashTableType'(
         others => rr_type.rrsig_record_type.rrsigRecordBucketType'(
         others => rr_type.rrsig_record_type.blankrrsigRecord));
      SOARecordKeys : RR_Type.OwnerHashTableType := RR_Type.OwnerHashTableType'(
         others => RR_Type.OwnerRecordBucketType'(
            others => RR_Type.BlankOwner));
      SOARecordTable : rr_type.SOA_record_type.SOARecordHashTableType := rr_type.SOA_record_type.SOARecordHashTableType'(
         others => rr_type.SOA_record_type.SOARecordBucketType'(
         others => rr_type.SOA_record_type.blankSOARecord));
   end Dns_Table_Type;

--THIS IS THE NAME SERVER HASH TABLE
DNS_Table: Dns_Table_Type;

end dns_table_pkg;
