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

with Ada.Characters.Handling;
--In case debugging IO needed
--with Ada.Text_IO;
package body Dns_Table_Pkg

is

protected body Dns_Table_Type is
--UTILITIES
   function To_Lower(DomainName : in Rr_Type.WireStringType) return Rr_Type.WireStringType is
      LowerCaseVersion : Rr_Type.WireStringType := Rr_Type.BlankWire;
      length : rr_type.wireStringTypeIndex;
   begin
      Length := Rr_Type.WireNameLength(domainName);
      for I in Integer range 1..Length loop
         --# assert true;
         LowerCaseVersion(I) := Ada.Characters.Handling.to_lower(domainName(I));
      end loop;
      return lowerCaseVersion;
   end To_Lower;

   function Same(X,Y : in RR_Type.WireStringType) return Boolean is
      Length : Rr_Type.WireStringTypeIndex;
      result : boolean;
   begin
      result := true;
      Length := Rr_Type.WireNameLength(x);
      for I in Integer range 1..Length loop
         --#assert true;
         if X(I)/=Y(I) then
            Result := False;
            exit;
         end if;
      end loop;
      return result;
   end Same;

   function hash(domainName : in rr_type.WireStringType)
      return Rr_Type.NumBucketsIndexType
   --return val => (1 <= val and val <= rr_type.NumBuckets);
   is
      NumCharsInHashFunction : constant Natural := 4;
      val : natural := 0;
   begin
      for i in integer range 1..NumCharsInHashFunction loop
         --# assert val <= (i-1)*Character'Pos(Character'Last)
         --#   and (for all Q in rr_type.WireStringTypeIndex =>
         --#          (character'pos(domainname(Q))<=255 and
         --#           character'pos(domainname(Q))>=0));
         val := val + Character'Pos(domainName(i));
      end loop;
      return (val mod rr_type.NumBuckets) + 1;
   end hash;

--QUERY PROCEDURES
   procedure queryARecords(
   	domainName : in rr_type.WireStringType;
        returnedRecords : out rr_type.a_record_type.ARecordBucketType;
                           howMany : out rr_type.NumberOfRecordsType)
   --# global in ARecordTable, ARecordKeys;
   --# derives howMany from ARecordKeys, domainName &
   --#         returnedRecords from ARecordKeys, ARecordTable, domainName;
   is
      Bucket : Rr_Type.NumBucketsIndexType;
      Lower_DomainName : rr_type.WireStringType;
   begin
      -- must initialize the whole array to make flow error go away
--      returnedRecords := rr_type.a_record_type.ARecordBucketType'(
--        others => rr_type.a_record_type.blankARecord);
      Lower_Domainname := To_Lower(DomainName);

      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_DomainName);
      howMany := 0;
      for ctr in rr_type.ReturnedRecordsIndexType loop
         --# assert howMany >= 0 and howMany < ctr and bucket >= 1 and bucket <= rr_type.NumBuckets;
         exit when ARecordKeys(Bucket)(Ctr)(1) = ASCII.NUL;
         if Same(ARecordKeys(Bucket)(Ctr),Lower_domainName) then
            HowMany := HowMany+1;
            --# accept Flow, 23, returnedRecords, "assigning to uninitialized array is OK";
            returnedRecords(howMany) := ARecordTable(bucket)(ctr);
            --# end accept;
         end if;
      end loop;
      --# accept Flow, 602, returnedRecords, returnedRecords, "fills as much of array as needed";
   end QueryARecords;

--QUERY PROCEDURES
   procedure countARecords(
   	domainName : in rr_type.WireStringType;
      howMany : out rr_type.NumberOfRecordsType)
   --# global in ARecordKeys;
   --# derives howMany from ARecordKeys, domainName;
   is
      Bucket : Rr_Type.NumBucketsIndexType;
      Lower_DomainName : rr_type.WireStringType;
   begin
      -- must initialize the whole array to make flow error go away
      Lower_Domainname := To_Lower(DomainName);

      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(DomainName);
      howMany := 0;
      for ctr in rr_type.ReturnedRecordsIndexType loop
         --# assert howMany >= 0 and howMany < ctr and bucket >= 1 and bucket <= rr_type.NumBuckets;
         exit when ARecordKeys(Bucket)(Ctr)(1) = ASCII.NUL;
         --if To_Lower(ARecordTable(Bucket)(Ctr).Owner) = Lower_domainName then
         if Same(ARecordKeys(Bucket)(Ctr),Lower_domainName) then
            HowMany := HowMany+1;
         end if;
      end loop;
   end CountARecords;

   procedure countAAAARecords(
   	domainName : in rr_type.WireStringType;
      howMany : out rr_type.NumberOfRecordsType)
   --# global in AAAARecordKeys;
   --# derives howMany from AAAARecordKeys, domainName;
   is
      Bucket : Rr_Type.NumBucketsIndexType;
      Lower_DomainName : rr_type.WireStringType;
   begin
      -- must initialize the whole array to make flow error go away
      Lower_Domainname := To_Lower(DomainName);

      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(DomainName);
      howMany := 0;
      for ctr in rr_type.ReturnedRecordsIndexType loop
         --# assert howMany >= 0 and howMany < ctr and bucket >= 1 and bucket <= rr_type.NumBuckets;
         exit when AAAARecordKeys(Bucket)(Ctr)(1) = ASCII.NUL;
         --if To_Lower(ARecordTable(Bucket)(Ctr).Owner) = Lower_domainName then
         if Same(AAAARecordKeys(Bucket)(Ctr),Lower_domainName) then
            HowMany := HowMany+1;
         end if;
      end loop;
   end CountAAAARecords;


   procedure queryAAAARecords(
   	domainName : in rr_type.WireStringType;
      returnedRecords : out rr_type.aaaa_record_type.AAAARecordBucketType;
      howMany : out rr_type.NumberOfRecordsType)
   --# global in AAAARecordTable, AAAARecordKeys;
   --# derives howMany from AAAARecordKeys, domainName &
   --#         returnedRecords from AAAARecordKeys, AAAARecordTable, domainName;
   is
      bucket : rr_type.NumBucketsIndexType;
      Lower_Domainname : rr_Type.WireStringType;
   begin
      Lower_Domainname := To_Lower(Domainname);
      -- must initialize the whole array to make flow error go away
--      returnedRecords := rr_type.aaaa_record_type.AAAARecordBucketType'(
--        others => rr_type.aaaa_record_type.blankAAAARecord);

      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_DomainName);
      howMany := 0;
      for ctr in rr_type.ReturnedRecordsIndexType loop
         --# assert howMany >= 0 and howMany < ctr and bucket >= 1 and bucket <= rr_type.NumBuckets;
         exit when AAAARecordKeys(Bucket)(Ctr)(1) = ASCII.NUL;
--         if To_Lower(AAAARecordTable(Bucket)(Ctr).Owner) = Lower_domainName then
         if Same(AaaaRecordKeys(Bucket)(Ctr),Lower_domainName) then
            howMany := howMany+1;
            --# accept Flow, 23, returnedRecords, "assigning to uninitialized array is OK";
            returnedRecords(howMany) := AAAARecordTable(bucket)(ctr);
            --# end accept;
         end if;
      end loop;
      --# accept Flow, 602, returnedRecords, returnedRecords, "fills as much of array as needed";
   end queryAAAARecords;


   procedure queryCNAMERecords(domainName : in rr_type.WireStringType;
        returnedRecords : out rr_type.cname_record_type.CNAMERecordBucketType;
        howMany : out rr_type.NumberOfRecordsType)
   --# global in CNAMERecordTable, CNAMERecordKeys;
   --# derives howMany from CNAMERecordKeys, domainName &
   --#         returnedRecords from CNAMERecordKeys, CNAMERecordTable, domainName;
   is
      Bucket : Rr_Type.NumBucketsIndexType;
      Lower_Domainname : rr_Type.WireStringType;
   begin
      Lower_Domainname := To_Lower(Domainname);
      -- must initialize the whole array to make flow error go away
--      returnedRecords := rr_type.cname_record_type.CNAMERecordBucketType'(
--         others => Rr_Type.Cname_Record_Type.BlankCNAMERecord);

      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Domainname);
      howMany := 0;
      for ctr in rr_type.ReturnedRecordsIndexType loop
         --# assert howMany >= 0 and howMany < ctr and bucket >= 1 and bucket <= rr_type.NumBuckets;
         exit when CNAMERecordKeys(bucket)(ctr)(1) = ASCII.NUL;
         if Same(CNAMERecordKeys(Bucket)(Ctr),Lower_domainName) then
            howMany := howMany+1;
            --# accept Flow, 23, returnedRecords, "assigning to uninitialized array is OK";
            returnedRecords(howMany) := CNAMERecordTable(bucket)(ctr);
            --# end accept;
         end if;
      end loop;
      --# accept Flow, 602, returnedRecords, returnedRecords, "fills as much of array as needed";
   END QueryCNAMERecords;

   procedure queryDNSKEYRecords(domainName : in rr_type.WireStringType;
        returnedRecords : out rr_type.DNSKEY_record_type.DNSKEYRecordBucketType;
        howMany : out rr_type.NumberOfRecordsType)
   --# global in DNSKEYRecordTable, DNSKEYRecordKeys;
   --# derives howMany from DNSKEYRecordKeys, domainName &
   --#         returnedRecords from DNSKEYRecordKeys, DNSKEYRecordTable, domainName;
   is
      Bucket : Rr_Type.NumBucketsIndexType;
      Lower_Domainname : rr_Type.WireStringType;
   begin
      Lower_Domainname := To_Lower(Domainname);
      -- must initialize the whole array to make flow error go away
--      returnedRecords := rr_type.DNSKEY_record_type.DNSKEYRecordBucketType'(
--         others => Rr_Type.DNSKEY_Record_Type.BlankDNSKEYRecord);

      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Domainname);
      howMany := 0;
      for ctr in rr_type.ReturnedRecordsIndexType loop
         --# assert howMany >= 0 and howMany < ctr and bucket >= 1 and bucket <= rr_type.NumBuckets;
         exit when DNSKEYRecordKeys(bucket)(ctr)(1) = ASCII.NUL;
         if Same(DNSKEYRecordKeys(Bucket)(Ctr),Lower_domainName) then
            howMany := howMany+1;
            --# accept Flow, 23, returnedRecords, "assigning to uninitialized array is OK";
            returnedRecords(howMany) := DNSKEYRecordTable(bucket)(ctr);
            --# end accept;
         end if;
      end loop;
      --# accept Flow, 602, returnedRecords, returnedRecords, "fills as much of array as needed";
   END QueryDNSKEYRecords;

   procedure queryMXRecords(
      domainName : in rr_type.WireStringType;
      returnedRecords : out rr_type.mx_record_type.MXRecordBucketType;
      howMany : out rr_type.NumberOfRecordsType)
   --# global in MXRecordTable, MXRecordKeys;
   --# derives howMany from MXRecordKeys, domainName &
   --#         returnedRecords from MXRecordKeys, MXRecordTable, domainName;
   is
      Bucket : Rr_Type.NumBucketsIndexType;
      Lower_Domainname : rr_Type.WireStringType;
   begin
      Lower_Domainname := To_Lower(Domainname);
      -- must initialize the whole array to make flow error go away
--      returnedRecords := rr_type.mx_record_type.MXRecordBucketType'(
--         others => rr_Type.mx_Record_Type.BlankMXRecord);
      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Domainname);

      howMany := 0;
      for ctr in rr_type.ReturnedRecordsIndexType loop
         --# assert howMany >= 0 and howMany < ctr and bucket >= 1 and bucket <= rr_type.NumBuckets;
         exit when MXRecordKeys(bucket)(ctr)(1) = ASCII.NUL;
         if Same(MXRecordKeys(Bucket)(Ctr),Lower_domainName) then
            howMany := howMany+1;
            --# accept Flow, 23, returnedRecords, "assigning to uninitialized array is OK";
            returnedRecords(howMany) := MXRecordTable(bucket)(ctr);
            --# end accept;
         end if;
      end loop;
      --# accept Flow, 602, returnedRecords, returnedRecords, "fills as much of array as needed";
   END queryMXRecords;

   procedure querySRVRecords(
      domainName : in rr_type.WireStringType;
      returnedRecords : out rr_type.srv_record_type.SRVRecordBucketType;
      howMany : out rr_type.NumberOfRecordsType)
   --# global in SRVRecordTable, SRVRecordKeys;
   --# derives howMany from SRVRecordKeys, domainName &
   --#         returnedRecords from SRVRecordKeys, SRVRecordTable, domainName;
   is
      Bucket : Rr_Type.NumBucketsIndexType;
      Lower_Domainname : rr_Type.WireStringType;
   begin
      Lower_Domainname := To_Lower(Domainname);
      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Domainname);

      howMany := 0;
      for ctr in rr_type.ReturnedRecordsIndexType loop
         --# assert howMany >= 0 and howMany < ctr and bucket >= 1 and bucket <= rr_type.NumBuckets;
         exit when SRVRecordKeys(bucket)(ctr)(1) = ASCII.NUL;
         if Same(SRVRecordKeys(Bucket)(Ctr),Lower_domainName) then
            howMany := howMany+1;
            --# accept Flow, 23, returnedRecords, "assigning to uninitialized array is OK";
            returnedRecords(howMany) := SRVRecordTable(bucket)(ctr);
            --# end accept;
         end if;
      end loop;
      --# accept Flow, 602, returnedRecords, returnedRecords, "fills as much of array as needed";
   END querySRVRecords;

   procedure queryNSRecords(
   	domainName : in rr_type.WireStringType;
        returnedRecords : out rr_type.ns_record_type.NSRecordBucketType;
        howMany : out rr_type.NumberOfRecordsType)
   --# global in NSRecordTable, NSRecordKeys;
   --# derives howMany from NSRecordKeys, domainName &
   --#         returnedRecords from NSRecordKeys, NSRecordTable, domainName;
   is
      Bucket : Rr_Type.NumBucketsIndexType;
      Lower_Domainname : rr_Type.WireStringType;
   begin
      Lower_Domainname := To_Lower(Domainname);
      -- must initialize the whole array to make flow error go away
--      returnedRecords := rr_type.NS_record_type.NSRecordBucketType'(
--         others => Rr_Type.NS_Record_Type.BlankNSRecord);
      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Domainname);

      howMany := 0;
      for ctr in rr_type.ReturnedRecordsIndexType loop
         --# assert howMany >= 0 and howMany < ctr and bucket >= 1 and bucket <= rr_type.NumBuckets;
         exit when NSRecordKeys(bucket)(ctr)(1) = ASCII.NUL;
         if Same(NSRecordKeys(Bucket)(Ctr),Lower_domainName) then
            howMany := howMany+1;
            --# accept Flow, 23, returnedRecords, "assigning to uninitialized array is OK";
            returnedRecords(howMany) := NSRecordTable(bucket)(ctr);
            --# end accept;
         end if;
      end loop;
      --# accept Flow, 602, returnedRecords, returnedRecords, "fills as much of array as needed";
   end QueryNSRecords;

procedure queryNSECRecords(
   	domainName : in rr_type.WireStringType;
    returnedRecords : out rr_type.nsec_record_type.NSECRecordBucketType;
    howMany : out rr_type.NumberOfRecordsType)
   --# global in NSECRecordTable, NSECRecordKeys;
   --# derives howMany from NSECRecordKeys, domainName &
   --#         returnedRecords from NSECRecordKeys, NSECRecordTable, domainName;
   is
      Bucket : Rr_Type.NumBucketsIndexType;
      Lower_Domainname : rr_Type.WireStringType;
   begin
      Lower_Domainname := To_Lower(Domainname);
      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Domainname);
      howMany := 0;
      for ctr in rr_type.ReturnedRecordsIndexType loop
         --# assert howMany >= 0 and howMany < ctr and bucket >= 1 and bucket <= rr_type.NumBuckets;
         exit when NSECRecordKeys(bucket)(ctr)(1) = ASCII.NUL;
         if Same(NSECRecordKeys(Bucket)(Ctr),Lower_domainName) then
            howMany := howMany+1;
            --# accept Flow, 23, returnedRecords, "assigning to uninitialized array is OK";
            returnedRecords(howMany) := NSECRecordTable(bucket)(ctr);
            --# end accept;
         end if;
      end loop;
      --# accept Flow, 602, returnedRecords, returnedRecords, "fills as much of array as needed";
   end queryNSECRecords;


   procedure queryPTRRecords(
   	    domainName : in rr_type.WireStringType;
        returnedRecords : out rr_type.PTR_record_type.PTRRecordBucketType;
        howMany : out rr_type.NumberOfRecordsType)
   --# global in PTRRecordTable, PTRRecordKeys;
   --# derives howMany from PTRRecordKeys, domainName &
   --#         returnedRecords from PTRRecordKeys, PTRRecordTable, domainName;
   is
      Bucket : Rr_Type.NumBucketsIndexType;
      Lower_Domainname : rr_Type.WireStringType;
   begin
      Lower_Domainname := To_Lower(Domainname);
      -- must initialize the whole array to make flow error go away
--      returnedRecords := rr_type.ptr_record_type.PTRRecordBucketType'(
--         others => Rr_Type.ptr_Record_Type.BlankPTRRecord);
     --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Domainname);

      howMany := 0;
      for ctr in rr_type.ReturnedRecordsIndexType loop
         --# assert howMany >= 0 and howMany < ctr
         --#    and bucket >= 1 and bucket <= rr_type.NumBuckets;
         exit when PTRRecordKeys(bucket)(ctr)(1) = ASCII.NUL;
         if Same(PTRRecordKeys(Bucket)(Ctr),Lower_domainName) then
            howMany := howMany+1;
            --# accept Flow, 23, returnedRecords, "assigning to uninitialized array is OK";
            returnedRecords(howMany) := PTRRecordTable(bucket)(ctr);
            --# end accept;
         end if;
      end loop;
      --# accept Flow, 602, returnedRecords, returnedRecords, "fills as much of array as needed";
   END QueryPTRRecords;

   procedure queryRRSIGRecords(domainName : in rr_type.WireStringType;
        returnedRecords : out rr_type.RRSIG_record_type.RRSIGRecordBucketType;
        howMany : out rr_type.NumberOfRecordsType)
   --# global in RRSIGRecordTable, RRSIGRecordKeys;
   --# derives howMany from RRSIGRecordKeys, domainName &
   --#         returnedRecords from RRSIGRecordKeys, RRSIGRecordTable, domainName;
   is
      Bucket : Rr_Type.NumBucketsIndexType;
      Lower_Domainname : rr_Type.WireStringType;
   begin
      Lower_Domainname := To_Lower(Domainname);
      -- must initialize the whole array to make flow error go away
--      returnedRecords := rr_type.RRSIG_record_type.RRSIGRecordBucketType'(
--         others => Rr_Type.RRSIG_Record_Type.BlankRRSIGRecord);

      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Domainname);
      howMany := 0;
      for ctr in rr_type.ReturnedRecordsIndexType loop
         --# assert howMany >= 0 and howMany < ctr and bucket >= 1 and bucket <= rr_type.NumBuckets;
         exit when RRSIGRecordKeys(bucket)(ctr)(1) = ASCII.NUL;
         if Same(RRSIGRecordKeys(Bucket)(Ctr),Lower_domainName) then
            howMany := howMany+1;
            --# accept Flow, 23, returnedRecords, "assigning to uninitialized array is OK";
            returnedRecords(howMany) := RRSIGRecordTable(bucket)(ctr);
            --# end accept;
         end if;
      end loop;
      --# accept Flow, 602, returnedRecords, returnedRecords, "fills as much of array as needed";
   END QueryRRSIGRecords;

   procedure querySOARecords(
   	domainName : in rr_type.WireStringType;
        returnedRecords : out rr_type.SOA_record_type.SOARecordBucketType;
        howMany : out rr_type.NumberOfRecordsType)
   --# global in SOARecordTable, SOARecordKeys;
   --# derives howMany from SOARecordKeys, domainName &
   --#         returnedRecords from SOARecordKeys, SOARecordTable, domainName;
   is
      Bucket : Rr_Type.NumBucketsIndexType;
      Lower_Domainname : rr_Type.WireStringType;
   begin
      Lower_Domainname := To_Lower(Domainname);
      -- must initialize the whole array to make flow error go away
--      returnedRecords := rr_type.soa_record_type.soaRecordBucketType'(
--         others => Rr_Type.soa_Record_Type.BlankSOARecord);
      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Domainname);

      howMany := 0;
      for ctr in rr_type.ReturnedRecordsIndexType loop
         --# assert howMany >= 0 and howMany < ctr
         --#    and bucket >= 1 and bucket <= rr_type.NumBuckets;
         exit when SOARecordKeys(bucket)(ctr)(1) = ASCII.NUL;
         if Same(soarecordKeys(Bucket)(Ctr),Lower_domainName) then
            howMany := howMany+1;
            --# accept Flow, 23, returnedRecords, "assigning to uninitialized array is OK";
            ReturnedRecords(HowMany) := SOARecordTable(Bucket)(Ctr);
            --# end accept;
         end if;
      end loop;
      --# accept Flow, 602, returnedRecords, returnedRecords, "fills as much of array as needed";
   END QuerySOARecords;

--INSERT PROCEDURES
   procedure InsertARecord(Key : in Rr_Type.WireStringType;
                          theRecord : in rr_type.a_record_type.ARecordType;
                          success : out boolean)
   --# global in out ARecordTable, ARecordKeys;
   --# derives ARecordTable from *, ARecordKeys, theRecord, Key &
   --#         ARecordKeys from *, Key &
   --#         success from ARecordKeys, Key;
   is
      bucket : rr_type.NumBucketsIndexType;
      Lower_Key : RR_Type.WireStringType;
   begin
      Lower_Key := To_Lower(Key);
      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Key);

      success := false;
      for i in rr_type.ReturnedRecordsIndexType loop
         --# assert true;
         if ARecordKeys(bucket)(i) = rr_type.BlankOwner then
            ARecordKeys(bucket)(i) := Lower_Key;
            ARecordTable(bucket)(i) := theRecord;
            success := true;
         end if;
         exit when success;
      end loop;
   END InsertARecord;

   procedure insertAAAARecord(Key : in Rr_Type.WireStringType;
                          theRecord : in rr_type.aaaa_record_type.AAAARecordType;
                          success : out boolean)
   --# global in out AAAARecordTable, AAAARecordKeys;
   --# derives AAAARecordTable from *, AAAARecordKeys, theRecord, Key &
   --#         AAAARecordKeys from *, Key &
   --#         success from AAAARecordKeys, Key;
   is
      Bucket : Rr_Type.NumBucketsIndexType;
      Lower_Key : RR_Type.WireStringType;
   begin
      Lower_Key := To_Lower(Key);
      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Key);

      success := false;
      for i in rr_type.ReturnedRecordsIndexType loop
         --# assert true;
         if AAAARecordKeys(bucket)(i) = rr_type.BlankOwner then
            AAAARecordKeys(bucket)(i) := Lower_Key;
            AAAARecordTable(bucket)(i) := theRecord;
            success := true;
         end if;
         exit when success;
      end loop;
   END InsertAAAARecord;

   procedure InsertCNAMERecord(Key : in Rr_Type.WireStringType;
                          theRecord : in rr_type.cname_record_type.CNAMERecordType;
                          success : out boolean)
   --# global in out CNAMERecordTable, CNAMERecordKeys;
   --# derives CNAMERecordTable from *, CNAMERecordKeys, theRecord, Key &
   --#         CNAMERecordKeys from *, Key &
   --#         success from CNAMERecordKeys, Key;
   is
      bucket : rr_type.NumBucketsIndexType;
      Lower_Key : RR_Type.WireStringType;
   begin
      Lower_Key := To_Lower(Key);
      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Key);

      success := false;
      for i in rr_type.ReturnedRecordsIndexType loop
         --# assert true;
         if CNAMERecordKeys(bucket)(i) = rr_type.BlankOwner then
            CNAMERecordKeys(bucket)(i) := Lower_Key;
            CNAMERecordTable(bucket)(i) := theRecord;
            success := true;
         end if;
         exit when success;
      end loop;
   END InsertCNAMERecord;

procedure InsertDNSKEYRecord(Key : in Rr_Type.WireStringType;
                          theRecord : in rr_type.DNSKEY_record_type.DNSKEYRecordType;
                          success : out boolean)
   --# global in out DNSKEYRecordTable, DNSKEYRecordKeys;
   --# derives DNSKEYRecordTable from *, DNSKEYRecordKeys, theRecord, Key &
   --#         DNSKEYRecordKeys from *, Key &
   --#         success from DNSKEYRecordKeys, Key;
   is
      bucket : rr_type.NumBucketsIndexType;
      Lower_Key : RR_Type.WireStringType;
   begin
      Lower_Key := To_Lower(Key);
      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Key);

      success := false;
      for i in rr_type.ReturnedRecordsIndexType loop
         --# assert true;
         if DNSKEYRecordKeys(bucket)(i) = rr_type.BlankOwner then
            DNSKEYRecordKeys(bucket)(i) := Lower_Key;
            DNSKEYRecordTable(bucket)(i) := theRecord;
            success := true;
         end if;
         exit when success;
      end loop;
   END InsertDNSKEYRecord;


   procedure insertMXRecord(Key : in Rr_Type.WireStringType;
                          theRecord : in rr_type.mx_record_type.MXRecordType;
                          success : out boolean)
   --# global in out MXRecordTable, MXRecordKeys;
   --# derives MXRecordTable from *, MXRecordKeys, theRecord, Key &
   --#         MXRecordKeys from *, Key &
   --#         success from MXRecordKeys, Key;
   is
      bucket : rr_type.NumBucketsIndexType;
      Lower_Key : RR_Type.WireStringType;
   begin
      Lower_Key := To_Lower(Key);
      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Key);

      success := false;
      for i in rr_type.ReturnedRecordsIndexType loop
         --# assert true;
         if MXRecordKeys(bucket)(i) = rr_type.BlankOwner then
            MXRecordKeys(bucket)(i) := Lower_Key;
            MXRecordTable(bucket)(i) := theRecord;
            success := true;
         end if;
         exit when success;
      end loop;
   END InsertMXRecord;

   procedure insertSRVRecord(Key : in Rr_Type.WireStringType;
                          theRecord : in rr_type.srv_record_type.SRVRecordType;
                          success : out boolean)
   --# global in out SRVRecordTable, SRVRecordKeys;
   --# derives SRVRecordTable from *, SRVRecordKeys, theRecord, Key &
   --#         SRVRecordKeys from *, Key &
   --#         success from SRVRecordKeys, Key;
   is
      bucket : rr_type.NumBucketsIndexType;
      Lower_Key : RR_Type.WireStringType;
   begin
      Lower_Key := To_Lower(Key);
      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Key);
      success := false;
      for i in rr_type.ReturnedRecordsIndexType loop
         --# assert true;
         if SRVRecordKeys(bucket)(i) = rr_type.BlankOwner then
            SRVRecordKeys(bucket)(i) := Lower_Key;
            SRVRecordTable(bucket)(i) := theRecord;
            success := true;
         end if;
         exit when success;
      end loop;
   END InsertSRVRecord;

   procedure insertNSRecord(Key : in Rr_Type.WireStringType;
                          theRecord : in rr_type.ns_record_type.NSRecordType;
                          success : out boolean)
   --# global in out NSRecordTable, NSRecordKeys;
   --# derives NSRecordTable from *, NSRecordKeys, theRecord, Key &
   --#         NSRecordKeys from *, Key &
   --#         success from NSRecordKeys, Key;
  is
      bucket : rr_type.NumBucketsIndexType;
      Lower_Key : RR_Type.WireStringType;
   begin
      Lower_Key := To_Lower(Key);
      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Key);

      success := false;
      for i in rr_type.ReturnedRecordsIndexType loop
         --# assert true;
         if NSRecordKeys(bucket)(i) = rr_type.BlankOwner then
            NSRecordKeys(bucket)(i) := Lower_Key;
            NSRecordTable(bucket)(i) := theRecord;
            success := true;
         end if;
         exit when success;
      end loop;
   END InsertNSRecord;

   procedure insertNSECRecord(Key : in Rr_Type.WireStringType;
                          theRecord : in rr_type.nsec_record_type.NSECRecordType;
                          success : out boolean)
   --# global in out NSECRecordTable, NSECRecordKeys;
   --# derives NSECRecordTable from *, NSECRecordKeys, theRecord, Key &
   --#         NSECRecordKeys from *, Key &
   --#         success from NSECRecordKeys, Key;
  is
      bucket : rr_type.NumBucketsIndexType;
      Lower_Key : RR_Type.WireStringType;
   begin
      Lower_Key := To_Lower(Key);
      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Key);

      success := false;
      for i in rr_type.ReturnedRecordsIndexType loop
         --# assert true;
         if NSECRecordKeys(bucket)(i) = rr_type.BlankOwner then
            NSECRecordKeys(bucket)(i) := Lower_Key;
            NSECRecordTable(bucket)(i) := theRecord;
            success := true;
         end if;
         exit when success;
      end loop;
   END InsertNSECRecord;

   procedure insertPTRRecord(Key : in Rr_Type.WireStringType;
                          theRecord : in rr_type.PTR_record_type.PTRRecordType;
                          success : out boolean)
   --# global in out PTRRecordTable, PTRRecordKeys;
   --# derives PTRRecordTable from *, PTRRecordKeys, theRecord, Key &
   --#         PTRRecordKeys from *, Key &
   --#         success from PTRRecordKeys, Key;
  is
      bucket : rr_type.NumBucketsIndexType;
      Lower_Key : RR_Type.WireStringType;
   begin
      Lower_Key := To_Lower(Key);
      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Key);

      success := false;
      for i in rr_type.ReturnedRecordsIndexType loop
         --# assert true;
         if PTRRecordKeys(bucket)(i) = rr_type.BlankOwner then
            PTRRecordKeys(bucket)(i) := Lower_Key;
            PTRRecordTable(bucket)(i) := theRecord;
            success := true;
         end if;
         exit when success;
      end loop;
   END InsertPTRRecord;

   procedure InsertRRSIGRecord(Key : in Rr_Type.WireStringType;
                          theRecord : in rr_type.rrsig_record_type.rrsigRecordType;
                          success : out boolean)
   --# global in out rrsigRecordTable, rrsigRecordKeys;
   --# derives rrsigRecordTable from *, rrsigRecordKeys, theRecord, Key &
   --#         rrsigRecordKeys from *, Key &
   --#         success from rrsigRecordKeys, Key;
   is
      bucket : rr_type.NumBucketsIndexType;
      Lower_Key : RR_Type.WireStringType;
   begin
      Lower_Key := To_Lower(Key);
      --queries must be case-insensitive, so hash on Lower case version
      Bucket := Hash(Lower_Key);

      success := false;
      for i in rr_type.ReturnedRecordsIndexType loop
         --# assert true;
         if rrsigRecordKeys(bucket)(i) = rr_type.BlankOwner then
            rrsigRecordKeys(bucket)(i) := Lower_Key;
            rrsigRecordTable(bucket)(i) := theRecord;
            success := true;
         end if;
         exit when success;
      end loop;
   END InsertRRSIGRecord;

   procedure insertSOARecord(Key : in Rr_Type.WireStringType;
                          theRecord : in rr_type.SOA_record_type.SOARecordType;
                          success : out boolean)
   --# global in out SOARecordTable, SOARecordKeys;
   --# derives SOARecordTable from *, SOARecordKeys, theRecord, Key &
   --#         SOARecordKeys from *, Key &
   --#         success from SOARecordKeys, Key;
   is
      Bucket : Rr_Type.NumBucketsIndexType;
      ReturnedSOARecords : Rr_Type.SOA_Record_Type.SOARecordBucketType;
      NumFound : natural;
      Lower_Key : RR_Type.WireStringType;
   begin
      Lower_Key := To_Lower(Key);
      --# accept Flow, 10, ReturnedSOARecords, "only care if there are any";
      --ReturnedSOARecords := Rr_Type.SOA_Record_Type.SOARecordBucketType'(others => rr_type.soa_record_type.BlanksoaRecord);
      --SOA records are special, can only have one per domain.  Enforce that here.
      QuerySOARecords(Lower_Key, ReturnedSOARecords, NumFound);
      --# end accept;
      if NumFound > 0 then
         Success := False;
      else
         --queries must be case-insensitive, so hash on Lower case version
         Bucket := Hash(Lower_Key);

         success := false;
         for i in rr_type.ReturnedRecordsIndexType loop
            --# assert true;
            if SOARecordKeys(bucket)(i) = rr_type.BlankOwner then
               SOARecordKeys(bucket)(i) := Lower_Key;
               SOARecordTable(bucket)(i) := theRecord;
               success := true;
            end if;
            exit when success;
         end loop;
      end if;
      --# accept Flow, 33, ReturnedSOARecords, "only care if there are any";
   END InsertSOARecord;

end Dns_Table_Type;

end dns_table_pkg;
