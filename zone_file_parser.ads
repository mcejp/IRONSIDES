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

with Dns_Types, Rr_Type, Rr_Type.Aaaa_Record_Type, Rr_Type.Dnskey_Record_Type,
   rr_type.nsec_record_type, rr_type.rrsig_record_type, unsigned_types;
--with Ada.Text_IO, Ada.Integer_Text_IO;

--# inherit Ada.Characters.Handling, Ada.Characters.Latin_1, dns_types, error_msgs,
--#   parser_utilities, rr_type, rr_type.aaaa_record_type, rr_type.dnskey_record_type,
--#   rr_type.nsec_record_type,
--#   rr_type.mx_record_type, rr_type.rrsig_record_type, rr_type.soa_record_type,
--#   rr_type.srv_record_type, Spark.Ada.Strings.Maps, unsigned_types;

PACKAGE Zone_File_Parser IS
   TYPE Unsigned8 IS mod 2**8;

   procedure ParseDNSKeyHeader(DNSKEY_Rec: out rr_type.dnskey_record_type.DNSKeyRecordType;
      zoneFileLine : in rr_type.LineFromFileType;
      ZLength : in Rr_Type.LineLengthIndex;
      Success : in out Boolean);
   --# derives DNSKEY_Rec, success from zoneFileLine, zLength, success;

   procedure ParseRRSigHeader(RRSIG_Rec: out rr_type.rrsig_record_type.RRSIGRecordType;
      zoneFileLine : in rr_type.LineFromFileType;
      ZLength : in Rr_Type.LineLengthIndex;
      Success : in out Boolean);
   --# derives RRSIG_Rec, success from zoneFileLine, zLength, success;

   procedure ParseRRSig2ndLine(RRSIG_Rec:  in out rr_type.rrsig_record_type.RRSIGRecordType;
      zoneFileLine : in rr_type.LineFromFileType;
      ZLength : in Rr_Type.LineLengthIndex;
      Success : in out Boolean);
   --# derives RRSIG_Rec from RRSIG_Rec, zoneFileLine, zLength, success  & success from zoneFileLine, zLength, success;

   procedure ParseControlLine(newOrigin : in out rr_type.DomainNameStringType;
                              NewTTL : in out Unsigned_Types.Unsigned32;
                              zoneFileLine : in rr_type.LineFromFileType;
                              ZLength : in Rr_Type.LineLengthIndex; Success : in out Boolean);
   --# derives newOrigin from newOrigin, zoneFileLine, zLength
   --# & newTTL from newTTL, zoneFileLine, zLength, success
   --# & success from success, zoneFileLine, zLength;

   procedure parseDomainName(newDomainName : out rr_type.DomainNameStringType;
                             zoneFileLine : in rr_type.LineFromFileType;
                             ZLength : IN rr_type.LineLengthIndex; Success : IN OUT Boolean);
    --# derives newDomainName from zoneFileLine, zLength
    --# & success from success, zoneFileLine, zLength;

   procedure ParseDomainNameAndRRString(
      newDomainName : out rr_type.DomainNameStringType;
      RRString : out Rr_Type.LineFromFileType;
      zoneFileLine : in rr_type.LineFromFileType;
      ZLength : IN Rr_Type.LineLengthIndex;
      Success : IN OUT Boolean);
    --# derives newDomainName, RRString from zoneFileLine, zLength
    --# & success from success, zoneFileLine, zLength;

   PROCEDURE FillBlockInfo(RRString: IN Rr_Type.LineFromFileType;
      NumberOfRecordTypes: OUT Rr_Type.Nsec_Record_Type.RecordTypeIndexValue;
      RecordTypes: out Rr_Type.Nsec_Record_Type.recordTypeArrayType;
      numberOfBlocks: out Rr_Type.Nsec_Record_Type.BlockNumberValue;
      BlockNumbers: OUT Rr_Type.Nsec_Record_Type.BlockNumberArrayType;
      BlockLengths: OUT Rr_Type.Nsec_Record_Type.BlockLengthArrayType;
      BitMaps: OUT Rr_Type.Nsec_Record_Type.BitMapsArrayArrayType;
      LineCount : in Unsigned_Types.Unsigned32;
      Success: IN OUT Boolean);
   --# derives numberOfRecordTypes from RRString
   --# & recordTypes from RRString & numberOfBlocks from RRString & blockNumbers from RRString
   --# & blockLengths from RRString & bitMaps from RRString & success from RRString, Success & null from LineCount;
   --# post Success = true -> numberOfBlocks > 0;

   procedure parseIpv4(newIpv4 : out unsigned_types.Unsigned32;
                       zoneFileLine : in rr_type.LineFromFileType;
                       zLength : in rr_type.LineLengthIndex; success : in out boolean);
   --# derives newIpv4 from zoneFileLine, zLength
   --# & success from success, zoneFileLine, zLength;

   procedure parseIpv6(newIpv6 : out rr_type.aaaa_record_type.IPV6AddrType;
                       zoneFileLine : in rr_type.LineFromFileType;
                        zLength : in rr_type.LineLengthIndex; success : in out boolean);
   --# derives newIpv6 from zoneFileLine, zLength
   --# & success from success, zoneFileLine, zLength;

   procedure parsePrefAndDomainName(newPref : out unsigned_types.Unsigned16;
                                    newDomainName : out rr_type.DomainNameStringType;
                                    zoneFileLine : in rr_type.LineFromFileType;
                                    zLength : in rr_type.LineLengthIndex; success : in out boolean);
   --# derives newPref, newDomainName from zoneFileLine, zlength
   --# & success from success, zoneFileLine, zLength;

   procedure parsePrefWeightPortAndDomainName(newPref : out unsigned_types.Unsigned16;
                                    newWeight : out unsigned_types.Unsigned16;
                                    newPort : out unsigned_types.Unsigned16;
                                    newDomainName : out rr_type.DomainNameStringType;
                                    zoneFileLine : in rr_type.LineFromFileType;
                                    zLength : in rr_type.LineLengthIndex; success : in out boolean);
   --# derives newPref, newWeight, newPort, newDomainName from zoneFileLine, zlength
   --# & success from success, zoneFileLine, zLength;

   procedure ParseNameServerAndEmail(newNameServer : out Rr_Type.DomainNameStringType;
                                      newEmail : out rr_type.DomainNameStringType;
                                      zoneFileLine : in rr_type.LineFromFileType;
                                      ZLength : in Rr_Type.LineLengthIndex; Success : in out Boolean);
   --# derives newNameServer, newEMail from zoneFileLine, zlength
   --# & success from success, zoneFileLine, zLength;

   procedure parseSerialNumber(newSerialNumber : out unsigned_types.Unsigned32;
                                 zoneFileLine : in rr_type.LineFromFileType;
                                 ZLength : in Rr_Type.LineLengthIndex; Success : in out Boolean);
   --# derives newSerialNumber from zoneFileLine, zLength
   --# & success from success, zoneFileLine, zLength;

   procedure ParseTimeSpec(newTimeSpec : out Unsigned_Types.Unsigned32;
      zoneFileLine : in Rr_Type.LineFromFileType;
      ZLength : in Rr_Type.LineLengthIndex; Success : in out Boolean);
   --# derives newTimeSpec from zoneFileLine, zLength, success
   --# & success from success, zoneFileLine, zLength;

   procedure parseOwnerTTLClassAndRecordType(newOwner : in out rr_type.DomainNameStringType;
                              newTTL : in out unsigned_types.Unsigned32;
                              newClass : in out rr_type.classType;
                              newType : in out dns_types.Query_Type;
                      	      zoneFileLine : in rr_type.LineFromFileType;
                              zLength : in rr_type.LineLengthIndex; success : in out boolean);
   --# derives newOwner from newOwner, zoneFileLine, zLength
   --#  & newTTL from newTTL, zoneFileLine, zLength, success
   --#  & newClass from newClass, zoneFileLine, zLength, success
   --#  & newType from newType, zoneFileLine, zLength, success
   --#  & success from success, zoneFileLine, zLength;

end zone_file_parser;
