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
with dns_types;
--#inherit rr_type, dns_types, unsigned_types;
PACKAGE Rr_Type.Nsec_Record_Type IS
   MaxNumberOfRecordTypes: CONSTANT Natural := 32;

   subtype recordTypeIndexValue is natural range 0..maxNumberOfRecordTypes;
   subtype recordTypeArrayIndex is natural range 1..maxNumberOfRecordTypes;
   TYPE recordTypeArrayType IS ARRAY(recordTypeArrayIndex) OF Dns_Types.Query_Type;

   MaxNumberOfBlocks: CONSTANT Natural := MaxNumberOfRecordTypes;
   subtype blockNumberValue is natural range 0..maxNumberOfBlocks;
   subtype blockNumberArrayIndex is natural range 1..maxNumberOfBlocks;
   TYPE BlockNumberArrayType IS ARRAY(blockNumberArrayIndex) OF Dns_Types.Byte;

   SUBTYPE BlockLengthValue is positive Range 1..32;
   TYPE BlockLengthArrayType IS ARRAY(blockNumberArrayIndex) OF BlockLengthValue;

   SUBTYPE BitMapIndex IS Positive RANGE 1..BlockLengthValue'last;
   TYPE BitMapArrayType IS ARRAY(BitMapindex) OF DNS_Types.Byte;
   type bitMapsArrayArrayType is array(blockNumberArrayIndex) of bitMapArrayType;

   MaxRRDataLength : constant Natural :=
      ((((rr_type.MaxDomainNameLength + 1) --how long a wire domain name length can be
      + MaxNumberofBlocks) --how many blocks you can have
      + MaxNumberOfBlocks) --again for the block lengths
      + MaxNumberOfBlocks*BlockLengthValue'last); --for the bitmaps

   type NSECRecordType is new rr_type.ResourceRecordType with
   record
      nextDomainName : Rr_Type.WireStringType;
      RecordList : Rr_Type.LineFromFileType; --just a string, gets parsed into detailed info below

      --record type block and bitmap info, needed for when record goes out on the wire
      NumberOfRecordTypes: recordTypeIndexValue;
      recordTypes: recordTypeArrayType;
      numberOfBlocks: blockNumberValue;
      blockNumbers:  BlockNumberArrayType;
      BlockLengths:  BlockLengthArrayType;
      bitMaps: BitMapsArrayArrayType;
   end record;

--placeholder for empty slots in hash table
blankNSECRecord : constant NSECRecordType := NSECRecordType'(
   ttlInSeconds => 0,
   class => Rr_Type.INTERNET,
   nextDomainName => " " & Rr_Type.Spaces128,
   RecordList => Rr_Type.Spaces256,
   NumberOfRecordTypes => 0,
   recordTypes => recordTypeArrayType'(others => dns_types.UNIMPLEMENTED),
   numberOfBlocks => 0,
   blockNumbers => BlockNumberArrayType'(others => 0),
   blockLengths => BlockLengthArrayType'(OTHERS => blockLengthValue'first),
   bitMaps => bitMapsArrayArrayType'(Others => bitMapArrayType'(others => 0))
         );

--hash table (2d array) for NSEC records
type NSECRecordBucketType is array(rr_type.ReturnedRecordsIndexType) of NSECRecordType;
type NSECRecordHashTableType is array(rr_type.NumBucketsIndexType) of NSECRecordBucketType;

end rr_type.nsec_record_type;
