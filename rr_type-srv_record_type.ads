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

with Unsigned_Types, Rr_Type;
use type Unsigned_Types.Unsigned32,Unsigned_Types.Unsigned16;
--# inherit Unsigned_Types, rr_type;
package Rr_Type.SRV_Record_Type is
   --sufficiently below 2^16-1 that we can detect too large values without wraparound
   MAX_PREF_VAL : constant Unsigned_Types.Unsigned16 := 2**15-1;
   MAX_WEIGHT_VAL : constant Unsigned_Types.Unsigned16 := 2**15-1;
   MAX_PORT_VAL : constant Unsigned_Types.Unsigned16 := 2**15-1;
   type SRVRecordType is new Rr_Type.ResourceRecordType with
      record
         Pref          : Unsigned_Types.Unsigned16; --change MAX_PREF_VAL above if this type changes
         Weight        : Unsigned_Types.Unsigned16; --change MAX_WEIGHT_VAL above if this type changes
         PortNum       : Unsigned_Types.Unsigned16; --change MAX_PORT_VAL above if this type changes
         ServerName    : Rr_Type.WireStringType;
      end record;

   --placeholder for empty slots in hash table
   BlankSRVRecord : constant SRVRecordType := SRVRecordType'(
      TtlInSeconds => 0,
      Class => Rr_Type.INTERNET,
      Pref => 0,
      Weight => 0,
      PortNum => 0,
      ServerName => "empty.SRV.resource.record        " & Rr_Type.Spaces32
      & Rr_Type.Spaces32 & Rr_Type.Spaces32);

   --hash table (2d array) for SRV records
   type SRVRecordBucketType is array (Rr_Type.ReturnedRecordsIndexType) of SRVRecordType;
   type SRVRecordHashTableType is array (Rr_Type.NumBucketsIndexType) of SRVRecordBucketType;

end Rr_Type.SRV_Record_Type;

