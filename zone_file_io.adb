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

WITH Dns_Types, Dns_Table_Pkg, Parser_Utilities, Process_First_Line_Of_Record, Zone_File_Parser,
   error_msgs, unsigned_types, rr_type;
with Rr_Type.Dnskey_Record_Type, Rr_type.rrsig_record_type, Rr_Type.Soa_Record_Type;
WITH Spark.Ada.Text_IO;

use type Rr_Type.RrItemType;
use type dns_types.Query_Type;
USE TYPE Spark.Ada.Text_IO.Exception_T;
use type unsigned_types.unsigned32;

--just in case debugging needed

--WITH Ada.Text_IO, Ada.Integer_Text_IO;


package body Zone_File_Io is

   procedure processZoneFile(zoneFile : in out Spark.Ada.Text_IO.File_Type;
                             success : out boolean)
   is
      currentLine : rr_type.LineFromFileType := rr_type.LineFromFileType'(others => ' ');
      LastPos : Natural := 0;
      LineTooLong : Boolean;
      KeyTooLong : Boolean := false;
      BlankLine : Boolean;
      CommentLine : Boolean := False;   --true if line is a comment
      ControlLine : Boolean := False;   --true if line is a control statement (e.g. $TTL)
      HaveSOARecord : Boolean := false; --set to true if first record is SOA
      Parseable : Boolean;
      AllDone : Boolean;
      returnedType : rr_type.rrItemType := rr_type.Other;
      RecordSuccessfullyInserted : Boolean := True;
      LineCount : Unsigned_Types.Unsigned32 := 0;  --will wrap around if file has 2^32 lines :-)
      RRCtr : Unsigned_Types.Unsigned32 := 0;   --counts resource recs, see above
      LastException : Spark.Ada.Text_IO.Exception_T;
      InMultilineRecord : Boolean := False;
      lineInRecordCtr : Unsigned_Types.Unsigned32 := 0; --first line of multiline record is 0
      BegIdx : Rr_Type.LineLengthIndex;
      endIdx : rr_type.LineLengthIndex;

      currentOrigin : rr_type.DomainNameStringType := rr_type.blankDomainName;
      currentOwner : rr_type.DomainNameStringType := rr_type.blankDomainName;
      currentTTL : unsigned_types.Unsigned32 := 0;
      CurrentClass : Rr_Type.ClassType := Rr_Type.INTERNET;

      CurrentRecordType : Dns_Types.Query_Type := Dns_Types.A;

      --SOA record fields
      CurrentNameServer : Rr_Type.DomainNameStringType := Rr_Type.BlankDomainName;
      --if we need a DNSKEY record
      DNSKEY_Rec : Rr_Type.Dnskey_Record_Type.DNSKeyRecordType;
      --if we need an RRSIG record
      RRSIG_Rec : Rr_Type.Rrsig_Record_Type.RRSIGRecordType;

      --(these initial values never used, but make flow errors go away)
      CurrentEmail : Rr_Type.DomainNameStringType := rr_type.BlankDomainName;
      currentSerialNumber : unsigned_types.unsigned32 := 0;
      CurrentRefresh : unsigned_types.unsigned32 := 0;
      CurrentRetry : unsigned_types.unsigned32 := 0;
      CurrentExpiry : unsigned_types.unsigned32 := 0;
      CurrentMinimum : Unsigned_Types.Unsigned32 := 0;

      -- Used to test the last section of an SRV record
      -- testOwner: rr_type.DomainNameStringType := rr_type.blankDomainName;

   begin
      --make bogus flow errors go away
      DNSKEY_Rec := Rr_Type.Dnskey_Record_Type.BlankDNSKeyRecord;
      RRSIG_Rec := Rr_Type.Rrsig_Record_Type.BlankRRSIGRecord;
      success := true;
      lastException := Spark.Ada.Text_IO.Get_Last_Exception_File(zoneFile);

      --grab first line if file opened OK
      if (lastException = Spark.Ada.Text_IO.No_Exception) then
         Spark.Ada.Text_IO.Procedure_Get_Line_File(File => zoneFile,
            Item => CurrentLine, Arg_Last => LastPos);
         LineCount := LineCount+1;
         lastException := Spark.Ada.Text_IO.Get_Last_Exception_File(zoneFile);
      end if;

      WHILE (LastException = Spark.Ada.Text_IO.No_Exception) AND Success LOOP
         --# assert true;
         blankLine := (lastPos = 0);
         LineTooLong := LastPos >= Rr_Type.MaxLineLength;
         if lineTooLong then
            error_msgs.printLineLengthErrorInfo(currentLine, lastPos, lineCount);
            success := false;
         elsif not blankLine then
            Parser_Utilities.FindFirstToken(CurrentLine, LastPos, ReturnedType);
            CommentLine := (ReturnedType = Rr_Type.Comment);
            ControlLine := (ReturnedType = Rr_Type.Control);
         end if;

         parseable := (not blankLine) and (not lineTooLong) and (not CommentLine);
         IF Parseable THEN
            if not inMultilineRecord then  --multiline records treated differently
               --for monoline records, build record from line and insert in appropriate table
               if ControlLine then
                  --control statements are monoline, but different from DNS records
                  Zone_File_Parser.ParseControlLine(currentOrigin, currentTTL, currentLine,
                     LastPos, Success);
               else
                  --if not a control line, grab the owner, TTL, class and record type
                  RRCtr := RRCtr + 1;

                  zone_file_parser.parseOwnerTTLClassAndRecordType(currentOwner, currentTTL,
                     CurrentClass, CurrentRecordType, CurrentLine, LastPos, Success);

                  IF Success THEN
                     if CurrentTTL = 0 then
                        error_msgs.printZeroTTLWarning(currentLine, lastPos, lineCount);
                     end if;
                     --if domain name does not end in '.', append value of $ORIGIN
                     parser_utilities.checkAndAppendOrigin(currentOwner, currentOrigin, currentLine, lastPos,
                        LineCount, Success);

                     --owners for A, AAAA, DNSKEY, or MX records must be valid host names, check those more carefully
                     if CurrentRecordType = Dns_Types.A or CurrentRecordType = Dns_Types.AAAA
                        or CurrentRecordType = Dns_Types.DNSKEY or CurrentRecordType = Dns_Types.MX then
                        parser_utilities.CheckValidHostName(CurrentOwner, Success);
                     elsif CurrentRecordType = Dns_Types.SRV then
                        parser_utilities.checkValidSRVOwner(CurrentOwner, Success);
                     end if;

                     if Success then
                        --handle the record and (if not multiline) put it in the DNS table
                        process_first_line_of_record.ProcessFirstLineOfRecord (CurrentRecordType, CurrentOrigin, CurrentOwner,
                           CurrentTTL, CurrentClass, CurrentLine, LastPos, LineCount,
                           InMultilineRecord, lineInRecordCtr, currentNameServer,
                           CurrentEmail, DNSKEY_Rec, RRSIG_Rec, RecordSuccessfullyInserted,
                           Success);
                     end if;
                  end if;   --successful parse of owner/ttl/class/recordType
               end if;  --control line or other monoline record
            else  --inside a multiline record
               case CurrentRecordType is
                  when dns_types.SOA =>
                     --parsing the numeric fields of an SOA record ( after the '(' )
                     --must be one per line
                     lineInRecordCtr := lineInRecordCtr + 1;
                     case lineInRecordCtr is
                        when 1 =>
                           Zone_File_Parser.ParseSerialNumber(CurrentSerialNumber, CurrentLine, LastPos, Success);
               	      when 2 =>
                           Zone_File_Parser.ParseTimeSpec(CurrentRefresh, CurrentLine, LastPos, Success);
                         when 3 =>
                           Zone_File_Parser.ParseTimeSpec(CurrentRetry, CurrentLine, LastPos, Success);
                         when 4 =>
                           Zone_File_Parser.ParseTimeSpec(CurrentExpiry, CurrentLine, LastPos, Success);
                         when 5 =>
                           Zone_File_Parser.ParseTimeSpec(CurrentMinimum, CurrentLine, LastPos, Success);
                           --check if the token after the time specifier is a right paren
                           begIdx := 1;
                           Parser_Utilities.FindNextToken(CurrentLine, LastPos, BegIdx, EndIdx, ReturnedType);
                           --begIdx <= endIdx always true, makes flow errors go away
                           if (ReturnedType = rr_type.DomainNameOrTimeSpec and begIdx <= endIdx and endIdx < LastPos) then
                     	        BegIdx := EndIdx+1;
                           end if;
                           Parser_Utilities.FindNextToken(CurrentLine, LastPos, BegIdx, EndIdx, ReturnedType);
                           --begIdx <= endIdx always true, makes flow errors go away
                           if ReturnedType = Rr_Type.RParen and begIdx <= endIdx then
                              InMultilineRecord := False;
                              Dns_Table_Pkg.Dns_Table.InsertSOARecord(Rr_Type.ConvertDomainNameToWire(CurrentOwner),
                                 Rr_Type.Soa_Record_Type.SoaRecordType'(
                                 TtlInSeconds=>CurrentTTL, Class => CurrentClass,
                                 NameServer => rr_type.ConvertDomainNameToWire(CurrentNameServer),
                                 Email => Rr_Type.ConvertDomainNameToWire(CurrentEmail),
                                 SerialNumber => CurrentSerialNumber, Refresh => CurrentRefresh,
                                 Retry => CurrentRetry, Expiry => CurrentExpiry, Minimum => CurrentMinimum),
                                 RecordSuccessfullyInserted);
                                 HaveSOARecord := HaveSOARecord or (RecordSuccessfullyInserted and RRCtr = 1);
                           end if;

                        when others =>
                           if ReturnedType = Rr_Type.RParen then
                              InMultilineRecord := False;
                              Dns_Table_Pkg.Dns_Table.InsertSOARecord(Rr_Type.ConvertDomainNameToWire(CurrentOwner),
                                 Rr_Type.Soa_Record_Type.SoaRecordType'(
                                 TtlInSeconds=>CurrentTTL, Class => CurrentClass,
                                 NameServer => rr_type.ConvertDomainNameToWire(CurrentNameServer),
                                 Email => Rr_Type.ConvertDomainNameToWire(CurrentEmail),
                                 SerialNumber => CurrentSerialNumber, Refresh => CurrentRefresh,
                                 Retry => CurrentRetry, Expiry => CurrentExpiry, Minimum => CurrentMinimum),
                                 RecordSuccessfullyInserted);
                                 HaveSOARecord := HaveSOARecord or (RecordSuccessfullyInserted and RRCtr = 1);
                           else
                              Success := False;
                           end if;
                     end case; --lineInRecordCtr value
                  when Dns_Types.DNSKEY =>
                     --parsing the lines of a DNSKEY record ( after the '(' )
                     --each line is a piece of the key, except for the last
                     LineInRecordCtr := LineInRecordCtr + 1;
                     --check if line begins with ')'
                     begIdx := 1;
                     Parser_Utilities.FindNextToken(CurrentLine, LastPos, BegIdx, EndIdx, ReturnedType);
                     --if ')' found, record complete, can insert in table
                     --begIdx <= endIdx always true, makes flow errors go away
                     if ReturnedType = Rr_Type.RParen and begIdx <= endIdx then
                        InMultilineRecord := False;
                        DNSKEY_Rec.TtlInSeconds := CurrentTTL;
                        DNSKEY_Rec.Class := CurrentClass;
                        --flags, protocol, algorithm already set when first line processed,
                        --key and keyLength set when remaining lines processed, so we're done
                        Dns_Table_Pkg.DNS_Table.InsertDNSKEYRecord(Rr_Type.ConvertDomainNameToWire(CurrentOwner),
                           DNSKEY_Rec, RecordSuccessfullyInserted);
                     else --otherwise we're still in the middle of a DNSKEY record, parsing the key
                        Parser_Utilities.AddToKey(DNSKEY_Rec, CurrentLine, LastPos, Success);
                        if not Success then
                           KeyTooLong := True;
                        end if;
                     end if;
                  when Dns_Types.RRSIG =>
                     --parsing the lines of an RRSIG record after the first one
                     --2nd line has record fields, the rest of the lines are the key
                     --terminated by a right paren
                     LineInRecordCtr := LineInRecordCtr + 1;
                     case LineInRecordCtr is
                        when 1 =>
                           zone_file_parser.ParseRRSig2ndLine(RRSig_Rec, currentLine, LastPos,
                              Success);
                        when others =>
                           Parser_Utilities.AddToKeyR(RRSig_Rec, CurrentLine, LastPos, AllDone,
                              Success);
                           if not Success then
                              KeyTooLong := True;
                           ELSIF AllDone THEN
                              RRSIG_Rec.TtlInSeconds := CurrentTTL;
                              RRSIG_Rec.Class := CurrentClass;
                              Dns_Table_Pkg.DNS_Table.InsertRRSIGRecord(Rr_Type.ConvertDomainNameToWire(CurrentOwner),
                                 RRSIG_Rec, RecordSuccessfullyInserted);
                              InMultilineRecord := False;
                           end if;
                     end case;

                  when others => --other multiline record types can go here
                     null;
               end case; --multiline record types
            end if; --parsing a multiline record
         ELSE
            null;  --non-parseable line, blank lines/comments ignored
         END IF;

         --check for various error conditions
         Success := Success AND RecordSuccessfullyInserted;
         if not RecordSuccessfullyInserted then
            Error_Msgs.PrintDNSTableFullInfo(CurrentLine, LineCount);
         elsif KeyTooLong then
            error_msgs.printKeyLengthErrorInfo(currentLine, lastPos, lineCount);
         elsIF NOT Success and not lineTooLong THEN
            Error_Msgs.PrintParseErrorInfo(CurrentLine, LastPos, LineCount);
         elsif NOT HaveSOARecord and RRCtr > 1 then
            Success := False;
            Error_Msgs.PrintMissingSOARecordInfo;
         elsif not LineTooLong then
            --looks like we're good, get the next line and repeat
            Spark.Ada.Text_IO.Procedure_Get_Line_File(File => zoneFile,
               Item => CurrentLine, Arg_Last => LastPos);
            --having old characters reset to blank helps with error reporting
            if LastPos >= 1 and LastPos < rr_type.MaxLineLength then
            	for I in integer range LastPos+1..rr_type.MaxLineLength loop
            	   --#assert I >= 1;
            	   CurrentLine(I) := ' ';
            	end loop;
            end if;
            lineCount := lineCount + 1;
            LastException := Spark.Ada.Text_IO.Get_Last_Exception_File(ZoneFile);
         END IF;
      end loop; --file reading loop, one line per iteration

      --Only possible undetected errors at this point are file errors
      Success := Success and (LastException = Spark.Ada.Text_IO.End_Error);

   end processZoneFile;
end zone_file_io;
