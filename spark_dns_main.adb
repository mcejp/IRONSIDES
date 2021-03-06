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

with Udp_Dns_Package;
with Tcp_Dns_Package;
with Spark_Ada_Command_Line;
with Spark.Ada.Text_IO;
with DNS_Table_Pkg;
with Zone_File_Io;
--# inherit udp_dns_package, dns_table_pkg, Tcp_Dns_Package, Protected_SPARK_IO_05,
--#    DNS_Network, zone_file_io, Spark_Ada_Command_Line, Spark.Ada.Text_IO;
--# main_program
--# global in out DNS_Network.Network;
--#        in out Protected_SPARK_IO_05.SPARK_IO_PO;
--#        in out Udp_Dns_Package.Startup_Suspension;
--#        in out Tcp_Dns_Package.Startup_Suspension;
--#        in out DNS_Table_Pkg.DNS_Table;
--#        in Spark_Ada_Command_Line.State;
--# derives DNS_Network.Network from *, tcp_dns_package.startup_suspension,
--#             udp_dns_package.startup_suspension, dns_table_pkg.dns_table, spark_ada_command_line.state &
--#         Protected_SPARK_IO_05.SPARK_IO_PO from *, DNS_Network.Network, udp_dns_package.startup_suspension,
--#               tcp_dns_package.startup_suspension, spark_ada_command_line.state, dns_table_pkg.dns_table &
--#         Udp_Dns_Package.Startup_Suspension from * &
--#         Tcp_Dns_Package.Startup_Suspension from * &
--#         DNS_Table_Pkg.DNS_Table from *, Spark_Ada_Command_Line.State;
procedure Spark_Dns_Main
--# global out Tcp_Dns_Package.Startup_Suspension;
--#        out Udp_Dns_Package.Startup_Suspension;
--#        in out DNS_Table_Pkg.DNS_Table;
--#        in Spark_Ada_Command_Line.State;
--# derives tcp_dns_package.startup_suspension from  &
--#         DNS_Table_Pkg.DNS_Table from *, Spark_Ada_Command_Line.State &
--#         udp_dns_package.startup_suspension from;
--# declare delay;
is
   Success : Boolean;
--   Error : constant String := "Error--please shut down and correct zone file";
--   Good : constant String := "Correct zone file";
   pragma Priority(0);
   zoneFile : Spark.Ada.Text_IO.File_type;
begin
   Spark_Ada_Command_Line.Create_File_From_Argument(1,ZoneFile);
--# accept Flow, 10, zoneFile, "done with file after this call";
   zone_file_io.processzoneFile(zoneFile, success);
--# end accept;
   if Success=False then
      Spark_Ada_Command_Line.Exit_With_Status(Spark_Ada_Command_Line.Failure);
   end if;
   tcp_dns_package.Initialization_Done;
   Udp_Dns_Package.Initialization_Done;
end Spark_Dns_Main;

