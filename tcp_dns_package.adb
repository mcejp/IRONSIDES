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



package body Tcp_Dns_Package is
   The_Task : Tcp_Dns_Task;
   Startup_Suspension : Ada.Synchronous_Task_Control.Suspension_Object;

   procedure Initialization_Done is
   begin
      Ada.Synchronous_Task_Control.Set_True(Startup_Suspension);
   end Initialization_Done;

   ------------------
   -- Tcp_Dns_Task --
   ------------------

   task body Tcp_Dns_Task is
      Reply_Socket  : DNS_Network.DNS_Socket;
   begin
      Ada.Synchronous_Task_Control.Suspend_Until_True(Startup_Suspension);
      -- start listening on a port
      DNS_Network.Initialize_TCP;
      loop
         --# assert true;
         -- get a connection
         DNS_Network.Get_Connection_Tcp(Socket => Reply_Socket);
         -- process the request and reply
         Multitask_Process_Dns_Request.Process_Request_Tcp(
            Reply_Socket => Reply_Socket);
      end loop;
   end Tcp_Dns_Task;

end Tcp_Dns_Package;
