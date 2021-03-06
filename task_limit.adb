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

--with ada.text_io;
package body Task_Limit is

   ---------------------
   -- Task_Count_Type --
   ---------------------

   protected body Task_Count_Type is

      ---------------
      -- Increment --
      ---------------

      procedure Increment (Success : out Boolean)
         --# global in out Task_Count;
         --# derives Task_Count from * &
         --#         Success from Task_Count;
         --# pre Task_Count >= 0 and Task_Count <= MAX_TASKS;
         --# post Task_Count >= 0 and Task_Count <= MAX_TASKS and
         --#      (((Task_Count~ = MAX_TASKS) -> ((Task_Count = Task_Count~) and (Success=False))) and
         --#       ((Task_Count~ < MAX_TASKS) -> ((Task_Count = Task_Count~ + 1) and Success)));
      is
      begin
         if Task_Count < MAX_TASKS then
            Task_Count := Task_Count + 1;
            --ada.Text_IO.put_line("increment : " & integer'image(task_count));
            Success := True;
         else
            Success := False;
         end if;
      end Increment;

      ---------------
      -- Decrement --
      ---------------

      procedure Decrement
         --# global in out Task_Count;
         --# derives Task_Count from *;
         --# pre Task_Count >= 0 and Task_Count <= MAX_TASKS;
         --# post Task_Count >= 0 and Task_Count <= MAX_TASKS and
         --#      (Task_Count~ > 0 -> (Task_Count = Task_Count~ - 1)) and
         --#      (Task_Count~ = 0 -> (Task_Count = Task_Count~));
      is
      begin
         if Task_Count > 0 then
            Task_Count := Task_Count - 1;
         end if;
      end Decrement;

   end Task_Count_Type;

end Task_Limit;
