Transport Rules
=======
**Show-TransportRules** shows the transport rules (mail flow rules) in your organization. Transport rules are a set of policies that allow organizations to apply specific actions and conditions to incoming or outgoing email messages.

Show transport rules
^^^^^^^^^^^
Shows the transport rules in your organization.

Usage
""""""""""""""""""""""""""
Show all the transport rules in your organization:
::

   Show-TransportRules

Get transport rules
^^^^^^^^^^^
Collects all the transport rules in your organization.

Parameters
""""""""""""""""""""""""""
-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: Output\Rules

-Encoding (optional)
    - Encoding is the parameter specifying the encoding of the CSV output file.
    - Default: UTF8

Usage
""""""""""""""""""""""""""
Get all transport rules in your organization:
::

   Get-TransportRules

Output
""""""""""""""""""""""""""
The output will be saved to the 'Rules' directory within the 'Output' directory, with the file name 'TransportRules.csv'.
